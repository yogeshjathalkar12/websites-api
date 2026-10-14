-- CRM email outreach: semi-automatic and automatic modes.
--
--   off   nothing is sent.
--   semi  every pipeline card with a contact gets an "Email" button next to "Call"; clicking it sends the template.
--   auto  the template is sent the moment a new deal (with a contact that has an email) is added.
--
-- Mail goes through the desktop relay (2026-10-10_email_relay.sql, run that first): it is queued in
-- email_relay_queue and the deal owner's desktop app sends it from their own mailbox, under that mailbox's
-- warm-up, daily limit, opening hours, opt-outs and pauses. Works the same for deals created in the web app
-- or the desktop app, because it is a database trigger. The pipeline card shows what became of each email
-- (table deal_outreach), kept apart from the deals table so deal history is not filled with status changes.
--
-- Safeguards in automatic mode: bulk imports are never emailed automatically (more than 5 deals added by the same
-- person within a minute), nobody is emailed twice within 30 days, and at most 50 emails wait per sender.
-- A failure in any of this never stops a deal from being saved.
-- Safe to run more than once. Run in the Supabase SQL editor.

-- ---------------------------------------------------------------------------------------------------------
-- 1. Relay rows can belong to a deal
-- ---------------------------------------------------------------------------------------------------------
alter table public.email_relay_queue add column if not exists deal_id uuid references public.deals(id) on delete cascade;

-- A deal has at most one live outreach email; a failed / cancelled / expired one can be retried.
create unique index if not exists email_relay_queue_one_per_deal on public.email_relay_queue (deal_id)
  where deal_id is not null and status in ('queued', 'claimed', 'accepted', 'sent', 'replied', 'bounced');

-- ---------------------------------------------------------------------------------------------------------
-- 2. The organization's mode and template
-- ---------------------------------------------------------------------------------------------------------
create table if not exists public.crm_outreach_settings (
  owner_id   uuid primary key references auth.users(id) on delete cascade,   -- the organization id
  mode       text not null default 'off' check (mode in ('off', 'semi', 'auto')),
  subject    text not null default 'Quick question, {{first_name}}',
  body       text not null default E'Hi {{first_name}},\n\nI came across {{company}} and thought what we do could be a good fit.\n\nWould you be open to a short call this week?\n\nThanks',
  updated_by uuid,
  updated_at timestamptz not null default now()
);
alter table public.crm_outreach_settings enable row level security;
drop policy if exists crm_outreach_settings_select on public.crm_outreach_settings;
create policy crm_outreach_settings_select on public.crm_outreach_settings
  for select to authenticated using (owner_id = (select public.my_org_id()));
revoke insert, update, delete on public.crm_outreach_settings from anon, authenticated;

-- ---------------------------------------------------------------------------------------------------------
-- 3. What became of each deal's email (shown on the pipeline card)
-- ---------------------------------------------------------------------------------------------------------
create table if not exists public.deal_outreach (
  deal_id      uuid primary key references public.deals(id) on delete cascade,
  owner_id     uuid not null,
  sender_id    uuid,                                   -- whose desktop app sends it
  trigger_kind text not null default 'manual' check (trigger_kind in ('manual', 'auto')),
  status       text not null default 'queued'
               check (status in ('queued', 'accepted', 'sent', 'replied', 'bounced', 'failed', 'cancelled', 'expired', 'skipped')),
  relay_id     uuid,
  error        text,
  requested_by uuid,
  created_at   timestamptz not null default now(),
  updated_at   timestamptz not null default now()
);
alter table public.deal_outreach enable row level security;
revoke insert, update, delete on public.deal_outreach from anon, authenticated;
drop policy if exists deal_outreach_select on public.deal_outreach;
-- You can see a deal's email status if you can see the deal (the subquery runs under the deals policies).
create policy deal_outreach_select on public.deal_outreach
  for select to authenticated using (
    owner_id = (select public.my_org_id())
    and exists (select 1 from public.deals d where d.id = deal_outreach.deal_id)
  );

-- Live updates on the pipeline board.
do $$
begin
  begin
    alter publication supabase_realtime add table public.deal_outreach;
  exception when duplicate_object or undefined_object then null;
  end;
end $$;

-- ---------------------------------------------------------------------------------------------------------
-- 4. Template filling
-- ---------------------------------------------------------------------------------------------------------
create or replace function public.crm_merge(p_text text, p_vars jsonb) returns text
language plpgsql immutable as $$
declare
  k text;
  v text;
  result text := coalesce(p_text, '');
begin
  for k, v in select key, value from jsonb_each_text(coalesce(p_vars, '{}'::jsonb)) loop
    result := replace(result, '{{' || k || '}}', coalesce(v, ''));
  end loop;
  return regexp_replace(result, '\{\{[^{}]*\}\}', '', 'g');   -- unknown tags vanish instead of showing up in the email
end $$;

create or replace function public.crm_text_to_html(p_text text) returns text
language sql immutable as $$
  select '<div>' || replace(replace(replace(replace(replace(coalesce(p_text, ''), '&', '&amp;'), '<', '&lt;'), '>', '&gt;'),
         E'\r', ''), E'\n', '<br>') || '</div>'
$$;

-- ---------------------------------------------------------------------------------------------------------
-- 5. The one place an outreach email is decided and queued (called by the trigger and the button)
-- ---------------------------------------------------------------------------------------------------------
create or replace function public.crm_outreach_queue(p_deal uuid, p_kind text, p_actor uuid) returns jsonb
language plpgsql security definer set search_path = public as $$
declare
  d record;
  s record;
  c record;
  v_sender uuid;
  v_email text;
  v_company text;
  v_first text;
  v_vars jsonb;
  v_status text := 'queued';
  v_error text;
  v_relay uuid;
begin
  select * into d from public.deals where id = p_deal;
  if not found then return jsonb_build_object('status', 'not_found'); end if;

  select * into s from public.crm_outreach_settings where owner_id = d.owner_id;
  if not found or s.mode = 'off' then return jsonb_build_object('status', 'off'); end if;

  if exists (select 1 from public.deal_outreach o
              where o.deal_id = p_deal and o.status in ('queued', 'accepted', 'sent', 'replied', 'bounced')) then
    return jsonb_build_object('status', 'already');
  end if;

  if d.contact_id is null then return jsonb_build_object('status', 'no_contact'); end if;
  select * into c from public.contacts where id = d.contact_id;
  v_email := lower(trim(coalesce(c.email, '')));
  v_sender := coalesce(d.assignee_id, d.created_by, d.owner_id);

  if v_email !~ '^[^@[:space:]]+@[^@[:space:]]+\.[^@[:space:]]+$' then
    v_status := 'skipped'; v_error := 'This contact has no valid email address.';
  elsif public.relay_billing_plan() = 'Free' then
    v_status := 'skipped'; v_error := 'Email automation is part of the Pro plan.';
  elsif (select count(*) from public.email_relay_queue q
          where q.user_id = v_sender and q.status in ('queued', 'claimed', 'accepted')) >= 50 then
    v_status := 'skipped'; v_error := 'Too many emails are already waiting for the desktop app.';
  elsif p_kind = 'auto' and (select count(*) from public.deals x
                              where x.created_by is not distinct from d.created_by
                                and x.created_at > now() - interval '60 seconds') > 5 then
    v_status := 'skipped'; v_error := 'Added in bulk, so not emailed automatically. Use the Email button for the ones you want.';
  elsif p_kind = 'auto' and exists (
          select 1 from public.email_relay_queue q join public.deals x on x.id = q.deal_id
           where x.owner_id = d.owner_id and lower(q.to_email) = v_email and q.deal_id <> p_deal
             and q.created_at > now() - interval '30 days'
             and q.status in ('queued', 'claimed', 'accepted', 'sent', 'replied', 'bounced')) then
    v_status := 'skipped'; v_error := 'This contact was already emailed from another deal in the last 30 days.';
  end if;

  if v_status = 'queued' then
    select name into v_company from public.companies where id = d.company_id;
    v_first := coalesce(nullif(trim(c.first_name), ''), nullif(split_part(trim(coalesce(c.name, '')), ' ', 1), ''), 'there');
    v_vars := jsonb_build_object(
      'first_name', v_first,
      'last_name', coalesce(c.last_name, ''),
      'name', coalesce(nullif(trim(c.name), ''), v_first),
      'company', coalesce(nullif(trim(v_company), ''), 'your company'),
      'deal_title', coalesce(d.title, ''));
    insert into public.email_relay_queue (user_id, to_email, subject, body_html, deal_id)
    values (v_sender, v_email,
            left(public.crm_merge(s.subject, v_vars), 200),
            public.crm_text_to_html(public.crm_merge(s.body, v_vars)),
            p_deal)
    returning id into v_relay;
  end if;

  insert into public.deal_outreach as o (deal_id, owner_id, sender_id, trigger_kind, status, relay_id, error, requested_by, updated_at)
  values (p_deal, d.owner_id, v_sender, p_kind, v_status, v_relay, v_error, p_actor, now())
  on conflict (deal_id) do update
    set sender_id = excluded.sender_id, trigger_kind = excluded.trigger_kind, status = excluded.status,
        relay_id = excluded.relay_id, error = excluded.error, requested_by = excluded.requested_by, updated_at = now();

  return jsonb_build_object('status', v_status, 'error', v_error);
end $$;

-- ---------------------------------------------------------------------------------------------------------
-- 6. The Email button, and saving the settings
-- ---------------------------------------------------------------------------------------------------------
create or replace function public.crm_outreach_request(p_deal_id uuid) returns jsonb
language plpgsql security definer set search_path = public as $$
declare
  v_uid uuid := auth.uid();
  v_ok boolean;
begin
  if v_uid is null then raise exception 'not signed in'; end if;
  -- the same rule as the deals update policy: your organization's deal, one you can see, and you may edit
  select exists (
    select 1 from public.deals dl
     where dl.id = p_deal_id
       and dl.owner_id = public.my_org_id()
       and (public.is_owner() or public.has_perm('view_all')
            or dl.assignee_id = any (public.my_team_ids()) or dl.created_by = any (public.my_team_ids()))
       and public.has_perm('edit')
  ) into v_ok;
  if not v_ok then raise exception 'You cannot send email from this deal.'; end if;
  return public.crm_outreach_queue(p_deal_id, 'manual', v_uid);
end $$;

create or replace function public.crm_outreach_save(p_mode text, p_subject text, p_body text) returns void
language plpgsql security definer set search_path = public as $$
declare v_org uuid := public.my_org_id();
begin
  if auth.uid() is null or v_org is null then raise exception 'not signed in'; end if;
  if not (public.is_owner() or public.is_org_admin()) then
    raise exception 'Only the organization owner or an admin can change email automation.';
  end if;
  if p_mode not in ('off', 'semi', 'auto') then raise exception 'unknown mode'; end if;
  if p_mode <> 'off' and public.relay_billing_plan() = 'Free' then
    raise exception 'Email automation is part of the Pro plan.';
  end if;
  if length(trim(coalesce(p_subject, ''))) not between 1 and 200 then raise exception 'The subject must be 1 to 200 characters.'; end if;
  if length(trim(coalesce(p_body, ''))) not between 1 and 5000 then raise exception 'The message must be 1 to 5000 characters.'; end if;
  insert into public.crm_outreach_settings as s (owner_id, mode, subject, body, updated_by, updated_at)
  values (v_org, p_mode, trim(p_subject), trim(p_body), auth.uid(), now())
  on conflict (owner_id) do update
    set mode = excluded.mode, subject = excluded.subject, body = excluded.body,
        updated_by = excluded.updated_by, updated_at = now();
end $$;

-- ---------------------------------------------------------------------------------------------------------
-- 7. Triggers
-- ---------------------------------------------------------------------------------------------------------

-- Automatic mode: a new deal, or a contact added to a deal that is under 2 hours old. Never blocks the deal.
create or replace function public.crm_outreach_deal_trg() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  if TG_OP = 'UPDATE' and not (old.contact_id is null and new.contact_id is not null
                               and new.created_at > now() - interval '2 hours') then
    return null;
  end if;
  if exists (select 1 from public.crm_outreach_settings s where s.owner_id = new.owner_id and s.mode = 'auto') then
    begin
      perform public.crm_outreach_queue(new.id, 'auto', auth.uid());
    exception when others then
      raise warning 'CRM outreach skipped for deal %: %', new.id, sqlerrm;
    end;
  end if;
  return null;
end $$;

drop trigger if exists crm_outreach_after_insert on public.deals;
create trigger crm_outreach_after_insert after insert on public.deals
  for each row execute function public.crm_outreach_deal_trg();
drop trigger if exists crm_outreach_after_contact on public.deals;
create trigger crm_outreach_after_contact after update of contact_id on public.deals
  for each row when (old.contact_id is distinct from new.contact_id)
  execute function public.crm_outreach_deal_trg();

-- Keep the card's status in step with the relay queue (desktop picked it up, sent, failed, bounced, replied...).
create or replace function public.crm_outreach_sync_trg() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  update public.deal_outreach
     set status = case new.status when 'claimed' then 'queued' else new.status end,
         error = case when new.status in ('failed', 'cancelled', 'expired') then coalesce(new.error, error) else null end,
         updated_at = now()
   where deal_id = new.deal_id and relay_id = new.id;
  return null;
end $$;

drop trigger if exists email_relay_queue_deal_sync on public.email_relay_queue;
create trigger email_relay_queue_deal_sync after update of status on public.email_relay_queue
  for each row when (new.deal_id is not null and new.status is distinct from old.status)
  execute function public.crm_outreach_sync_trg();

-- ---------------------------------------------------------------------------------------------------------
-- 8. Who may call what
-- ---------------------------------------------------------------------------------------------------------
revoke all on function public.crm_outreach_queue(uuid, text, uuid) from public, anon, authenticated;
revoke all on function public.crm_outreach_deal_trg() from public, anon, authenticated;
revoke all on function public.crm_outreach_sync_trg() from public, anon, authenticated;
revoke all on function public.crm_outreach_request(uuid) from public, anon;
revoke all on function public.crm_outreach_save(text, text, text) from public, anon;
grant execute on function public.crm_outreach_request(uuid) to authenticated;
grant execute on function public.crm_outreach_save(text, text, text) to authenticated;

notify pgrst, 'reload schema';

select to_regclass('public.crm_outreach_settings') is not null as settings_exist,
       to_regclass('public.deal_outreach') is not null as status_table_exists;
