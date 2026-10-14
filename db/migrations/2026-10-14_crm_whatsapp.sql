-- CRM WhatsApp outreach: off / semi-automatic / automatic, the same idea as the email modes (2026-10-14_crm_outreach.sql).
--
--   off   nothing is sent.
--   semi  each pipeline card with a contact gets a "WhatsApp" button next to Call and Email; nothing is sent until it is clicked.
--   auto  a message is queued the moment a new deal with a contact phone number is added.
--
-- WhatsApp only lets a business START a conversation with a template that Meta has approved, so the "template" here is
-- the name of one of your approved templates plus which contact details fill its {{1}} {{2}} ... blanks.
-- Unlike email this is sent by the backend (your WhatsApp access token lives there, encrypted), so the database only
-- QUEUES the message (status 'pending') and the backend's POST /api/raptor/whatsapp/crm/dispatch sends it. The web app
-- calls that endpoint whenever a message is waiting, so no scheduler is needed while someone has Raptor open.
-- What became of each message (sent, delivered, read, replied, failed) is shown on the pipeline card (table deal_whatsapp,
-- kept apart from the deals table so deal history is not filled with status changes).
--
-- Safeguards: switching it on needs a confirmation that the contacts agreed to receive WhatsApp messages; automatic mode
-- never messages bulk-imported deals (more than 5 added by one person within a minute), nobody is messaged twice within
-- 30 days, people who opted out are skipped, and at most 50 messages wait at once. A failure here never stops a deal
-- from being saved.
-- Needs the relay migration (2026-10-10) and the email modes migration (2026-10-14_crm_outreach) first.
-- Safe to run more than once. Run in the Supabase SQL editor.

-- ---------------------------------------------------------------------------------------------------------
-- 1. Settings (per organization)
-- ---------------------------------------------------------------------------------------------------------
create table if not exists public.crm_whatsapp_settings (
  owner_id            uuid primary key references auth.users(id) on delete cascade,   -- the organization id
  mode                text not null default 'off' check (mode in ('off', 'semi', 'auto')),
  account_id          uuid references public.whatsapp_accounts(id) on delete set null,
  template_name       text,
  template_language   text not null default 'en_US',
  params              text[] not null default '{}',     -- what fills {{1}}, {{2}}...: first_name | last_name | name | company | deal_title
  country_code        text not null default '91',       -- put in front of 10-digit numbers
  opt_in_confirmed_at timestamptz,
  updated_by          uuid,
  updated_at          timestamptz not null default now()
);
alter table public.crm_whatsapp_settings enable row level security;
drop policy if exists crm_whatsapp_settings_select on public.crm_whatsapp_settings;
create policy crm_whatsapp_settings_select on public.crm_whatsapp_settings
  for select to authenticated using (owner_id = (select public.my_org_id()));
revoke insert, update, delete on public.crm_whatsapp_settings from anon, authenticated;

-- ---------------------------------------------------------------------------------------------------------
-- 2. What became of each deal's message
-- ---------------------------------------------------------------------------------------------------------
create table if not exists public.deal_whatsapp (
  deal_id           uuid primary key references public.deals(id) on delete cascade,
  owner_id          uuid not null,
  sender_id         uuid,
  contact_id        uuid,
  account_id        uuid references public.whatsapp_accounts(id) on delete set null,
  trigger_kind      text not null default 'manual' check (trigger_kind in ('manual', 'auto')),
  status            text not null default 'pending'
                    check (status in ('pending', 'sending', 'sent', 'delivered', 'read', 'replied', 'failed', 'skipped')),
  to_phone          text,
  template_name     text,
  template_language text,
  params            text[] not null default '{}',
  message_id        text,
  error             text,                                -- the reason, or a note while it waits (business hours, daily limit)
  attempts          integer not null default 0,
  requested_by      uuid,
  created_at        timestamptz not null default now(),
  updated_at        timestamptz not null default now(),
  sent_at           timestamptz
);
create index if not exists deal_whatsapp_owner_status_idx on public.deal_whatsapp (owner_id, status);
create index if not exists deal_whatsapp_message_idx on public.deal_whatsapp (message_id) where message_id is not null;
alter table public.deal_whatsapp enable row level security;
revoke insert, update, delete on public.deal_whatsapp from anon, authenticated;
drop policy if exists deal_whatsapp_select on public.deal_whatsapp;
create policy deal_whatsapp_select on public.deal_whatsapp
  for select to authenticated using (
    owner_id = (select public.my_org_id())
    and exists (select 1 from public.deals d where d.id = deal_whatsapp.deal_id)
  );

do $$
begin
  begin
    alter publication supabase_realtime add table public.deal_whatsapp;
  exception when duplicate_object or undefined_object then null;
  end;
end $$;

-- ---------------------------------------------------------------------------------------------------------
-- 3. Phone numbers: WhatsApp wants digits with the country code, no + or spaces
-- ---------------------------------------------------------------------------------------------------------
create or replace function public.crm_wa_phone(p_raw text, p_cc text) returns text
language plpgsql immutable as $$
declare
  d text;
  cc text := coalesce(nullif(regexp_replace(coalesce(p_cc, ''), '\D', '', 'g'), ''), '91');
begin
  if p_raw is null then return null; end if;
  d := regexp_replace(p_raw, '\D', '', 'g');
  if d = '' then return null; end if;
  if btrim(p_raw) like '+%' then
    null;                                           -- already international
  elsif left(d, 2) = '00' then
    d := substr(d, 3);
  elsif length(d) = 10 then
    d := cc || d;
  elsif left(d, 1) = '0' and length(d) = 11 then
    d := cc || substr(d, 2);
  end if;
  if length(d) < 8 or length(d) > 15 then return null; end if;
  return d;
end $$;

-- ---------------------------------------------------------------------------------------------------------
-- 4. The one place a WhatsApp message is decided and queued (called by the trigger and the button)
-- ---------------------------------------------------------------------------------------------------------
create or replace function public.crm_wa_queue(p_deal uuid, p_kind text, p_actor uuid) returns jsonb
language plpgsql security definer set search_path = public as $$
declare
  d record;
  s record;
  c record;
  v_company text;
  v_first text;
  v_phone text;
  v_vars jsonb;
  v_params text[] := '{}';
  k text;
  v_status text := 'pending';
  v_error text;
begin
  select * into d from public.deals where id = p_deal;
  if not found then return jsonb_build_object('status', 'not_found'); end if;

  select * into s from public.crm_whatsapp_settings where owner_id = d.owner_id;
  if not found or s.mode = 'off' then return jsonb_build_object('status', 'off'); end if;

  if exists (select 1 from public.deal_whatsapp o
              where o.deal_id = p_deal and o.status in ('pending', 'sending', 'sent', 'delivered', 'read', 'replied')) then
    return jsonb_build_object('status', 'already');
  end if;

  if d.contact_id is null then return jsonb_build_object('status', 'no_contact'); end if;
  select * into c from public.contacts where id = d.contact_id;
  v_phone := public.crm_wa_phone(c.phone, s.country_code);

  if s.account_id is null or coalesce(s.template_name, '') = '' then
    v_status := 'skipped'; v_error := 'WhatsApp is not fully set up: choose a number and a template in the WhatsApp settings.';
  elsif s.opt_in_confirmed_at is null then
    v_status := 'skipped'; v_error := 'Confirm in the WhatsApp settings that your contacts agreed to receive WhatsApp messages.';
  elsif v_phone is null then
    v_status := 'skipped'; v_error := 'This contact has no valid phone number.';
  elsif public.relay_billing_plan() = 'Free' then
    v_status := 'skipped'; v_error := 'WhatsApp automation is part of the Pro plan.';
  elsif exists (select 1 from public.whatsapp_suppressions x where x.account_id = s.account_id and x.phone = v_phone) then
    v_status := 'skipped'; v_error := 'This person opted out of WhatsApp messages.';
  elsif (select count(*) from public.deal_whatsapp q where q.owner_id = d.owner_id and q.status in ('pending', 'sending')) >= 50 then
    v_status := 'skipped'; v_error := 'Too many WhatsApp messages are already waiting to be sent.';
  elsif p_kind = 'auto' and (select count(*) from public.deals x
                              where x.created_by is not distinct from d.created_by
                                and x.created_at > now() - interval '60 seconds') > 5 then
    v_status := 'skipped'; v_error := 'Added in bulk, so not messaged automatically. Use the WhatsApp button for the ones you want.';
  elsif p_kind = 'auto' and exists (
          select 1 from public.deal_whatsapp q join public.deals x on x.id = q.deal_id
           where x.owner_id = d.owner_id and q.to_phone = v_phone and q.deal_id <> p_deal
             and q.created_at > now() - interval '30 days'
             and q.status in ('pending', 'sending', 'sent', 'delivered', 'read', 'replied')) then
    v_status := 'skipped'; v_error := 'This contact was already messaged from another deal in the last 30 days.';
  end if;

  if v_status = 'pending' then
    select name into v_company from public.companies where id = d.company_id;
    v_first := coalesce(nullif(trim(c.first_name), ''), nullif(split_part(trim(coalesce(c.name, '')), ' ', 1), ''), 'there');
    v_vars := jsonb_build_object(
      'first_name', v_first,
      'last_name', coalesce(nullif(trim(c.last_name), ''), '-'),
      'name', coalesce(nullif(trim(c.name), ''), v_first),
      'company', coalesce(nullif(trim(v_company), ''), 'your company'),
      'deal_title', coalesce(nullif(trim(d.title), ''), '-'));
    foreach k in array s.params loop
      v_params := v_params || coalesce(v_vars ->> k, '-');
    end loop;
  end if;

  insert into public.deal_whatsapp as o
    (deal_id, owner_id, sender_id, contact_id, account_id, trigger_kind, status, to_phone, template_name, template_language,
     params, message_id, error, attempts, requested_by, updated_at, sent_at)
  values (p_deal, d.owner_id, coalesce(d.assignee_id, d.created_by, d.owner_id), d.contact_id, s.account_id, p_kind, v_status, v_phone,
          s.template_name, s.template_language, v_params, null, v_error, 0, p_actor, now(), null)
  on conflict (deal_id) do update
    set sender_id = excluded.sender_id, contact_id = excluded.contact_id, account_id = excluded.account_id,
        trigger_kind = excluded.trigger_kind, status = excluded.status, to_phone = excluded.to_phone,
        template_name = excluded.template_name, template_language = excluded.template_language, params = excluded.params,
        message_id = null, error = excluded.error, attempts = 0, requested_by = excluded.requested_by,
        updated_at = now(), sent_at = null;

  return jsonb_build_object('status', v_status, 'error', v_error);
end $$;

-- ---------------------------------------------------------------------------------------------------------
-- 5. The WhatsApp button, and saving the settings
-- ---------------------------------------------------------------------------------------------------------
create or replace function public.crm_wa_request(p_deal_id uuid) returns jsonb
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
  if not v_ok then raise exception 'You cannot send WhatsApp messages from this deal.'; end if;
  return public.crm_wa_queue(p_deal_id, 'manual', v_uid);
end $$;

create or replace function public.crm_wa_save(
  p_mode text, p_account uuid, p_template text, p_language text, p_params text[], p_country_code text, p_opt_in boolean
) returns void
language plpgsql security definer set search_path = public as $$
declare
  v_org uuid := public.my_org_id();
  v_prev timestamptz;
  v_cc text := regexp_replace(coalesce(p_country_code, ''), '\D', '', 'g');
  v_params text[] := coalesce(p_params, '{}');
  k text;
begin
  if auth.uid() is null or v_org is null then raise exception 'not signed in'; end if;
  if not (public.is_owner() or public.is_org_admin()) then
    raise exception 'Only the organization owner or an admin can change WhatsApp automation.';
  end if;
  if p_mode not in ('off', 'semi', 'auto') then raise exception 'unknown mode'; end if;
  if p_mode <> 'off' and public.relay_billing_plan() = 'Free' then
    raise exception 'WhatsApp automation is part of the Pro plan.';
  end if;
  if array_length(v_params, 1) > 5 then raise exception 'A template can take at most 5 variables.'; end if;
  foreach k in array v_params loop
    if k not in ('first_name', 'last_name', 'name', 'company', 'deal_title') then raise exception 'Unknown variable %.', k; end if;
  end loop;
  if v_cc !~ '^[0-9]{1,3}$' then raise exception 'The country code must be 1 to 3 digits, like 91.'; end if;
  if coalesce(p_language, '') !~ '^[a-z]{2,3}(_[A-Za-z]{2})?$' then raise exception 'The language must look like en_US.'; end if;

  if p_mode <> 'off' then
    if coalesce(p_template, '') !~ '^[a-z0-9_]{1,255}$' then
      raise exception 'The template name must be lowercase letters, numbers and underscores, exactly as in WhatsApp Manager.';
    end if;
    if p_account is null or not exists (select 1 from public.whatsapp_accounts a
                                         where a.id = p_account and (a.owner_id = auth.uid() or a.owner_id = v_org)) then
      raise exception 'Choose one of your connected WhatsApp numbers.';
    end if;
  end if;

  select opt_in_confirmed_at into v_prev from public.crm_whatsapp_settings where owner_id = v_org;
  if p_mode <> 'off' and v_prev is null and not coalesce(p_opt_in, false) then
    raise exception 'Please confirm that your contacts agreed to receive WhatsApp messages from you.';
  end if;

  insert into public.crm_whatsapp_settings as s
    (owner_id, mode, account_id, template_name, template_language, params, country_code, opt_in_confirmed_at, updated_by, updated_at)
  values (v_org, p_mode, p_account, nullif(trim(p_template), ''), p_language, v_params, v_cc,
          case when coalesce(p_opt_in, false) then now() else null end, auth.uid(), now())
  on conflict (owner_id) do update
    set mode = excluded.mode, account_id = excluded.account_id, template_name = excluded.template_name,
        template_language = excluded.template_language, params = excluded.params, country_code = excluded.country_code,
        opt_in_confirmed_at = coalesce(s.opt_in_confirmed_at, excluded.opt_in_confirmed_at),
        updated_by = excluded.updated_by, updated_at = now();
end $$;

-- ---------------------------------------------------------------------------------------------------------
-- 6. Triggers
-- ---------------------------------------------------------------------------------------------------------

-- Automatic mode: a new deal, or a contact added to a deal that is under 2 hours old. Never blocks the deal.
create or replace function public.crm_wa_deal_trg() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  if TG_OP = 'UPDATE' and not (old.contact_id is null and new.contact_id is not null
                               and new.created_at > now() - interval '2 hours') then
    return null;
  end if;
  if exists (select 1 from public.crm_whatsapp_settings s where s.owner_id = new.owner_id and s.mode = 'auto') then
    begin
      perform public.crm_wa_queue(new.id, 'auto', auth.uid());
    exception when others then
      raise warning 'CRM WhatsApp skipped for deal %: %', new.id, sqlerrm;
    end;
  end if;
  return null;
end $$;

drop trigger if exists crm_wa_after_insert on public.deals;
create trigger crm_wa_after_insert after insert on public.deals
  for each row execute function public.crm_wa_deal_trg();
drop trigger if exists crm_wa_after_contact on public.deals;
create trigger crm_wa_after_contact after update of contact_id on public.deals
  for each row when (old.contact_id is distinct from new.contact_id)
  execute function public.crm_wa_deal_trg();

-- Meta reports delivered / read / failed, and the contact may answer: keep the card in step.
-- (The backend already stores these as whatsapp_events rows; this only reads them.)
create or replace function public.crm_wa_event_sync_trg() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  if new.direction = 'outbound' and new.provider_message_id is not null then
    if new.event_type = 'delivered' then
      update public.deal_whatsapp set status = 'delivered', updated_at = now()
       where message_id = new.provider_message_id and status = 'sent';
    elsif new.event_type = 'read' then
      update public.deal_whatsapp set status = 'read', updated_at = now()
       where message_id = new.provider_message_id and status in ('sent', 'delivered');
    elsif new.event_type = 'failed' then
      update public.deal_whatsapp set status = 'failed', updated_at = now(),
             error = coalesce(error, 'WhatsApp could not deliver this message.')
       where message_id = new.provider_message_id and status in ('sent', 'delivered');
    end if;
  elsif new.direction = 'inbound' and new.event_type = 'received' and new.contact_phone is not null then
    update public.deal_whatsapp set status = 'replied', updated_at = now()
     where account_id = new.account_id and to_phone = new.contact_phone
       and status in ('sent', 'delivered', 'read') and sent_at > now() - interval '14 days';
  end if;
  return null;
end $$;

drop trigger if exists whatsapp_events_deal_sync on public.whatsapp_events;
create trigger whatsapp_events_deal_sync after insert on public.whatsapp_events
  for each row execute function public.crm_wa_event_sync_trg();

-- ---------------------------------------------------------------------------------------------------------
-- 7. Who may call what
-- ---------------------------------------------------------------------------------------------------------
revoke all on function public.crm_wa_queue(uuid, text, uuid) from public, anon, authenticated;
revoke all on function public.crm_wa_deal_trg() from public, anon, authenticated;
revoke all on function public.crm_wa_event_sync_trg() from public, anon, authenticated;
revoke all on function public.crm_wa_request(uuid) from public, anon;
revoke all on function public.crm_wa_save(text, uuid, text, text, text[], text, boolean) from public, anon;
grant execute on function public.crm_wa_request(uuid) to authenticated;
grant execute on function public.crm_wa_save(text, uuid, text, text, text[], text, boolean) to authenticated;

notify pgrst, 'reload schema';

select to_regclass('public.crm_whatsapp_settings') is not null as settings_exist,
       to_regclass('public.deal_whatsapp') is not null as status_table_exists;
