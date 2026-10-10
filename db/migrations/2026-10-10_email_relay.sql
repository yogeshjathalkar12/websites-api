-- Desktop email relay.
--
-- The web app cannot send mail itself while the server blocks SMTP ports, so mail written there waits in
-- public.email_relay_queue and the user's own desktop app picks it up and sends it from their own mailbox
-- (where warm-up, daily cap, opening hours, suppression and bounce pauses already apply).
--
--   web app / server  --insert-->  email_relay_queue  --relay_claim()-->  desktop app  --relay_report()-->  queue + web tables
--
-- * Mail that is not claimed within 48 hours of its scheduled time EXPIRES and is never sent late.
-- * The email body is deleted from this table as soon as the mail has been sent (or has failed / been cancelled).
-- * Browsers can only READ their own rows. Everything else goes through the functions below, which check who is calling.
-- Safe to run more than once. Run in the Supabase SQL editor.

-- ---------------------------------------------------------------------------------------------------------
-- 1. Is the desktop app online? (the web app shows this)
-- ---------------------------------------------------------------------------------------------------------
create table if not exists public.desktop_heartbeats (
  user_id           uuid primary key references auth.users(id) on delete cascade,
  device_id         text,
  app_version       text,
  mailbox_connected boolean not null default false,
  paused_reason     text,
  pending_count     integer not null default 0,
  last_seen_at      timestamptz not null default now()
);
alter table public.desktop_heartbeats enable row level security;
drop policy if exists desktop_heartbeats_select_own on public.desktop_heartbeats;
create policy desktop_heartbeats_select_own on public.desktop_heartbeats
  for select to authenticated using (user_id = auth.uid());

-- ---------------------------------------------------------------------------------------------------------
-- 2. The queue
-- ---------------------------------------------------------------------------------------------------------
create table if not exists public.email_relay_queue (
  id             uuid primary key default gen_random_uuid(),
  user_id        uuid not null references auth.users(id) on delete cascade,  -- whose desktop sends it
  account_id     uuid references public.email_accounts(id) on delete cascade,
  to_email       text not null,
  subject        text not null,
  body_html      text,                                                       -- cleared once delivered
  send_after     timestamptz not null default now(),
  expires_at     timestamptz not null default (now() + interval '48 hours'),
  status         text not null default 'queued'
                 check (status in ('queued','claimed','accepted','sent','failed','bounced','replied','cancelled','expired')),
  attempts       integer not null default 0,
  claimed_device text,
  claimed_at     timestamptz,
  lease_until    timestamptz,
  sent_at        timestamptz,
  error          text,
  local_ref      text,
  created_at     timestamptz not null default now(),
  updated_at     timestamptz not null default now()
);

create index if not exists email_relay_queue_user_status_idx on public.email_relay_queue (user_id, status, send_after);
create index if not exists email_relay_queue_account_idx on public.email_relay_queue (account_id);

alter table public.email_relay_queue enable row level security;
drop policy if exists email_relay_queue_select_own on public.email_relay_queue;
create policy email_relay_queue_select_own on public.email_relay_queue
  for select to authenticated using (user_id = auth.uid());
-- No insert/update/delete policy on purpose: the server (service role) inserts, the functions below change state.

-- ---------------------------------------------------------------------------------------------------------
-- 3. Helpers
-- ---------------------------------------------------------------------------------------------------------

-- The plan of the caller's organization ('Free' when unknown). Members use their organization's plan.
create or replace function public.relay_billing_plan() returns text
language sql stable security definer set search_path = public as $$
  select coalesce((
    select ru.plan::text
      from public.raptor_users ru
     where ru.user_id = case
             when exists (select 1 from public.org_members m0 where m0.user_id = auth.uid())
               then (select m.org_id from public.org_members m where m.user_id = auth.uid() and m.status = 'active' limit 1)
             else auth.uid()
           end
  ), 'Free')
$$;

-- When a queued email will never go out, the web tables should say so.
create or replace function public.relay_fail_web_rows(p_id uuid, p_status text) returns void
language plpgsql security definer set search_path = public as $$
begin
  update public.email_campaign_recipients set status = p_status
   where provider_message_id = p_id::text and status = 'sent';
  update public.email_sequence_sends set status = p_status
   where provider_message_id = p_id::text and status = 'sent';
end $$;

-- ---------------------------------------------------------------------------------------------------------
-- 4. Desktop app -> database
-- ---------------------------------------------------------------------------------------------------------

-- Hands the caller's due emails to the desktop app (max 50 at a time). Also expires old mail and cancels mail to
-- people who unsubscribed or bounced in the meantime. A claim lasts 10 minutes; the desktop app queues mail
-- idempotently, so if it dies and the claim is handed out again, nothing is sent twice.
create or replace function public.relay_claim(p_device text, p_limit integer default 10)
returns setof public.email_relay_queue
language plpgsql security definer set search_path = public as $$
declare
  v_uid uuid := auth.uid();
  r record;
begin
  if v_uid is null then raise exception 'not signed in'; end if;

  for r in
    update public.email_relay_queue
       set status = 'expired', body_html = null, updated_at = now(),
           error = 'Not sent in time: your desktop app was offline for too long.'
     where user_id = v_uid and status in ('queued', 'claimed') and expires_at < now()
    returning id
  loop
    perform public.relay_fail_web_rows(r.id, 'failed');
  end loop;

  if public.relay_billing_plan() = 'Free' then return; end if;

  for r in
    update public.email_relay_queue q
       set status = 'cancelled', body_html = null, updated_at = now(),
           error = 'This person unsubscribed or bounced before the email was sent.'
     where q.user_id = v_uid and q.status in ('queued', 'claimed') and q.account_id is not null
       and exists (select 1 from public.email_suppressions s
                    where s.account_id = q.account_id and lower(s.email) = lower(q.to_email))
    returning q.id
  loop
    perform public.relay_fail_web_rows(r.id, 'cancelled');
  end loop;

  return query
  with due as (
    select id from public.email_relay_queue
     where user_id = v_uid and send_after <= now() and expires_at >= now()
       and (status = 'queued' or (status = 'claimed' and lease_until < now()))
     order by send_after, created_at
     limit greatest(1, least(coalesce(p_limit, 10), 50))
     for update skip locked
  )
  update public.email_relay_queue q
     set status = 'claimed', claimed_device = p_device, claimed_at = now(),
         lease_until = now() + interval '10 minutes', attempts = q.attempts + 1, updated_at = now()
    from due
   where q.id = due.id
  returning q.*;
end $$;

-- The desktop app tells us what happened to one email. Status only moves forward:
-- queued -> claimed -> accepted -> sent -> (bounced | replied); failed / cancelled / expired are final.
create or replace function public.relay_report(
  p_id uuid, p_status text, p_error text default null, p_local_ref text default null, p_sent_at timestamptz default null
) returns void
language plpgsql security definer set search_path = public as $$
declare
  v_uid uuid := auth.uid();
  r public.email_relay_queue%rowtype;
begin
  if v_uid is null then raise exception 'not signed in'; end if;
  if p_status not in ('accepted', 'sent', 'failed', 'bounced', 'replied', 'cancelled') then
    raise exception 'unknown status %', p_status;
  end if;

  select * into r from public.email_relay_queue where id = p_id and user_id = v_uid for update;
  if not found then return; end if;                                   -- not this caller's email: ignore
  if r.status in ('failed', 'cancelled', 'expired', 'bounced', 'replied') then return; end if;
  if r.status = 'sent' and p_status not in ('bounced', 'replied') then return; end if;
  if r.status = 'accepted' and p_status = 'accepted' then return; end if;

  update public.email_relay_queue
     set status = p_status,
         error = case when p_status in ('failed', 'cancelled') then left(coalesce(p_error, error), 500) else error end,
         local_ref = coalesce(p_local_ref, local_ref),
         sent_at = case when p_status = 'sent' then coalesce(p_sent_at, now()) else sent_at end,
         body_html = case when p_status in ('sent', 'failed', 'bounced', 'replied', 'cancelled') then null else body_html end,
         lease_until = case when p_status = 'accepted' then null else lease_until end,
         updated_at = now()
   where id = p_id;

  if p_status in ('failed', 'cancelled') then
    perform public.relay_fail_web_rows(p_id, p_status);
  elsif r.account_id is not null and p_status = 'bounced' then
    insert into public.email_events (account_id, contact_email, event_type, provider_message_id)
      values (r.account_id, r.to_email, 'bounced', p_id::text);
    insert into public.email_suppressions (account_id, email, reason)
      select r.account_id, r.to_email, 'bounced'
       where not exists (select 1 from public.email_suppressions s
                          where s.account_id = r.account_id and lower(s.email) = lower(r.to_email));
  elsif r.account_id is not null and p_status = 'replied' then
    insert into public.email_events (account_id, contact_email, event_type, provider_message_id)
      values (r.account_id, r.to_email, 'replied', p_id::text);
  end if;
end $$;

-- "I'm here": called every ~30 seconds by the desktop app while it is open and signed in.
create or replace function public.relay_heartbeat(
  p_device text, p_version text, p_mailbox_connected boolean, p_paused text, p_pending integer
) returns void
language plpgsql security definer set search_path = public as $$
begin
  if auth.uid() is null then raise exception 'not signed in'; end if;
  insert into public.desktop_heartbeats as h (user_id, device_id, app_version, mailbox_connected, paused_reason, pending_count, last_seen_at)
  values (auth.uid(), left(p_device, 100), left(p_version, 40), coalesce(p_mailbox_connected, false), left(p_paused, 100), greatest(coalesce(p_pending, 0), 0), now())
  on conflict (user_id) do update
    set device_id = excluded.device_id, app_version = excluded.app_version, mailbox_connected = excluded.mailbox_connected,
        paused_reason = excluded.paused_reason, pending_count = excluded.pending_count, last_seen_at = now();
end $$;

-- ---------------------------------------------------------------------------------------------------------
-- 5. Web app -> database
-- ---------------------------------------------------------------------------------------------------------

-- Cancel an email that is still waiting (not yet picked up by the desktop app).
create or replace function public.relay_cancel(p_id uuid) returns boolean
language plpgsql security definer set search_path = public as $$
declare v_count integer;
begin
  if auth.uid() is null then raise exception 'not signed in'; end if;
  update public.email_relay_queue
     set status = 'cancelled', body_html = null, error = 'Cancelled before it was sent.', updated_at = now()
   where id = p_id and user_id = auth.uid() and status = 'queued';
  get diagnostics v_count = row_count;
  if v_count > 0 then perform public.relay_fail_web_rows(p_id, 'cancelled'); end if;
  return v_count > 0;
end $$;

-- ---------------------------------------------------------------------------------------------------------
-- 6. Who may call what
-- ---------------------------------------------------------------------------------------------------------
revoke all on function public.relay_billing_plan() from public, anon;
revoke all on function public.relay_fail_web_rows(uuid, text) from public, anon, authenticated;
revoke all on function public.relay_claim(text, integer) from public, anon;
revoke all on function public.relay_report(uuid, text, text, text, timestamptz) from public, anon;
revoke all on function public.relay_heartbeat(text, text, boolean, text, integer) from public, anon;
revoke all on function public.relay_cancel(uuid) from public, anon;
grant execute on function public.relay_billing_plan() to authenticated;
grant execute on function public.relay_claim(text, integer) to authenticated;
grant execute on function public.relay_report(uuid, text, text, text, timestamptz) to authenticated;
grant execute on function public.relay_heartbeat(text, text, boolean, text, integer) to authenticated;
grant execute on function public.relay_cancel(uuid) to authenticated;

notify pgrst, 'reload schema';

select to_regclass('public.email_relay_queue') is not null as relay_queue_exists,
       to_regclass('public.desktop_heartbeats') is not null as heartbeats_exist;
