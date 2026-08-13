-- ══════════════════════════════════════════════════════════════════
-- Mailer addition — run this AFTER the existing schema.sql
-- ══════════════════════════════════════════════════════════════════

-- ── Tool 10: Multi-Tenant SMTP Dispatcher ─────────────────────────────
create table if not exists user_mail_settings (
  user_id                  uuid primary key references auth.users(id) on delete cascade,
  provider                 text not null default 'custom',
  smtp_host                text not null,
  smtp_port                int not null default 587,
  from_email               text not null,
  encrypted_app_password   text not null,   -- Fernet-encrypted, never plaintext
  daily_limit              int not null default 150,
  active                   boolean not null default true,
  updated_at               timestamptz not null default now()
);
alter table user_mail_settings enable row level security;
create policy "own mail settings" on user_mail_settings
  for select using (auth.uid() = user_id);
-- No insert/update/delete policy for anon/authenticated: writes only
-- happen through the FastAPI backend's service-role key, same pattern
-- as every other table in this schema.

-- ── Suppression list (never re-send to these addresses) ──────────────
create table if not exists suppressed_recipients (
  id            bigint generated always as identity primary key,
  user_id       uuid not null references auth.users(id) on delete cascade,
  email         text not null,
  reason        text not null check (reason in ('unsubscribed','bounced','manual','complaint')),
  created_at    timestamptz not null default now(),
  unique (user_id, email)
);
create index if not exists idx_suppressed_user on suppressed_recipients (user_id, email);
alter table suppressed_recipients enable row level security;
create policy "own suppression list" on suppressed_recipients
  for select using (auth.uid() = user_id);

-- ── outreach_queue additions needed for the dispatcher ────────────────
-- spintax_router.py's /queue endpoint currently writes variant_text +
-- variant_hash but not who each variant is addressed to, or a subject
-- line, or a sent_at timestamp for the daily-cap check in mailer_router.py.
alter table outreach_queue add column if not exists recipient_email text;
alter table outreach_queue add column if not exists subject text;
alter table outreach_queue add column if not exists sent_at timestamptz;
create index if not exists idx_outreach_queue_unsent on outreach_queue (user_id, sent) where sent = false;

-- ══════════════════════════════════════════════════════════════════
-- Reminder: spintax_router.py's /queue endpoint needs a small update to
-- accept recipient_email + subject per row and to check
-- suppressed_recipients before inserting — see the note in
-- mailer_router.py's compliance block. Not included here since that's
-- an edit to an existing file, not a new table.
-- ══════════════════════════════════════════════════════════════════