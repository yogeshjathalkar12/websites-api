-- ══════════════════════════════════════════════════════════════════
-- Raptor Arsenal — Supabase schema for the 9 heavy-compute tools
-- ══════════════════════════════════════════════════════════════════
-- Assumes raptor_users(user_id uuid primary key, credits int, ...)
-- already exists from the original Raptor deployment — every tool
-- below draws from and writes to that same shared credit pool via
-- raptor_auth.deduct_credit(), so it is NOT recreated here.
--
-- Pattern for every table: RLS is ON. The FastAPI backend authenticates
-- with the Supabase service-role key, which bypasses RLS entirely (by
-- design, same as raptor_campaigns/raptor_opens) — so the backend can
-- always read/write. The policies below exist so that IF a table is
-- ever queried directly from client-side JS with the anon key, a user
-- can only ever see their own rows, never another user's.
-- ══════════════════════════════════════════════════════════════════

-- ── Tool 1: Unified Infrastructure Diagnostic Suite ──────────────────
create table if not exists diagnostic_runs (
  id           bigint generated always as identity primary key,
  user_id      uuid not null references auth.users(id) on delete cascade,
  run_type     text not null check (run_type in ('bulk_check','blacklist','parse_headers')),
  domain_count int,
  results      jsonb not null,
  created_at   timestamptz not null default now()
);
alter table diagnostic_runs enable row level security;
create policy "own diagnostic runs" on diagnostic_runs
  for select using (auth.uid() = user_id);

-- ── Tool 2: IMAP Pitch Threader ───────────────────────────────────────
-- Raw IMAP passwords are NEVER persisted here — only host/mailbox
-- metadata and the resulting reply tree, per raptor_auth.py's comment
-- about not holding mailbox secrets at rest without proper encryption.
create table if not exists threader_scans (
  id                 bigint generated always as identity primary key,
  user_id            uuid not null references auth.users(id) on delete cascade,
  mailbox            text not null,
  message_count      int not null default 0,
  human_reply_count  int not null default 0,
  tree               jsonb not null,
  created_at         timestamptz not null default now()
);
alter table threader_scans enable row level security;
create policy "own threader scans" on threader_scans
  for select using (auth.uid() = user_id);

-- ── Tool 3: Spintax Compiler & Injection Queue ────────────────────────
create table if not exists outreach_queue (
  id            bigint generated always as identity primary key,
  user_id       uuid not null references auth.users(id) on delete cascade,
  campaign_id   text not null check (campaign_id ~ '^[a-zA-Z0-9_-]+$'),
  variant_text  text not null,
  variant_hash  text not null,
  sent          boolean not null default false,
  created_at    timestamptz not null default now(),
  unique (user_id, variant_hash)
);
create index if not exists idx_outreach_queue_campaign on outreach_queue (user_id, campaign_id);
alter table outreach_queue enable row level security;
create policy "own outreach queue" on outreach_queue
  for select using (auth.uid() = user_id);

-- ── Tool 4: B2B Reverse-IP Resolver (The Deanonymizer) ────────────────
create table if not exists ip_ranges (
  id            bigint generated always as identity primary key,
  user_id       uuid not null references auth.users(id) on delete cascade,
  cidr          cidr not null,
  company_name  text not null,
  created_at    timestamptz not null default now(),
  unique (user_id, cidr)
);
create index if not exists idx_ip_ranges_user on ip_ranges (user_id);
alter table ip_ranges enable row level security;
create policy "own ip ranges" on ip_ranges
  for select using (auth.uid() = user_id);

create table if not exists resolved_visits (
  id            bigint generated always as identity primary key,
  user_id       uuid not null references auth.users(id) on delete cascade,
  ip            inet not null,
  company_name  text,
  source        text not null default 'manual_lookup',
  created_at    timestamptz not null default now()
);
create index if not exists idx_resolved_visits_user on resolved_visits (user_id, created_at desc);
alter table resolved_visits enable row level security;
create policy "own resolved visits" on resolved_visits
  for select using (auth.uid() = user_id);

-- ── Tool 5: Chronos Timezone Optimization Engine ──────────────────────
-- geocode_cache is intentionally NOT user-scoped -- "Austin, Texas" resolves
-- to the same coordinates for everyone, so it's a shared, RLS-open lookup
-- table (no personal data in it) to avoid re-geocoding the same city per user.
create table if not exists geocode_cache (
  query          text primary key,
  lat            double precision not null,
  lng            double precision not null,
  resolved_name  text,
  created_at     timestamptz not null default now()
);
alter table geocode_cache enable row level security;
create policy "geocode cache is public read" on geocode_cache
  for select using (true);

create table if not exists scheduled_sends (
  id               bigint generated always as identity primary key,
  user_id          uuid not null references auth.users(id) on delete cascade,
  place            text not null,
  timezone         text not null,
  local_send_time  timestamptz not null,
  send_after_utc   timestamptz not null,
  created_at       timestamptz not null default now()
);
create index if not exists idx_scheduled_sends_user on scheduled_sends (user_id, send_after_utc);
alter table scheduled_sends enable row level security;
create policy "own scheduled sends" on scheduled_sends
  for select using (auth.uid() = user_id);

-- ── Tool 6: WASM Call Audio VAD ────────────────────────────────────────
create table if not exists call_recordings (
  id                       bigint generated always as identity primary key,
  user_id                  uuid not null references auth.users(id) on delete cascade,
  call_id                  text not null,
  original_duration_sec    numeric not null,
  compressed_duration_sec  numeric not null,
  silence_removed_pct      numeric not null,
  storage_url              text,
  created_at               timestamptz not null default now()
);
create index if not exists idx_call_recordings_user on call_recordings (user_id, created_at desc);
alter table call_recordings enable row level security;
create policy "own call recordings" on call_recordings
  for select using (auth.uid() = user_id);

-- ── Tool 7: K-Means ICP Clustering Engine ─────────────────────────────
create table if not exists icp_clusters (
  id          bigint generated always as identity primary key,
  user_id     uuid not null references auth.users(id) on delete cascade,
  k           int not null,
  fields      jsonb not null,
  row_count   int not null,
  result      jsonb not null,
  created_at  timestamptz not null default now()
);
alter table icp_clusters enable row level security;
create policy "own icp clusters" on icp_clusters
  for select using (auth.uid() = user_id);

-- ── Tool 8: Video Payload Compressor & Metadata Scrubber ──────────────
create table if not exists video_assets (
  id                      bigint generated always as identity primary key,
  user_id                 uuid not null references auth.users(id) on delete cascade,
  video_id                text not null,
  original_size_bytes     bigint not null,
  compressed_size_bytes   bigint not null,
  reduction_pct           numeric not null,
  metadata_scrubbed       boolean not null default false,
  storage_url             text,
  created_at              timestamptz not null default now()
);
create index if not exists idx_video_assets_user on video_assets (user_id, created_at desc);
alter table video_assets enable row level security;
create policy "own video assets" on video_assets
  for select using (auth.uid() = user_id);

-- ── Tool 9: Monte Carlo Pipeline Simulator ────────────────────────────
create table if not exists simulation_runs (
  id              bigint generated always as identity primary key,
  user_id         uuid not null references auth.users(id) on delete cascade,
  deal_count      int not null,
  iterations      int not null,
  p10             numeric not null,
  p50             numeric not null,
  p90             numeric not null,
  deals_snapshot  jsonb not null,
  created_at      timestamptz not null default now()
);
create index if not exists idx_simulation_runs_user on simulation_runs (user_id, created_at desc);
alter table simulation_runs enable row level security;
create policy "own simulation runs" on simulation_runs
  for select using (auth.uid() = user_id);

-- ══════════════════════════════════════════════════════════════════
-- Reminder: none of these policies grant INSERT/UPDATE to the anon/
-- authenticated roles on purpose. All writes go through the FastAPI
-- backend using the service-role key (same as raptor_router.py's
-- deduct_credit and generate-tracker), so RLS never blocks a
-- legitimate write and never needs an insert policy opened up to
-- the browser.
-- ══════════════════════════════════════════════════════════════════