-- WARNING: This schema is for context only and is not meant to be run.
-- Table order and constraints may not be valid for execution.

CREATE TABLE public.users (
  id uuid NOT NULL,
  email text,
  monthly_credits integer DEFAULT 100,
  CONSTRAINT users_pkey PRIMARY KEY (id),
  CONSTRAINT users_id_fkey FOREIGN KEY (id) REFERENCES auth.users(id)
);
CREATE TABLE public.raptor_users (
  user_id uuid NOT NULL,
  email text,
  credits integer DEFAULT 50,
  total_credits integer DEFAULT 50,
  plan text DEFAULT 'Free'::text,
  CONSTRAINT raptor_users_pkey PRIMARY KEY (user_id),
  CONSTRAINT raptor_users_user_id_fkey FOREIGN KEY (user_id) REFERENCES auth.users(id)
);
CREATE TABLE public.raptor_opens (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  campaign_id text NOT NULL,
  opened_at timestamp with time zone NOT NULL DEFAULT timezone('utc'::text, now()),
  CONSTRAINT raptor_opens_pkey PRIMARY KEY (id),
  CONSTRAINT raptor_opens_campaign_id_fkey FOREIGN KEY (campaign_id) REFERENCES public.raptor_campaigns(campaign_id)
);
CREATE TABLE public.raptor_campaigns (
  campaign_id text NOT NULL,
  user_id uuid NOT NULL,
  created_at timestamp with time zone DEFAULT now(),
  display_name text,
  CONSTRAINT raptor_campaigns_pkey PRIMARY KEY (campaign_id),
  CONSTRAINT raptor_campaigns_user_id_fkey FOREIGN KEY (user_id) REFERENCES auth.users(id)
);
CREATE TABLE public.contacts (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  owner_id uuid NOT NULL DEFAULT auth.uid(),
  first_name text,
  last_name text,
  email text,
  status text DEFAULT 'new'::text,
  last_interaction_at timestamp with time zone,
  created_at timestamp with time zone DEFAULT now(),
  updated_at timestamp with time zone DEFAULT now(),
  company_id uuid,
  name text NOT NULL,
  phone text,
  CONSTRAINT contacts_pkey PRIMARY KEY (id),
  CONSTRAINT contacts_owner_id_fkey FOREIGN KEY (owner_id) REFERENCES auth.users(id),
  CONSTRAINT contacts_company_id_fkey FOREIGN KEY (company_id) REFERENCES public.companies(id)
);
CREATE TABLE public.deals (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  owner_id uuid NOT NULL DEFAULT auth.uid(),
  contact_id uuid,
  title text NOT NULL,
  value numeric DEFAULT 0,
  stage text DEFAULT 'lead'::text,
  created_at timestamp with time zone DEFAULT now(),
  updated_at timestamp with time zone DEFAULT now(),
  company_id uuid,
  campaign_id uuid,
  CONSTRAINT deals_pkey PRIMARY KEY (id),
  CONSTRAINT deals_owner_id_fkey FOREIGN KEY (owner_id) REFERENCES auth.users(id),
  CONSTRAINT deals_contact_id_fkey FOREIGN KEY (contact_id) REFERENCES public.contacts(id),
  CONSTRAINT deals_company_id_fkey FOREIGN KEY (company_id) REFERENCES public.companies(id),
  CONSTRAINT deals_campaign_id_fkey FOREIGN KEY (campaign_id) REFERENCES public.campaigns(id)
);
CREATE TABLE public.automations (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  owner_id uuid NOT NULL DEFAULT auth.uid(),
  name text NOT NULL,
  trigger_type text NOT NULL DEFAULT 'contact_no_reply'::text CHECK (trigger_type = ANY (ARRAY['contact_no_reply'::text, 'deal_stalled'::text, 'deal_won'::text])),
  trigger_days integer DEFAULT 3,
  action_type text NOT NULL DEFAULT 'log_note'::text CHECK (action_type = ANY (ARRAY['log_note'::text, 'create_reminder'::text, 'webhook'::text])),
  action_message text,
  action_webhook_url text,
  is_active boolean DEFAULT true,
  last_run_at timestamp with time zone,
  created_at timestamp with time zone DEFAULT now(),
  CONSTRAINT automations_pkey PRIMARY KEY (id),
  CONSTRAINT automations_owner_id_fkey FOREIGN KEY (owner_id) REFERENCES auth.users(id)
);
CREATE TABLE public.reminders (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  owner_id uuid NOT NULL DEFAULT auth.uid(),
  automation_id uuid,
  contact_id uuid,
  deal_id uuid,
  message text NOT NULL,
  is_done boolean DEFAULT false,
  created_at timestamp with time zone DEFAULT now(),
  CONSTRAINT reminders_pkey PRIMARY KEY (id),
  CONSTRAINT reminders_owner_id_fkey FOREIGN KEY (owner_id) REFERENCES auth.users(id),
  CONSTRAINT reminders_automation_id_fkey FOREIGN KEY (automation_id) REFERENCES public.automations(id),
  CONSTRAINT reminders_contact_id_fkey FOREIGN KEY (contact_id) REFERENCES public.contacts(id),
  CONSTRAINT reminders_deal_id_fkey FOREIGN KEY (deal_id) REFERENCES public.deals(id)
);
CREATE TABLE public.automation_runs (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  owner_id uuid NOT NULL,
  automation_id uuid,
  contact_id uuid,
  deal_id uuid,
  action_taken text,
  ran_at timestamp with time zone DEFAULT now(),
  CONSTRAINT automation_runs_pkey PRIMARY KEY (id),
  CONSTRAINT automation_runs_owner_id_fkey FOREIGN KEY (owner_id) REFERENCES auth.users(id),
  CONSTRAINT automation_runs_automation_id_fkey FOREIGN KEY (automation_id) REFERENCES public.automations(id),
  CONSTRAINT automation_runs_contact_id_fkey FOREIGN KEY (contact_id) REFERENCES public.contacts(id),
  CONSTRAINT automation_runs_deal_id_fkey FOREIGN KEY (deal_id) REFERENCES public.deals(id)
);
CREATE TABLE public.diagnostic_runs (
  id bigint GENERATED ALWAYS AS IDENTITY NOT NULL,
  user_id uuid NOT NULL,
  run_type text NOT NULL CHECK (run_type = ANY (ARRAY['bulk_check'::text, 'blacklist'::text, 'parse_headers'::text])),
  domain_count integer,
  results jsonb NOT NULL,
  created_at timestamp with time zone NOT NULL DEFAULT now(),
  CONSTRAINT diagnostic_runs_pkey PRIMARY KEY (id),
  CONSTRAINT diagnostic_runs_user_id_fkey FOREIGN KEY (user_id) REFERENCES auth.users(id)
);
CREATE TABLE public.threader_scans (
  id bigint GENERATED ALWAYS AS IDENTITY NOT NULL,
  user_id uuid NOT NULL,
  mailbox text NOT NULL,
  message_count integer NOT NULL DEFAULT 0,
  human_reply_count integer NOT NULL DEFAULT 0,
  tree jsonb NOT NULL,
  created_at timestamp with time zone NOT NULL DEFAULT now(),
  CONSTRAINT threader_scans_pkey PRIMARY KEY (id),
  CONSTRAINT threader_scans_user_id_fkey FOREIGN KEY (user_id) REFERENCES auth.users(id)
);
CREATE TABLE public.outreach_queue (
  id bigint GENERATED ALWAYS AS IDENTITY NOT NULL,
  user_id uuid NOT NULL,
  campaign_id text NOT NULL CHECK (campaign_id ~ '^[a-zA-Z0-9_-]+$'::text),
  variant_text text NOT NULL,
  variant_hash text NOT NULL,
  sent boolean NOT NULL DEFAULT false,
  created_at timestamp with time zone NOT NULL DEFAULT now(),
  CONSTRAINT outreach_queue_pkey PRIMARY KEY (id),
  CONSTRAINT outreach_queue_user_id_fkey FOREIGN KEY (user_id) REFERENCES auth.users(id)
);
CREATE TABLE public.ip_ranges (
  id bigint GENERATED ALWAYS AS IDENTITY NOT NULL,
  user_id uuid NOT NULL,
  cidr cidr NOT NULL,
  company_name text NOT NULL,
  created_at timestamp with time zone NOT NULL DEFAULT now(),
  CONSTRAINT ip_ranges_pkey PRIMARY KEY (id),
  CONSTRAINT ip_ranges_user_id_fkey FOREIGN KEY (user_id) REFERENCES auth.users(id)
);
CREATE TABLE public.resolved_visits (
  id bigint GENERATED ALWAYS AS IDENTITY NOT NULL,
  user_id uuid NOT NULL,
  ip inet NOT NULL,
  company_name text,
  source text NOT NULL DEFAULT 'manual_lookup'::text,
  created_at timestamp with time zone NOT NULL DEFAULT now(),
  CONSTRAINT resolved_visits_pkey PRIMARY KEY (id),
  CONSTRAINT resolved_visits_user_id_fkey FOREIGN KEY (user_id) REFERENCES auth.users(id)
);
CREATE TABLE public.geocode_cache (
  query text NOT NULL,
  lat double precision NOT NULL,
  lng double precision NOT NULL,
  resolved_name text,
  created_at timestamp with time zone NOT NULL DEFAULT now(),
  CONSTRAINT geocode_cache_pkey PRIMARY KEY (query)
);
CREATE TABLE public.scheduled_sends (
  id bigint GENERATED ALWAYS AS IDENTITY NOT NULL,
  user_id uuid NOT NULL,
  place text NOT NULL,
  timezone text NOT NULL,
  local_send_time timestamp with time zone NOT NULL,
  send_after_utc timestamp with time zone NOT NULL,
  created_at timestamp with time zone NOT NULL DEFAULT now(),
  CONSTRAINT scheduled_sends_pkey PRIMARY KEY (id),
  CONSTRAINT scheduled_sends_user_id_fkey FOREIGN KEY (user_id) REFERENCES auth.users(id)
);
CREATE TABLE public.call_recordings (
  id bigint GENERATED ALWAYS AS IDENTITY NOT NULL,
  user_id uuid NOT NULL,
  call_id text NOT NULL,
  original_duration_sec numeric NOT NULL,
  compressed_duration_sec numeric NOT NULL,
  silence_removed_pct numeric NOT NULL,
  storage_url text,
  created_at timestamp with time zone NOT NULL DEFAULT now(),
  CONSTRAINT call_recordings_pkey PRIMARY KEY (id),
  CONSTRAINT call_recordings_user_id_fkey FOREIGN KEY (user_id) REFERENCES auth.users(id)
);
CREATE TABLE public.icp_clusters (
  id bigint GENERATED ALWAYS AS IDENTITY NOT NULL,
  user_id uuid NOT NULL,
  k integer NOT NULL,
  fields jsonb NOT NULL,
  row_count integer NOT NULL,
  result jsonb NOT NULL,
  created_at timestamp with time zone NOT NULL DEFAULT now(),
  CONSTRAINT icp_clusters_pkey PRIMARY KEY (id),
  CONSTRAINT icp_clusters_user_id_fkey FOREIGN KEY (user_id) REFERENCES auth.users(id)
);
CREATE TABLE public.video_assets (
  id bigint GENERATED ALWAYS AS IDENTITY NOT NULL,
  user_id uuid NOT NULL,
  video_id text NOT NULL,
  original_size_bytes bigint NOT NULL,
  compressed_size_bytes bigint NOT NULL,
  reduction_pct numeric NOT NULL,
  metadata_scrubbed boolean NOT NULL DEFAULT false,
  storage_url text,
  created_at timestamp with time zone NOT NULL DEFAULT now(),
  CONSTRAINT video_assets_pkey PRIMARY KEY (id),
  CONSTRAINT video_assets_user_id_fkey FOREIGN KEY (user_id) REFERENCES auth.users(id)
);
CREATE TABLE public.simulation_runs (
  id bigint GENERATED ALWAYS AS IDENTITY NOT NULL,
  user_id uuid NOT NULL,
  deal_count integer NOT NULL,
  iterations integer NOT NULL,
  p10 numeric NOT NULL,
  p50 numeric NOT NULL,
  p90 numeric NOT NULL,
  deals_snapshot jsonb NOT NULL,
  created_at timestamp with time zone NOT NULL DEFAULT now(),
  CONSTRAINT simulation_runs_pkey PRIMARY KEY (id),
  CONSTRAINT simulation_runs_user_id_fkey FOREIGN KEY (user_id) REFERENCES auth.users(id)
);
CREATE TABLE public.companies (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  owner_id uuid NOT NULL DEFAULT auth.uid(),
  name text NOT NULL,
  created_at timestamp with time zone DEFAULT now(),
  CONSTRAINT companies_pkey PRIMARY KEY (id),
  CONSTRAINT companies_owner_id_fkey FOREIGN KEY (owner_id) REFERENCES auth.users(id)
);
CREATE TABLE public.campaigns (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  owner_id uuid NOT NULL DEFAULT auth.uid(),
  name text NOT NULL,
  product_name text,
  product_price numeric DEFAULT 0,
  target_count integer DEFAULT 0,
  start_date date,
  end_date date,
  created_at timestamp with time zone DEFAULT now(),
  CONSTRAINT campaigns_pkey PRIMARY KEY (id),
  CONSTRAINT campaigns_owner_id_fkey FOREIGN KEY (owner_id) REFERENCES auth.users(id)
);
CREATE TABLE public.raptor_topups (
  payment_id text NOT NULL,
  user_id uuid NOT NULL,
  credits integer NOT NULL,
  created_at timestamp with time zone NOT NULL DEFAULT now(),
  CONSTRAINT raptor_topups_pkey PRIMARY KEY (payment_id),
  CONSTRAINT raptor_topups_user_id_fkey FOREIGN KEY (user_id) REFERENCES auth.users(id)
);
CREATE TABLE public.whatsapp_accounts (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  owner_id uuid NOT NULL,
  label text NOT NULL,
  phone_number_id text NOT NULL,
  waba_id text NOT NULL,
  encrypted_access_token text NOT NULL,
  daily_cap integer NOT NULL DEFAULT 20,
  warmup_started_at timestamp with time zone NOT NULL DEFAULT now(),
  warmup_target integer NOT NULL DEFAULT 100,
  business_hours_start smallint NOT NULL DEFAULT 9,
  business_hours_end smallint NOT NULL DEFAULT 18,
  timezone text NOT NULL DEFAULT 'Asia/Kolkata'::text,
  created_at timestamp with time zone NOT NULL DEFAULT now(),
  CONSTRAINT whatsapp_accounts_pkey PRIMARY KEY (id),
  CONSTRAINT whatsapp_accounts_owner_id_fkey FOREIGN KEY (owner_id) REFERENCES auth.users(id)
);
CREATE TABLE public.whatsapp_contacts (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  account_id uuid NOT NULL,
  phone text NOT NULL,
  first_name text,
  last_name text,
  tags ARRAY NOT NULL DEFAULT '{}'::text[],
  created_at timestamp with time zone NOT NULL DEFAULT now(),
  CONSTRAINT whatsapp_contacts_pkey PRIMARY KEY (id),
  CONSTRAINT whatsapp_contacts_account_id_fkey FOREIGN KEY (account_id) REFERENCES public.whatsapp_accounts(id)
);
CREATE TABLE public.whatsapp_suppressions (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  account_id uuid NOT NULL,
  phone text NOT NULL,
  reason text NOT NULL,
  created_at timestamp with time zone NOT NULL DEFAULT now(),
  CONSTRAINT whatsapp_suppressions_pkey PRIMARY KEY (id),
  CONSTRAINT whatsapp_suppressions_account_id_fkey FOREIGN KEY (account_id) REFERENCES public.whatsapp_accounts(id)
);
CREATE TABLE public.whatsapp_broadcasts (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  account_id uuid NOT NULL,
  name text NOT NULL,
  template_name text NOT NULL,
  template_language text NOT NULL DEFAULT 'en_US'::text,
  template_params_use_name boolean NOT NULL DEFAULT false,
  audience_tag text,
  status text NOT NULL DEFAULT 'draft'::text,
  locked_at timestamp with time zone,
  created_at timestamp with time zone NOT NULL DEFAULT now(),
  CONSTRAINT whatsapp_broadcasts_pkey PRIMARY KEY (id),
  CONSTRAINT whatsapp_broadcasts_account_id_fkey FOREIGN KEY (account_id) REFERENCES public.whatsapp_accounts(id)
);
CREATE TABLE public.whatsapp_broadcast_recipients (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  broadcast_id uuid NOT NULL,
  contact_id uuid NOT NULL,
  status text NOT NULL DEFAULT 'pending'::text,
  provider_message_id text,
  sent_at timestamp with time zone,
  CONSTRAINT whatsapp_broadcast_recipients_pkey PRIMARY KEY (id),
  CONSTRAINT whatsapp_broadcast_recipients_broadcast_id_fkey FOREIGN KEY (broadcast_id) REFERENCES public.whatsapp_broadcasts(id),
  CONSTRAINT whatsapp_broadcast_recipients_contact_id_fkey FOREIGN KEY (contact_id) REFERENCES public.whatsapp_contacts(id)
);
CREATE TABLE public.whatsapp_sequences (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  account_id uuid NOT NULL,
  name text NOT NULL,
  status text NOT NULL DEFAULT 'active'::text,
  created_at timestamp with time zone NOT NULL DEFAULT now(),
  CONSTRAINT whatsapp_sequences_pkey PRIMARY KEY (id),
  CONSTRAINT whatsapp_sequences_account_id_fkey FOREIGN KEY (account_id) REFERENCES public.whatsapp_accounts(id)
);
CREATE TABLE public.whatsapp_sequence_steps (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  sequence_id uuid NOT NULL,
  step_order integer NOT NULL,
  delay_hours integer NOT NULL DEFAULT 0,
  template_name text NOT NULL,
  template_language text NOT NULL DEFAULT 'en_US'::text,
  created_at timestamp with time zone NOT NULL DEFAULT now(),
  CONSTRAINT whatsapp_sequence_steps_pkey PRIMARY KEY (id),
  CONSTRAINT whatsapp_sequence_steps_sequence_id_fkey FOREIGN KEY (sequence_id) REFERENCES public.whatsapp_sequences(id)
);
CREATE TABLE public.whatsapp_sequence_enrollments (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  sequence_id uuid NOT NULL,
  contact_id uuid NOT NULL,
  current_step integer NOT NULL DEFAULT 0,
  next_send_at timestamp with time zone NOT NULL DEFAULT now(),
  status text NOT NULL DEFAULT 'active'::text,
  created_at timestamp with time zone NOT NULL DEFAULT now(),
  CONSTRAINT whatsapp_sequence_enrollments_pkey PRIMARY KEY (id),
  CONSTRAINT whatsapp_sequence_enrollments_sequence_id_fkey FOREIGN KEY (sequence_id) REFERENCES public.whatsapp_sequences(id),
  CONSTRAINT whatsapp_sequence_enrollments_contact_id_fkey FOREIGN KEY (contact_id) REFERENCES public.whatsapp_contacts(id)
);
CREATE TABLE public.whatsapp_triggers (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  account_id uuid NOT NULL,
  keyword text NOT NULL,
  match_type text NOT NULL DEFAULT 'contains'::text,
  reply_text text NOT NULL,
  is_active boolean NOT NULL DEFAULT true,
  created_at timestamp with time zone NOT NULL DEFAULT now(),
  CONSTRAINT whatsapp_triggers_pkey PRIMARY KEY (id),
  CONSTRAINT whatsapp_triggers_account_id_fkey FOREIGN KEY (account_id) REFERENCES public.whatsapp_accounts(id)
);
CREATE TABLE public.whatsapp_events (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  account_id uuid NOT NULL,
  contact_phone text NOT NULL,
  direction text NOT NULL,
  event_type text NOT NULL,
  body_text text,
  provider_message_id text,
  created_at timestamp with time zone NOT NULL DEFAULT now(),
  CONSTRAINT whatsapp_events_pkey PRIMARY KEY (id),
  CONSTRAINT whatsapp_events_account_id_fkey FOREIGN KEY (account_id) REFERENCES public.whatsapp_accounts(id)
);
CREATE TABLE public.email_accounts (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  owner_id uuid NOT NULL,
  label text NOT NULL,
  provider text NOT NULL DEFAULT 'resend'::text,
  from_email text NOT NULL,
  from_name text NOT NULL,
  encrypted_api_key text NOT NULL,
  smtp_config jsonb,
  daily_cap integer NOT NULL DEFAULT 20,
  warmup_started_at timestamp with time zone NOT NULL DEFAULT now(),
  warmup_target integer NOT NULL DEFAULT 100,
  business_hours_start smallint NOT NULL DEFAULT 9,
  business_hours_end smallint NOT NULL DEFAULT 18,
  timezone text NOT NULL DEFAULT 'Asia/Kolkata'::text,
  created_at timestamp with time zone NOT NULL DEFAULT now(),
  CONSTRAINT email_accounts_pkey PRIMARY KEY (id),
  CONSTRAINT email_accounts_owner_id_fkey FOREIGN KEY (owner_id) REFERENCES auth.users(id)
);
CREATE TABLE public.email_contacts (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  account_id uuid NOT NULL,
  email text NOT NULL,
  first_name text,
  last_name text,
  company text,
  tags ARRAY NOT NULL DEFAULT '{}'::text[],
  created_at timestamp with time zone NOT NULL DEFAULT now(),
  CONSTRAINT email_contacts_pkey PRIMARY KEY (id),
  CONSTRAINT email_contacts_account_id_fkey FOREIGN KEY (account_id) REFERENCES public.email_accounts(id)
);
CREATE TABLE public.email_suppressions (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  account_id uuid NOT NULL,
  email text NOT NULL,
  reason text NOT NULL,
  created_at timestamp with time zone NOT NULL DEFAULT now(),
  CONSTRAINT email_suppressions_pkey PRIMARY KEY (id),
  CONSTRAINT email_suppressions_account_id_fkey FOREIGN KEY (account_id) REFERENCES public.email_accounts(id)
);
CREATE TABLE public.email_campaigns (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  account_id uuid NOT NULL,
  name text NOT NULL,
  subject text NOT NULL,
  body_html text NOT NULL,
  audience_tag text,
  status text NOT NULL DEFAULT 'draft'::text,
  created_at timestamp with time zone NOT NULL DEFAULT now(),
  CONSTRAINT email_campaigns_pkey PRIMARY KEY (id),
  CONSTRAINT email_campaigns_account_id_fkey FOREIGN KEY (account_id) REFERENCES public.email_accounts(id)
);
CREATE TABLE public.email_campaign_recipients (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  campaign_id uuid NOT NULL,
  contact_id uuid NOT NULL,
  status text NOT NULL DEFAULT 'pending'::text,
  provider_message_id text,
  sent_at timestamp with time zone,
  CONSTRAINT email_campaign_recipients_pkey PRIMARY KEY (id),
  CONSTRAINT email_campaign_recipients_campaign_id_fkey FOREIGN KEY (campaign_id) REFERENCES public.email_campaigns(id),
  CONSTRAINT email_campaign_recipients_contact_id_fkey FOREIGN KEY (contact_id) REFERENCES public.email_contacts(id)
);
CREATE TABLE public.email_events (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  account_id uuid NOT NULL,
  contact_email text NOT NULL,
  event_type text NOT NULL,
  body_text text,
  provider_message_id text,
  created_at timestamp with time zone NOT NULL DEFAULT now(),
  CONSTRAINT email_events_pkey PRIMARY KEY (id),
  CONSTRAINT email_events_account_id_fkey FOREIGN KEY (account_id) REFERENCES public.email_accounts(id)
);
CREATE TABLE public.ai_content_keys (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  owner_id uuid NOT NULL,
  provider text NOT NULL,
  encrypted_api_key text NOT NULL,
  capabilities jsonb NOT NULL DEFAULT '{"text": false, "image": false, "video": false}'::jsonb,
  created_at timestamp with time zone NOT NULL DEFAULT now(),
  CONSTRAINT ai_content_keys_pkey PRIMARY KEY (id),
  CONSTRAINT ai_content_keys_owner_id_fkey FOREIGN KEY (owner_id) REFERENCES auth.users(id)
);
CREATE TABLE public.ai_pipeline_runs (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  owner_id uuid NOT NULL,
  content_type text NOT NULL,
  status text NOT NULL DEFAULT 'running'::text,
  result text,
  created_at timestamp with time zone NOT NULL DEFAULT now(),
  CONSTRAINT ai_pipeline_runs_pkey PRIMARY KEY (id),
  CONSTRAINT ai_pipeline_runs_owner_id_fkey FOREIGN KEY (owner_id) REFERENCES auth.users(id)
);
CREATE TABLE public.ai_pipeline_steps (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  run_id uuid NOT NULL,
  step_index integer NOT NULL,
  provider text NOT NULL,
  template_id text NOT NULL,
  modality text NOT NULL,
  variables jsonb NOT NULL DEFAULT '{}'::jsonb,
  output text,
  status text NOT NULL DEFAULT 'pending'::text,
  provider_job_id text,
  CONSTRAINT ai_pipeline_steps_pkey PRIMARY KEY (id),
  CONSTRAINT ai_pipeline_steps_run_id_fkey FOREIGN KEY (run_id) REFERENCES public.ai_pipeline_runs(id)
);
CREATE TABLE public.notifications (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  owner_id uuid NOT NULL,
  type text NOT NULL DEFAULT 'info'::text CHECK (type = ANY (ARRAY['info'::text, 'success'::text, 'warning'::text, 'alert'::text])),
  display_mode text NOT NULL DEFAULT 'inbox'::text CHECK (display_mode = ANY (ARRAY['inbox'::text, 'banner'::text, 'modal'::text])),
  title text NOT NULL,
  body text,
  action_label text,
  action_url text,
  is_read boolean NOT NULL DEFAULT false,
  read_at timestamp with time zone,
  created_at timestamp with time zone NOT NULL DEFAULT now(),
  CONSTRAINT notifications_pkey PRIMARY KEY (id),
  CONSTRAINT notifications_owner_id_fkey FOREIGN KEY (owner_id) REFERENCES auth.users(id)
);