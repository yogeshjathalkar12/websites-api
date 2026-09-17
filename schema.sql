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
  lead_score integer NOT NULL DEFAULT 0,
  assigned_to text,
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
  closed_at timestamp with time zone,
  CONSTRAINT deals_pkey PRIMARY KEY (id),
  CONSTRAINT deals_owner_id_fkey FOREIGN KEY (owner_id) REFERENCES auth.users(id),
  CONSTRAINT deals_contact_id_fkey FOREIGN KEY (contact_id) REFERENCES public.contacts(id),
  CONSTRAINT deals_company_id_fkey FOREIGN KEY (company_id) REFERENCES public.companies(id),
  CONSTRAINT deals_campaign_id_fkey FOREIGN KEY (campaign_id) REFERENCES public.campaigns(id)
);
CREATE TABLE public.automations (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  owner_id uuid NOT NULL DEFAULT auth.uid(),
  name text,
  trigger_type text NOT NULL DEFAULT 'contact_no_reply'::text CHECK (trigger_type = ANY (ARRAY['contact_no_reply'::text, 'deal_stalled'::text, 'deal_won'::text])),
  trigger_days integer DEFAULT 3,
  action_type text NOT NULL DEFAULT 'log_note'::text CHECK (action_type = ANY (ARRAY['log_note'::text, 'create_reminder'::text, 'webhook'::text])),
  action_message text,
  action_webhook_url text,
  enabled boolean DEFAULT true,
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
  catalog_id text,
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
  crm_contact_id uuid,
  CONSTRAINT whatsapp_contacts_pkey PRIMARY KEY (id),
  CONSTRAINT whatsapp_contacts_crm_contact_id_fkey FOREIGN KEY (crm_contact_id) REFERENCES public.contacts(id),
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
  reply_kind text NOT NULL DEFAULT 'text'::text CHECK (reply_kind = ANY (ARRAY['text'::text, 'buttons'::text, 'list'::text, 'catalog'::text, 'product'::text, 'product_list'::text])),
  reply_payload jsonb,
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
  conversation_id uuid,
  CONSTRAINT whatsapp_events_pkey PRIMARY KEY (id),
  CONSTRAINT whatsapp_events_conversation_id_fkey FOREIGN KEY (conversation_id) REFERENCES public.whatsapp_conversations(id),
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
  inbound_webhook_secret text,
  encrypted_shopify_webhook_secret text,
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
  segment_id uuid,
  ab_test_enabled boolean NOT NULL DEFAULT false,
  ab_test_percentage integer NOT NULL DEFAULT 100,
  ab_winner_metric text NOT NULL DEFAULT 'click_rate'::text CHECK (ab_winner_metric = ANY (ARRAY['open_rate'::text, 'click_rate'::text])),
  ab_test_duration_hours integer NOT NULL DEFAULT 4,
  ab_winner_variant_id uuid,
  ab_test_started_at timestamp with time zone,
  CONSTRAINT email_campaigns_pkey PRIMARY KEY (id),
  CONSTRAINT email_campaigns_ab_winner_variant_id_fkey FOREIGN KEY (ab_winner_variant_id) REFERENCES public.email_campaign_variants(id),
  CONSTRAINT email_campaigns_account_id_fkey FOREIGN KEY (account_id) REFERENCES public.email_accounts(id),
  CONSTRAINT email_campaigns_segment_id_fkey FOREIGN KEY (segment_id) REFERENCES public.email_segments(id)
);
CREATE TABLE public.email_campaign_recipients (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  campaign_id uuid NOT NULL,
  contact_id uuid NOT NULL,
  status text NOT NULL DEFAULT 'pending'::text,
  provider_message_id text,
  sent_at timestamp with time zone,
  opened_at timestamp with time zone,
  clicked_at timestamp with time zone,
  variant_id uuid,
  CONSTRAINT email_campaign_recipients_pkey PRIMARY KEY (id),
  CONSTRAINT email_campaign_recipients_variant_id_fkey FOREIGN KEY (variant_id) REFERENCES public.email_campaign_variants(id),
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
CREATE TABLE public.interactions (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  owner_id uuid NOT NULL DEFAULT auth.uid(),
  contact_id uuid,
  type text NOT NULL DEFAULT 'note'::text CHECK (type = ANY (ARRAY['note'::text, 'email'::text, 'call'::text, 'meeting'::text, 'whatsapp'::text])),
  content text NOT NULL,
  created_at timestamp with time zone NOT NULL DEFAULT now(),
  direction text CHECK (direction = ANY (ARRAY['inbound'::text, 'outbound'::text])),
  CONSTRAINT interactions_pkey PRIMARY KEY (id),
  CONSTRAINT interactions_owner_id_fkey FOREIGN KEY (owner_id) REFERENCES auth.users(id),
  CONSTRAINT interactions_contact_id_fkey FOREIGN KEY (contact_id) REFERENCES public.contacts(id)
);
CREATE TABLE public.whatsapp_conversations (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  owner_id uuid NOT NULL,
  account_id uuid NOT NULL,
  contact_phone text NOT NULL,
  crm_contact_id uuid,
  status text NOT NULL DEFAULT 'bot'::text CHECK (status = ANY (ARRAY['bot'::text, 'waiting'::text, 'human'::text, 'resolved'::text])),
  assigned_agent_id uuid,
  last_message_at timestamp with time zone NOT NULL DEFAULT now(),
  last_message_preview text,
  unread_count integer NOT NULL DEFAULT 0,
  created_at timestamp with time zone NOT NULL DEFAULT now(),
  CONSTRAINT whatsapp_conversations_pkey PRIMARY KEY (id),
  CONSTRAINT whatsapp_conversations_owner_id_fkey FOREIGN KEY (owner_id) REFERENCES auth.users(id),
  CONSTRAINT whatsapp_conversations_account_id_fkey FOREIGN KEY (account_id) REFERENCES public.whatsapp_accounts(id),
  CONSTRAINT whatsapp_conversations_crm_contact_id_fkey FOREIGN KEY (crm_contact_id) REFERENCES public.contacts(id),
  CONSTRAINT whatsapp_conversations_assigned_agent_id_fkey FOREIGN KEY (assigned_agent_id) REFERENCES auth.users(id)
);
CREATE TABLE public.whatsapp_flows (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  account_id uuid NOT NULL,
  name text NOT NULL,
  entry_keyword text NOT NULL,
  match_type text NOT NULL DEFAULT 'contains'::text CHECK (match_type = ANY (ARRAY['contains'::text, 'exact'::text])),
  definition jsonb NOT NULL DEFAULT '{"edges": [], "nodes": []}'::jsonb,
  is_active boolean NOT NULL DEFAULT true,
  created_at timestamp with time zone NOT NULL DEFAULT now(),
  CONSTRAINT whatsapp_flows_pkey PRIMARY KEY (id),
  CONSTRAINT whatsapp_flows_account_id_fkey FOREIGN KEY (account_id) REFERENCES public.whatsapp_accounts(id)
);
CREATE TABLE public.whatsapp_flow_sessions (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  account_id uuid NOT NULL,
  contact_phone text NOT NULL,
  flow_id uuid NOT NULL,
  current_node_id text NOT NULL,
  context jsonb NOT NULL DEFAULT '{}'::jsonb,
  status text NOT NULL DEFAULT 'active'::text CHECK (status = ANY (ARRAY['active'::text, 'completed'::text, 'handed_off'::text])),
  updated_at timestamp with time zone NOT NULL DEFAULT now(),
  created_at timestamp with time zone NOT NULL DEFAULT now(),
  CONSTRAINT whatsapp_flow_sessions_pkey PRIMARY KEY (id),
  CONSTRAINT whatsapp_flow_sessions_account_id_fkey FOREIGN KEY (account_id) REFERENCES public.whatsapp_accounts(id),
  CONSTRAINT whatsapp_flow_sessions_flow_id_fkey FOREIGN KEY (flow_id) REFERENCES public.whatsapp_flows(id)
);
CREATE TABLE public.whatsapp_ai_settings (
  account_id uuid NOT NULL,
  system_prompt text NOT NULL DEFAULT 'You are a helpful assistant answering questions on behalf of this business over WhatsApp. Keep replies short — 1-3 sentences.'::text,
  model text NOT NULL DEFAULT 'claude-sonnet-4-6'::text,
  is_enabled boolean NOT NULL DEFAULT true,
  updated_at timestamp with time zone NOT NULL DEFAULT now(),
  CONSTRAINT whatsapp_ai_settings_pkey PRIMARY KEY (account_id),
  CONSTRAINT whatsapp_ai_settings_account_id_fkey FOREIGN KEY (account_id) REFERENCES public.whatsapp_accounts(id)
);
CREATE TABLE public.email_triggers (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  account_id uuid NOT NULL,
  name text NOT NULL,
  event_key text NOT NULL,
  subject text,
  body_html text,
  delay_minutes integer NOT NULL DEFAULT 0,
  is_transactional boolean NOT NULL DEFAULT false,
  is_active boolean NOT NULL DEFAULT true,
  created_at timestamp with time zone NOT NULL DEFAULT now(),
  action_type text NOT NULL DEFAULT 'send_email'::text CHECK (action_type = ANY (ARRAY['send_email'::text, 'enroll_sequence'::text])),
  target_sequence_id uuid,
  CONSTRAINT email_triggers_pkey PRIMARY KEY (id),
  CONSTRAINT email_triggers_target_sequence_id_fkey FOREIGN KEY (target_sequence_id) REFERENCES public.email_sequences(id),
  CONSTRAINT email_triggers_account_id_fkey FOREIGN KEY (account_id) REFERENCES public.email_accounts(id)
);
CREATE TABLE public.email_trigger_events (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  trigger_id uuid NOT NULL,
  contact_email text NOT NULL,
  external_event_id text,
  payload jsonb NOT NULL DEFAULT '{}'::jsonb,
  scheduled_for timestamp with time zone NOT NULL,
  status text NOT NULL DEFAULT 'pending'::text,
  sent_at timestamp with time zone,
  created_at timestamp with time zone NOT NULL DEFAULT now(),
  account_id uuid,
  opened_at timestamp with time zone,
  clicked_at timestamp with time zone,
  CONSTRAINT email_trigger_events_pkey PRIMARY KEY (id),
  CONSTRAINT email_trigger_events_account_id_fkey FOREIGN KEY (account_id) REFERENCES public.email_accounts(id),
  CONSTRAINT email_trigger_events_trigger_id_fkey FOREIGN KEY (trigger_id) REFERENCES public.email_triggers(id)
);
CREATE TABLE public.campaign_followups (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  source_campaign_id uuid NOT NULL,
  name text NOT NULL,
  condition text NOT NULL CHECK (condition = ANY (ARRAY['opened'::text, 'not_opened'::text, 'clicked'::text, 'not_clicked'::text])),
  wait_hours integer NOT NULL DEFAULT 24,
  subject text NOT NULL,
  body_html text NOT NULL,
  is_transactional boolean NOT NULL DEFAULT false,
  is_active boolean NOT NULL DEFAULT true,
  created_at timestamp with time zone NOT NULL DEFAULT now(),
  CONSTRAINT campaign_followups_pkey PRIMARY KEY (id),
  CONSTRAINT campaign_followups_source_campaign_id_fkey FOREIGN KEY (source_campaign_id) REFERENCES public.email_campaigns(id)
);
CREATE TABLE public.campaign_followup_sends (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  followup_id uuid NOT NULL,
  recipient_id uuid NOT NULL,
  condition_met boolean NOT NULL,
  status text NOT NULL,
  sent_at timestamp with time zone,
  created_at timestamp with time zone NOT NULL DEFAULT now(),
  account_id uuid,
  contact_email text,
  opened_at timestamp with time zone,
  clicked_at timestamp with time zone,
  CONSTRAINT campaign_followup_sends_pkey PRIMARY KEY (id),
  CONSTRAINT campaign_followup_sends_account_id_fkey FOREIGN KEY (account_id) REFERENCES public.email_accounts(id),
  CONSTRAINT campaign_followup_sends_followup_id_fkey FOREIGN KEY (followup_id) REFERENCES public.campaign_followups(id),
  CONSTRAINT campaign_followup_sends_recipient_id_fkey FOREIGN KEY (recipient_id) REFERENCES public.email_campaign_recipients(id)
);
CREATE TABLE public.email_sequences (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  account_id uuid NOT NULL,
  name text NOT NULL,
  status text NOT NULL DEFAULT 'active'::text CHECK (status = ANY (ARRAY['active'::text, 'paused'::text])),
  created_at timestamp with time zone NOT NULL DEFAULT now(),
  CONSTRAINT email_sequences_pkey PRIMARY KEY (id),
  CONSTRAINT email_sequences_account_id_fkey FOREIGN KEY (account_id) REFERENCES public.email_accounts(id)
);
CREATE TABLE public.email_sequence_steps (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  sequence_id uuid NOT NULL,
  step_order integer NOT NULL,
  delay_hours integer NOT NULL DEFAULT 0,
  subject text NOT NULL,
  body_html text NOT NULL,
  is_transactional boolean NOT NULL DEFAULT false,
  created_at timestamp with time zone NOT NULL DEFAULT now(),
  branch_wait_hours integer,
  CONSTRAINT email_sequence_steps_pkey PRIMARY KEY (id),
  CONSTRAINT email_sequence_steps_sequence_id_fkey FOREIGN KEY (sequence_id) REFERENCES public.email_sequences(id)
);
CREATE TABLE public.email_sequence_enrollments (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  sequence_id uuid NOT NULL,
  contact_id uuid NOT NULL,
  current_step integer NOT NULL DEFAULT 0,
  next_send_at timestamp with time zone NOT NULL DEFAULT now(),
  status text NOT NULL DEFAULT 'active'::text CHECK (status = ANY (ARRAY['active'::text, 'completed'::text, 'stopped'::text])),
  created_at timestamp with time zone NOT NULL DEFAULT now(),
  awaiting_branch_evaluation boolean NOT NULL DEFAULT false,
  CONSTRAINT email_sequence_enrollments_pkey PRIMARY KEY (id),
  CONSTRAINT email_sequence_enrollments_sequence_id_fkey FOREIGN KEY (sequence_id) REFERENCES public.email_sequences(id),
  CONSTRAINT email_sequence_enrollments_contact_id_fkey FOREIGN KEY (contact_id) REFERENCES public.email_contacts(id)
);
CREATE TABLE public.email_segments (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  account_id uuid NOT NULL,
  name text NOT NULL,
  rules jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamp with time zone NOT NULL DEFAULT now(),
  CONSTRAINT email_segments_pkey PRIMARY KEY (id),
  CONSTRAINT email_segments_account_id_fkey FOREIGN KEY (account_id) REFERENCES public.email_accounts(id)
);
CREATE TABLE public.email_sequence_sends (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  enrollment_id uuid NOT NULL,
  step_id uuid NOT NULL,
  account_id uuid,
  contact_email text NOT NULL,
  status text NOT NULL,
  provider_message_id text,
  opened_at timestamp with time zone,
  clicked_at timestamp with time zone,
  sent_at timestamp with time zone,
  created_at timestamp with time zone NOT NULL DEFAULT now(),
  CONSTRAINT email_sequence_sends_pkey PRIMARY KEY (id),
  CONSTRAINT email_sequence_sends_enrollment_id_fkey FOREIGN KEY (enrollment_id) REFERENCES public.email_sequence_enrollments(id),
  CONSTRAINT email_sequence_sends_step_id_fkey FOREIGN KEY (step_id) REFERENCES public.email_sequence_steps(id),
  CONSTRAINT email_sequence_sends_account_id_fkey FOREIGN KEY (account_id) REFERENCES public.email_accounts(id)
);
CREATE TABLE public.email_reputation_status (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  account_id uuid NOT NULL,
  check_type text NOT NULL,
  status text NOT NULL,
  detail text,
  checked_at timestamp with time zone NOT NULL DEFAULT now(),
  CONSTRAINT email_reputation_status_pkey PRIMARY KEY (id),
  CONSTRAINT email_reputation_status_account_id_fkey FOREIGN KEY (account_id) REFERENCES public.email_accounts(id)
);
CREATE TABLE public.email_campaign_variants (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  campaign_id uuid NOT NULL,
  label text NOT NULL,
  subject text NOT NULL,
  body_html text NOT NULL,
  created_at timestamp with time zone NOT NULL DEFAULT now(),
  CONSTRAINT email_campaign_variants_pkey PRIMARY KEY (id),
  CONSTRAINT email_campaign_variants_campaign_id_fkey FOREIGN KEY (campaign_id) REFERENCES public.email_campaigns(id)
);
CREATE TABLE public.email_sequence_step_branches (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  step_id uuid NOT NULL,
  condition text NOT NULL CHECK (condition = ANY (ARRAY['opened'::text, 'not_opened'::text, 'clicked'::text, 'not_clicked'::text])),
  next_step_id uuid,
  created_at timestamp with time zone NOT NULL DEFAULT now(),
  CONSTRAINT email_sequence_step_branches_pkey PRIMARY KEY (id),
  CONSTRAINT email_sequence_step_branches_step_id_fkey FOREIGN KEY (step_id) REFERENCES public.email_sequence_steps(id),
  CONSTRAINT email_sequence_step_branches_next_step_id_fkey FOREIGN KEY (next_step_id) REFERENCES public.email_sequence_steps(id)
);
CREATE TABLE public.pattern_events (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  owner_id uuid NOT NULL DEFAULT auth.uid(),
  interaction_type text NOT NULL,
  company_name text NOT NULL DEFAULT ''::text,
  industry text NOT NULL DEFAULT ''::text,
  channel text NOT NULL DEFAULT 'email'::text,
  angle_used text NOT NULL DEFAULT ''::text,
  outcome text NOT NULL DEFAULT ''::text,
  day_of_week text NOT NULL,
  raw_data jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamp with time zone NOT NULL DEFAULT now(),
  CONSTRAINT pattern_events_pkey PRIMARY KEY (id),
  CONSTRAINT pattern_events_owner_id_fkey FOREIGN KEY (owner_id) REFERENCES auth.users(id)
);
CREATE TABLE public.calls (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  owner_id uuid NOT NULL DEFAULT auth.uid(),
  contact_id uuid,
  company_name text NOT NULL DEFAULT ''::text,
  started_at timestamp with time zone NOT NULL,
  ended_at timestamp with time zone NOT NULL,
  duration_seconds integer NOT NULL DEFAULT 0,
  transcript text NOT NULL DEFAULT ''::text,
  sentiment text NOT NULL DEFAULT 'neutral'::text,
  objections jsonb NOT NULL DEFAULT '[]'::jsonb,
  buying_signals jsonb NOT NULL DEFAULT '[]'::jsonb,
  summary text NOT NULL DEFAULT ''::text,
  next_steps text NOT NULL DEFAULT ''::text,
  live_event_count integer NOT NULL DEFAULT 0,
  created_at timestamp with time zone NOT NULL DEFAULT now(),
  CONSTRAINT calls_pkey PRIMARY KEY (id),
  CONSTRAINT calls_owner_id_fkey FOREIGN KEY (owner_id) REFERENCES auth.users(id),
  CONSTRAINT calls_contact_id_fkey FOREIGN KEY (contact_id) REFERENCES public.contacts(id)
);
CREATE TABLE public.competitors (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  owner_id uuid NOT NULL DEFAULT auth.uid(),
  name text NOT NULL,
  url text NOT NULL,
  what_they_sell text NOT NULL DEFAULT ''::text,
  target_customer text NOT NULL DEFAULT ''::text,
  pricing_model text NOT NULL DEFAULT 'Unknown'::text,
  strengths jsonb NOT NULL DEFAULT '[]'::jsonb,
  weaknesses jsonb NOT NULL DEFAULT '[]'::jsonb,
  positioning text NOT NULL DEFAULT ''::text,
  how_to_beat_them jsonb NOT NULL DEFAULT '[]'::jsonb,
  created_at timestamp with time zone NOT NULL DEFAULT now(),
  updated_at timestamp with time zone NOT NULL DEFAULT now(),
  CONSTRAINT competitors_pkey PRIMARY KEY (id),
  CONSTRAINT competitors_owner_id_fkey FOREIGN KEY (owner_id) REFERENCES auth.users(id)
);