-- Background-job bookkeeping for the K-Means (Smart Customer Profiler) and Monte Carlo
-- (Revenue Forecasting) tools. Safe to re-run. The server reads/writes it with its
-- service key; no browser access is needed, so row-level security is on with no
-- policies (browsers are denied, the server key bypasses it).
CREATE TABLE IF NOT EXISTS public.compute_jobs (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL,
  tool text NOT NULL,
  status text NOT NULL DEFAULT 'queued',
  input jsonb,
  result jsonb,
  error text,
  created_at timestamptz NOT NULL DEFAULT now(),
  finished_at timestamptz
);
CREATE INDEX IF NOT EXISTS compute_jobs_user_idx ON public.compute_jobs (user_id, created_at DESC);
ALTER TABLE public.compute_jobs ENABLE ROW LEVEL SECURITY;
