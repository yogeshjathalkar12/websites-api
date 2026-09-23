-- Record that a customer confirmed the responsibilities statement when
-- connecting a mailbox: when (server clock) and which wording (version).
--
-- RUN THIS IN THE SUPABASE SQL EDITOR *BEFORE* DEPLOYING THE BACKEND THAT
-- WRITES THESE COLUMNS. If the backend goes out first, connecting a mailbox
-- fails until this has been run.
--
-- Safe to run more than once.

ALTER TABLE public.email_accounts
  ADD COLUMN IF NOT EXISTS risks_accepted_at timestamp with time zone,
  ADD COLUMN IF NOT EXISTS risks_accepted_version text;

-- Resend is no longer offered to customers; a mailbox is the only kind.
ALTER TABLE public.email_accounts ALTER COLUMN provider SET DEFAULT 'smtp';

COMMENT ON COLUMN public.email_accounts.risks_accepted_at IS
  'When the owner confirmed the responsibilities statement (server clock). Set only by the backend.';
COMMENT ON COLUMN public.email_accounts.risks_accepted_version IS
  'Version of the statement wording shown at that moment (RISKS_VERSION in raptor/email/router.py).';

-- Customers reach this table directly through Supabase as well as through
-- the backend, so without this they could write or change their own proof.
-- Writes made as a signed-in user or anonymously cannot set or alter these
-- two columns; only the backend (service role) can.
CREATE OR REPLACE FUNCTION public.email_accounts_protect_risk_proof()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  IF current_user IN ('authenticated', 'anon') THEN
    IF TG_OP = 'INSERT' THEN
      NEW.risks_accepted_at := NULL;
      NEW.risks_accepted_version := NULL;
    ELSE
      NEW.risks_accepted_at := OLD.risks_accepted_at;
      NEW.risks_accepted_version := OLD.risks_accepted_version;
    END IF;
  END IF;
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS email_accounts_protect_risk_proof ON public.email_accounts;
CREATE TRIGGER email_accounts_protect_risk_proof
  BEFORE INSERT OR UPDATE ON public.email_accounts
  FOR EACH ROW EXECUTE FUNCTION public.email_accounts_protect_risk_proof();

-- Check afterwards (both should list the two new columns / the trigger):
--   SELECT column_name FROM information_schema.columns
--    WHERE table_name = 'email_accounts' AND column_name LIKE 'risks_%';
--   SELECT tgname FROM pg_trigger WHERE tgname = 'email_accounts_protect_risk_proof';
