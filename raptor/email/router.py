"""
router.py — everything the frontend and cron actually call for email.

REPLACES the standalone service's api.py + sender.py with a single design
change: sending is now BATCH-based, not one long BackgroundTask sleeping
20-90s between every recipient. That sleep pattern was fine as its own
process; inside the same worker serving chronos/kmeans/content, it would
hold a thread for potentially many minutes and block unrelated requests —
the exact problem already fixed for kmeans/montecarlo, reintroduced.

Pacing now comes from TWO knobs instead of one: BATCH_SIZE (how many
recipients one call processes) and how often something calls /tick (which
advances every actively-sending campaign by one batch). Point your
existing cron — the same one hitting /api/automations/run — at
POST /api/raptor/email/tick every 1-3 minutes, and sends trickle out at a
human-plausible rate without ever blocking a request thread.

Endpoints:
  POST /accounts                     — create account, api_key encrypted server-side
  GET  /analytics/overview           — aggregated open/click/event dashboard data (see analytics.py)
  GET  /accounts/{id}/reputation     — last-known deliverability health status (see reputation.py)
  POST /accounts/{id}/reputation/check — run a fresh reputation check now (live DNS lookups)
  POST /reputation-tick              — cron-only, runs reputation checks for every account (1-2x/day, not every tick)
  POST /campaigns/{id}/send          — process one batch right now (manual "Send Now")
  POST /tick                         — cron-only, advances every sending campaign one batch
  POST /events/webhook/{account_id}  — external behavioral-trigger event ingestion (see triggers.py)
  POST /trigger-tick                 — cron-only, sends due behavioral-trigger events
  POST /followup-tick                — cron-only, evaluates/sends due branching follow-ups (see branching.py)
  POST /sequences/{id}/enroll        — enroll contacts (by email or audience tag) into a drip sequence (see sequences.py)
  POST /sequence-tick                — cron-only, sends due sequence steps and advances enrollments
  POST /campaigns/{id}/ab-test/declare-winner — manually pick a winning variant now (see ab_testing.py)
  POST /ab-test-tick                 — cron-only, auto-finalizes AB tests whose duration has elapsed
  GET  /unsubscribe                  — token-verified suppression
  GET  /track/open, /track/click     — open/click tracking (see tracking.py)

Behavioral triggers (triggers.py) are a separate concept from campaigns:
a campaign fans one message out to many pre-selected recipients; a
trigger fans out to exactly one contact in response to an event, either
from your own CRM (same process, calls triggers.emit_event() directly)
or from outside (this file's /events/webhook route, via event_sources.py).
"""
import hmac
import os
import re
import secrets
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, HTTPException, Depends, Body, Request, Header
from fastapi.responses import HTMLResponse, Response, RedirectResponse

from raptor.utility.raptor_auth import get_current_user, supabase, pro_required, require_pro
from . import key_vault
from . import providers
from . import tracking
from . import triggers
from . import event_sources
from . import branching
from . import sequences
from . import segments
from . import crm_bridge
from . import ab_testing
from . import analytics
from . import reputation
from . import sending
from .spintax import render_email
from .warmup import todays_allowed_volume, sent_today_count, within_business_hours
from .security import verify_unsubscribe_token

# 1x1 transparent GIF served by /track/open — smallest valid GIF89a.
_PIXEL_GIF = bytes.fromhex(
    '47494638396101000100800000000000ffffff21f90401000000002c00000000010001000002024401003b'
)

router = APIRouter()

BATCH_SIZE = 3
# After a provider says "limit reached", that account isn't tried again for this
# long. Per-process memory is enough: at worst another worker tries once more.
PROVIDER_BACKOFF_MINUTES = 15
_provider_backoff_until: dict = {}
LOCK_STALE_MINUTES = 2  # short — batches finish in seconds now, not minutes
AUTOMATION_CRON_SECRET = os.environ.get('AUTOMATION_CRON_SECRET')  # same secret automations_router.py uses


def _require_automation_secret(x_automation_secret: str = Header(None)):
    """Defined here, immediately after the constant it depends on and
    BEFORE any route decorator references it via
    dependencies=[Depends(_require_automation_secret)] — FastAPI route
    decorators are evaluated at module-IMPORT time, top to bottom, so a
    dependency referenced before it's defined isn't a late-binding
    situation like a normal function call; it's an immediate NameError
    that fails to import this entire module. That's exactly what this
    used to be: this function used to live much further down the file
    (near /tick), while /reputation-tick further up already referenced
    it — router.py would have failed to import at all until this moved."""
    if not AUTOMATION_CRON_SECRET or x_automation_secret != AUTOMATION_CRON_SECRET:
        raise HTTPException(status_code=401, detail="Invalid or missing automation secret.")


@router.get("/status")
def status():
    return {"tool": "email-automation", "status": "operational"}


@router.get("/analytics/overview")
def analytics_overview(account_id: str, days: int = 30, user_id: str = Depends(get_current_user)):
    account = supabase.table('email_accounts').select('owner_id').eq('id', account_id).single().execute().data
    if not account:
        raise HTTPException(status_code=404, detail="Account not found.")
    if account['owner_id'] != user_id:
        raise HTTPException(status_code=403, detail="You don't own this account.")
    return analytics.compute_overview(account_id, days)


@router.get("/accounts/{account_id}/reputation")
def get_reputation(account_id: str, user_id: str = Depends(get_current_user)):
    """Fast read of the last-known status — no live DNS lookups, safe to
    call on every dashboard load. Use POST .../reputation/check for a
    fresh on-demand check."""
    account = supabase.table('email_accounts').select('owner_id').eq('id', account_id).single().execute().data
    if not account:
        raise HTTPException(status_code=404, detail="Account not found.")
    if account['owner_id'] != user_id:
        raise HTTPException(status_code=403, detail="You don't own this account.")
    rows = supabase.table('email_reputation_status').select('*').eq('account_id', account_id).execute().data or []
    return {'checks': rows}


@router.post("/accounts/{account_id}/reputation/check")
def run_reputation_check(account_id: str, user_id: str = Depends(get_current_user)):
    """Runs a fresh check right now — real DNS lookups included, so this
    is meaningfully slower than the GET above. For a 'Run check now'
    button, not for polling."""
    account = supabase.table('email_accounts').select('*').eq('id', account_id).single().execute().data
    if not account:
        raise HTTPException(status_code=404, detail="Account not found.")
    if account['owner_id'] != user_id:
        raise HTTPException(status_code=403, detail="You don't own this account.")
    return {'checks': reputation.check_and_store(account)}


@router.post("/reputation-tick", dependencies=[Depends(_require_automation_secret)])
def reputation_tick():
    """Cron-only — unlike /tick and friends, this should run once or
    twice a DAY, not every 1-3 minutes. DNS lookups and a week-long
    event scan across every account are heavier, and none of these
    signals meaningfully change minute to minute."""
    return reputation.check_all_accounts()


# ---------------------------------------------------------------------------
# Accounts
# ---------------------------------------------------------------------------

# Starting volume and ramp target per kind of account. The ramp adds
# WARMUP_DAILY_STEP per day from daily_cap up to warmup_target (warmup.py).
#   A customer's own mailbox is the only way to connect a new account.
#   10 a day growing to 20 is deliberately human-paced: Gmail and Microsoft
#   flag mailboxes far below their published limits when volume jumps.
#   (This server's own system emails — login codes, licence mail — use a
#   separate service, see utility/notifications.py.)
SENDING_DEFAULTS = {
    'smtp': {'daily_cap': 10, 'warmup_target': 20},
    # Same pace as the desktop app's own defaults (raptor/outreach/mailbox.py). The desktop app is the real
    # governor; this only limits how fast mail is queued, so it never piles up and expires.
    'desktop': {'daily_cap': 10, 'warmup_target': 20},
}

CREATABLE_PROVIDERS = ('smtp', 'desktop')

SMTP_OFF_MESSAGE = ("Sending from your own mailbox isn't switched on for this server yet. "
                    "Ask us when mailbox sending will be available.")

# What the customer confirms when connecting a mailbox. The wording lives
# here, not in the browser, so what is stored as accepted is exactly what
# was shown. CHANGING THE TEXT MEANS BUMPING THE VERSION: the version is
# recorded with each acceptance, and an acceptance sent for an old version
# is refused, so nobody can confirm wording they were not shown.
RISKS_VERSION = '2026-09-23'
RISKS_STATEMENT = (
    "I understand I am solely responsible for who I email and for following the laws that apply "
    "to my recipients (for example the DPDP Act and IT rules in India, GDPR in the EU, CAN-SPAM in "
    "the US). Raptor does not check whether recipients have agreed to hear from me. Gmail, "
    "Microsoft or my mail host can limit or suspend my mailbox if it sends unwanted mail."
)
PRO_MESSAGE = ("Email automation is part of the Pro plan. Upgrade to Pro to connect your own mailbox.")


def _require_pro(user_id: str) -> None:
    """Connecting a mailbox is a Pro feature - checked on the server for the
    organization's plan (shared check in raptor_auth.require_pro)."""
    require_pro(user_id, PRO_MESSAGE)


RISKS_MESSAGE = ("Please confirm the statement about your responsibilities before connecting. "
                 "If you already did, reload the page — the wording may have been updated.")


# ---------------------------------------------------------------------------
# A desktop account can carry the WHOLE mailbox (settings + password)
# ---------------------------------------------------------------------------
# So the web app and the desktop app share one source of truth for "which mailbox is connected". This server never
# logs in with the password (its host cannot reach mail servers); the owner's desktop app fetches it from
# GET /accounts/{id}/credentials and does the sending. The password is encrypted with key_vault before it is saved.

_HOSTNAME_RE = re.compile(r'[a-z0-9]([a-z0-9.\-]*[a-z0-9])?')
IMAP_PORTS = (993, 143)


def _whole_number(value, low: int, high: int, message: str) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError):
        raise ValueError(message)
    if not low <= number <= high:
        raise ValueError(message)
    return number


def _mailbox_extras(config: dict) -> dict:
    """Checks the non-secret mailbox settings beyond the SMTP ones (inbox server, signature, rules)."""
    imap_host = str(config.get('imap_host', '')).strip().lower()
    if imap_host and (len(imap_host) > 253 or not _HOSTNAME_RE.fullmatch(imap_host) or '.' not in imap_host):
        raise ValueError("Enter your inbox server's host name, like imap.gmail.com.")
    imap_port = _whole_number(config.get('imap_port') or 993, 1, 65535, "The inbox port must be a number.")
    if imap_port not in IMAP_PORTS:
        raise ValueError("The inbox port must be 993 (SSL) or 143.")
    signature = str(config.get('signature', '')).strip()
    if len(signature) > 600:
        raise ValueError("The signature is too long (600 characters at most).")
    threshold = _whole_number(config.get('icp_threshold', 70), 0, 100, "The prospect-fit threshold must be between 0 and 100.")
    return {'imap_host': imap_host, 'imap_port': imap_port, 'signature': signature,
            'weekdays_only': bool(config.get('weekdays_only', True)), 'icp_threshold': threshold}


def _mailbox_limits(payload: dict, defaults: dict) -> dict:
    """The sending rules (daily limits and hours), checked, as database columns."""
    daily = _whole_number(payload.get('daily_cap', defaults['daily_cap']), 1, 100, "The first-day limit must be between 1 and 100 emails.")
    target = _whole_number(payload.get('warmup_target', defaults['warmup_target']), 1, 200, "The daily maximum must be between 1 and 200 emails.")
    if target < daily:
        raise ValueError("The daily maximum cannot be lower than the first-day limit.")
    start = _whole_number(payload.get('hours_start', 9), 0, 23, "The sending start hour must be between 0 and 23.")
    end = _whole_number(payload.get('hours_end', 19), 1, 24, "The sending end hour must be between 1 and 24.")
    if end <= start:
        raise ValueError("The sending end hour must be after the start hour.")
    return {'daily_cap': daily, 'warmup_target': target, 'business_hours_start': start, 'business_hours_end': end}


@router.get("/providers")
def available_providers(user_id: str = Depends(get_current_user)):
    """Which ways of connecting a new account this server currently
    supports, plus the responsibilities statement the customer must confirm
    (and its version) so the screen shows exactly what gets recorded."""
    return {'smtp': providers.smtp_enabled(), 'desktop': True,
            'risks_version': RISKS_VERSION, 'risks_statement': RISKS_STATEMENT}


@router.post("/accounts/test-smtp")
def test_smtp_connection(payload: dict = Body(...), user_id: str = Depends(get_current_user)):
    """Logs in to the customer's mail server and disconnects, without
    sending anything, so the setup screen can say "connected" before the
    account is saved. The password is used for this one call only."""
    _require_pro(user_id)
    if not providers.smtp_enabled():
        raise HTTPException(status_code=400, detail=SMTP_OFF_MESSAGE)
    password = str(payload.get('password', ''))
    if not password:
        raise HTTPException(status_code=400, detail="Enter the mailbox password.")
    try:
        config = providers.validate_smtp_config(payload.get('smtp_config') or {})
        providers.SmtpProvider({**config, 'password': password}).check_connection()
    except (ValueError, RuntimeError, providers.ProviderUnavailable) as err:
        raise HTTPException(status_code=400, detail=str(err))
    return {'ok': True}


@router.post("/accounts")
def create_account(payload: dict = Body(...), user_id: str = Depends(get_current_user)):
    _require_pro(user_id)
    provider = payload.get('provider', 'smtp')
    # A desktop account holds no password at all: the mailbox lives in the desktop app.
    required = ['label', 'from_email', 'from_name'] + ([] if provider == 'desktop' else ['api_key'])
    missing = [f for f in required if not str(payload.get(f, '')).strip()]
    if missing:
        raise HTTPException(status_code=400, detail=f"Missing required field(s): {', '.join(missing)}")

    if provider not in CREATABLE_PROVIDERS:
        raise HTTPException(status_code=400, detail=f"Unknown provider '{provider}'. Use one of: {', '.join(CREATABLE_PROVIDERS)}.")
    if payload.get('accepted_risks_version') != RISKS_VERSION:
        raise HTTPException(status_code=400, detail=RISKS_MESSAGE)

    limits = None
    if provider == 'desktop':
        password = str(payload.get('api_key', '')).strip()
        if password:
            # The whole mailbox, stored for the owner's desktop app. No login is tried here: this server cannot reach
            # mail servers, so the desktop app checks the login the first time it uses the mailbox.
            try:
                raw_config = payload.get('smtp_config') or {}
                smtp_config = {**providers.validate_smtp_config(raw_config), **_mailbox_extras(raw_config)}
                limits = _mailbox_limits(payload, SENDING_DEFAULTS['desktop'])
            except ValueError as err:
                raise HTTPException(status_code=400, detail=str(err))
            secret = key_vault.encrypt_key(password)
        else:
            smtp_config, secret = None, ''
    else:
        if not providers.smtp_enabled():
            raise HTTPException(status_code=400, detail=SMTP_OFF_MESSAGE)
        try:
            smtp_config = providers.validate_smtp_config(payload.get('smtp_config') or {})
            # Never save a mailbox that has not just logged in successfully: the
            # setup screen's Test button is a convenience, this is the guarantee.
            providers.SmtpProvider({**smtp_config, 'password': payload['api_key'].strip()}).check_connection()
        except (ValueError, RuntimeError, providers.ProviderUnavailable) as err:
            raise HTTPException(status_code=400, detail=f"Not connected - {err}")
        secret = key_vault.encrypt_key(payload['api_key'].strip())

    caps = SENDING_DEFAULTS[provider]

    row = {
        'owner_id': user_id,
        'label': payload['label'].strip(),
        'provider': provider,
        'from_email': payload['from_email'].strip(),
        'from_name': payload['from_name'].strip(),
        # For SMTP this is the mailbox password. Only the non-secret
        # settings (host/port/username/security) go in smtp_config.
        # Empty for a desktop account: there is no password on this server.
        'encrypted_api_key': secret,
        'smtp_config': smtp_config,
        'daily_cap': caps['daily_cap'],
        'warmup_target': caps['warmup_target'],
        # Proof of the confirmation: the server's clock, and the exact version
        # of the wording shown. Never taken from the request. A database
        # trigger stops customers editing these directly (see migrations/).
        'risks_accepted_at': datetime.now(timezone.utc).isoformat(),
        'risks_accepted_version': RISKS_VERSION,
        # Compared with hmac.compare_digest on inbound webhooks, never
        # decrypted — a plain random token is enough, no need for
        # key_vault here.
        'inbound_webhook_secret': secrets.token_urlsafe(24),
    }
    if limits:
        row.update(limits)
    resp = supabase.table('email_accounts').insert(row).execute()
    if not resp.data:
        raise HTTPException(status_code=500, detail="Could not save this account.")
    account = resp.data[0]
    account.pop('encrypted_api_key', None)
    # inbound_webhook_secret is deliberately returned here, once, so the
    # frontend can show it for pasting into Shopify/Stripe/etc. It's not
    # selected by the direct-Supabase read in EmailConnectionSetup's
    # fetchAccounts, so this creation response is the only place it's
    # visible without a dedicated "reveal" endpoint (worth adding later).
    return account


@router.get("/accounts/{account_id}/credentials")
def get_mailbox_credentials(account_id: str, response: Response, user_id: str = Depends(get_current_user)):
    """The owner's desktop app fetches its stored mailbox here (settings and the decrypted password) so that it sends
    from the mailbox connected in the web app. Owner only; never cached."""
    _require_pro(user_id)
    found = supabase.table('email_accounts').select('*').eq('id', account_id).eq('owner_id', user_id).limit(1).execute()
    rows = found.data or []
    row = rows[0] if rows else None
    if not row or row.get('provider') != 'desktop' or not row.get('encrypted_api_key'):
        raise HTTPException(status_code=404, detail="No stored mailbox found for that account.")
    response.headers['Cache-Control'] = 'no-store'
    return {
        'id': row['id'], 'label': row.get('label'), 'from_email': row.get('from_email'), 'from_name': row.get('from_name'),
        'smtp_config': row.get('smtp_config') or {},
        'password': key_vault.decrypt_key(row['encrypted_api_key']),
        'daily_cap': row.get('daily_cap'), 'warmup_target': row.get('warmup_target'),
        'business_hours_start': row.get('business_hours_start'), 'business_hours_end': row.get('business_hours_end'),
        'timezone': row.get('timezone'),
    }


# ---------------------------------------------------------------------------
# Sending — shared batch logic used by both the manual trigger and /tick
# ---------------------------------------------------------------------------

def _try_acquire_lock(campaign_id: str) -> bool:
    stale_cutoff = (datetime.now(timezone.utc) - timedelta(minutes=LOCK_STALE_MINUTES)).isoformat()
    now_iso = datetime.now(timezone.utc).isoformat()
    resp = (
        supabase.table('email_campaigns')
        .update({'locked_at': now_iso})
        .eq('id', campaign_id)
        .or_(f'locked_at.is.null,locked_at.lt.{stale_cutoff}')
        .execute()
    )
    return bool(resp.data)


def _release_lock(campaign_id: str) -> None:
    supabase.table('email_campaigns').update({'locked_at': None}).eq('id', campaign_id).execute()


def _ensure_recipients_populated(campaign: dict) -> None:
    """THE FIX for a real bug: nothing anywhere — no DB trigger, no other
    code path — ever inserted email_campaign_recipients rows. Every
    campaign's first batch found zero 'pending' rows and immediately hit
    the no_pending_recipients branch below, marking the campaign 'done'
    having sent nothing. Silently, since an empty pending set looks
    identical to "already fully sent."

    Runs once per campaign: if any recipient row already exists (this
    campaign has been through this before), it's a no-op — the audience
    is a fixed snapshot taken the first time a campaign is processed,
    not re-resolved on every batch."""
    existing = (
        supabase.table('email_campaign_recipients')
        .select('id')
        .eq('campaign_id', campaign['id'])
        .limit(1)
        .execute()
        .data
    )
    if existing:
        return

    contacts = segments.resolve_audience(campaign['account_id'], campaign.get('segment_id'), campaign.get('audience_tag'))
    if not contacts:
        return  # legitimately empty audience — the no_pending_recipients path below correctly marks this 'done'

    # Handles both the plain case (no variants -> flat 'pending' rows)
    # and A/B tests (splits into a test group per variant + a held-back
    # 'awaiting_winner' rest group) — same call site either way.
    rows = ab_testing.split_recipients_for_ab_test(campaign, contacts)
    for i in range(0, len(rows), 500):  # chunked to avoid an oversized single insert on a large audience
        supabase.table('email_campaign_recipients').insert(rows[i:i + 500]).execute()

    if campaign.get('ab_test_enabled') and not campaign.get('ab_test_started_at'):
        # Starts the test's duration clock at population time, not at
        # the moment each individual test email actually goes out —
        # simple and predictable; ab_test_duration_hours should just be
        # set generously enough to account for warmup-paced trickle.
        supabase.table('email_campaigns').update({
            'ab_test_started_at': datetime.now(timezone.utc).isoformat(),
        }).eq('id', campaign['id']).execute()


def _send_one_batch(campaign_id: str) -> dict:
    """Sends up to BATCH_SIZE pending recipients for one campaign, right
    now, no sleep. Returns a small status dict rather than raising for
    expected skip conditions (outside hours, cap reached) — those are
    normal, not errors."""
    if not _try_acquire_lock(campaign_id):
        return {'skipped': 'locked_by_another_run'}

    try:
        campaign = supabase.table('email_campaigns').select('*, email_accounts(*)').eq('id', campaign_id).single().execute().data
        if not campaign:
            return {'skipped': 'not_found'}
        account = campaign['email_accounts']

        variants = supabase.table('email_campaign_variants').select('*').eq('campaign_id', campaign_id).order('created_at').execute().data or []
        bodies_to_check = [v['body_html'] for v in variants] if variants else [campaign['body_html']]
        if any('{{unsubscribe_url}}' not in b for b in bodies_to_check):
            return {'skipped': 'missing_unsubscribe_placeholder'}
        variants_by_id = {v['id']: v for v in variants}
        if campaign['status'] == 'done':
            return {'skipped': 'already_done'}
        if not within_business_hours(account):
            return {'skipped': 'outside_business_hours'}

        backoff_until = _provider_backoff_until.get(account['id'])
        if backoff_until and datetime.now(timezone.utc) < backoff_until:
            return {'skipped': 'provider_rate_limited', 'retry_after': backoff_until.isoformat()}

        allowed_today = todays_allowed_volume(account)
        sent_today = sent_today_count(account)
        remaining = allowed_today - sent_today
        if remaining <= 0:
            return {'skipped': 'daily_cap_reached', 'sent_today': sent_today, 'allowed_today': allowed_today}

        _ensure_recipients_populated(campaign)

        suppressed = {
            row['email'] for row in
            supabase.table('email_suppressions').select('email').eq('account_id', account['id']).execute().data
        }

        take = min(BATCH_SIZE, remaining)
        # No tag/segment filter needed here anymore — _ensure_recipients_populated
        # already resolved the audience once, so every row for this
        # campaign_id already matches by construction.
        recipients = (
            supabase.table('email_campaign_recipients')
            .select('*, email_contacts(*)')
            .eq('campaign_id', campaign_id)
            .eq('status', 'pending')
            .limit(take)
            .execute()
            .data
        )

        if not recipients:
            supabase.table('email_campaigns').update({'status': 'done'}).eq('id', campaign_id).execute()
            return {'skipped': 'no_pending_recipients', 'campaign_marked_done': True}

        supabase.table('email_campaigns').update({'status': 'sending'}).eq('id', campaign_id).execute()

        provider = sending.get_ready_provider(account)

        sent, failed, skipped = 0, 0, 0
        rate_limited = False
        for recipient in recipients:
            contact = recipient['email_contacts']
            if contact['email'] in suppressed:
                supabase.table('email_campaign_recipients').update({'status': 'skipped_suppressed'}).eq('id', recipient['id']).execute()
                skipped += 1
                continue

            unsubscribe_link = sending.unsubscribe_url(account['id'], contact['email'])
            variant = variants_by_id.get(recipient.get('variant_id'))
            subject_template = variant['subject'] if variant else campaign['subject']
            body_template = variant['body_html'] if variant else campaign['body_html']
            subject = render_email(subject_template, contact, unsubscribe_link)
            body = render_email(body_template, contact, unsubscribe_link)
            # Tracking is keyed off the recipient row's own id, not the
            # contact or campaign id, so a token only ever resolves to
            # this one send.
            body = tracking.wrap_links(body, f"campaign:{recipient['id']}", os.environ['APP_BASE_URL'])
            body += tracking.open_pixel_tag(f"campaign:{recipient['id']}", os.environ['APP_BASE_URL'])

            try:
                message_id = provider.send(account['from_email'], account['from_name'], contact['email'], subject, body)
                supabase.table('email_campaign_recipients').update({
                    'status': 'sent', 'provider_message_id': message_id, 'sent_at': datetime.now(timezone.utc).isoformat(),
                }).eq('id', recipient['id']).execute()
                supabase.table('email_events').insert({
                    'account_id': account['id'], 'contact_email': contact['email'],
                    'event_type': 'sent', 'provider_message_id': message_id,
                }).execute()
                sent += 1
            except providers.ProviderRateLimited as err:
                # The provider (or the mailbox) hit a sending limit. Nothing
                # is wrong with this recipient, so leave them 'pending' and
                # try again later instead of marking them failed for good.
                _provider_backoff_until[account['id']] = datetime.now(timezone.utc) + timedelta(minutes=PROVIDER_BACKOFF_MINUTES)
                rate_limited = True
                print(f"Provider unavailable or at its limit for account {account['id']}; pausing sends: {err}")
                break
            except Exception as err:
                supabase.table('email_campaign_recipients').update({'status': 'failed'}).eq('id', recipient['id']).execute()
                failed += 1
                print(f"Failed to send to {contact['email']}: {err}")

        result = {'sent': sent, 'failed': failed, 'skipped_suppressed': skipped}
        if rate_limited:
            result['paused'] = 'provider_rate_limited'
        return result
    finally:
        _release_lock(campaign_id)


@router.post("/campaigns/{campaign_id}/send", dependencies=[Depends(pro_required)])
def trigger_send(campaign_id: str, user_id: str = Depends(get_current_user)):
    campaign = supabase.table('email_campaigns').select('*, email_accounts(owner_id)').eq('id', campaign_id).single().execute().data
    if not campaign:
        raise HTTPException(status_code=404, detail="Campaign not found.")
    if campaign['email_accounts']['owner_id'] != user_id:
        raise HTTPException(status_code=403, detail="You don't own this campaign's sending account.")
    return _send_one_batch(campaign_id)


@router.post("/campaigns/{campaign_id}/ab-test/declare-winner", dependencies=[Depends(pro_required)])
def declare_ab_test_winner(campaign_id: str, user_id: str = Depends(get_current_user)):
    """Manual override — bypasses ab_test_duration_hours and picks a
    winner right now using the same logic the cron sweep uses (primary
    metric, falling back to the other on a tie). Safe to call even after
    a winner was already auto-picked; finalize_test() just re-confirms
    it rather than re-releasing anything."""
    campaign = supabase.table('email_campaigns').select('*, email_accounts(owner_id)').eq('id', campaign_id).single().execute().data
    if not campaign:
        raise HTTPException(status_code=404, detail="Campaign not found.")
    if campaign['email_accounts']['owner_id'] != user_id:
        raise HTTPException(status_code=403, detail="You don't own this campaign's sending account.")
    if not campaign.get('ab_test_enabled'):
        raise HTTPException(status_code=400, detail="This campaign doesn't have A/B testing enabled.")
    return ab_testing.finalize_test(campaign)


@router.post("/tick", dependencies=[Depends(_require_automation_secret)])
def tick():
    """Cron-only — point your existing scheduler at this alongside
    /api/automations/run, every 1-3 minutes. Advances every campaign
    currently in 'sending' status by one batch. This is what actually
    drives a campaign to completion over time; a single manual 'Send Now'
    click only sends one batch and then waits for this to keep going."""
    active = supabase.table('email_campaigns').select('id').eq('status', 'sending').execute().data or []
    results = {}
    for row in active:
        results[row['id']] = _send_one_batch(row['id'])
    return {'processed': len(active), 'results': results}


# ---------------------------------------------------------------------------
# Behavioral triggers — inbound events + the cron that sends them
# ---------------------------------------------------------------------------

@router.post("/accounts/{account_id}/webhook-secret/regenerate")
def regenerate_webhook_secret(account_id: str, user_id: str = Depends(get_current_user)):
    """The secret is only ever returned once at account creation (see
    create_account) — this is the way to get a fresh, visible one later,
    e.g. to paste into a new Shopify webhook. Regenerating invalidates
    the old one immediately, so update any configured webhook first."""
    account = supabase.table('email_accounts').select('owner_id').eq('id', account_id).single().execute().data
    if not account:
        raise HTTPException(status_code=404, detail="Account not found.")
    if account['owner_id'] != user_id:
        raise HTTPException(status_code=403, detail="You don't own this account.")

    new_secret = secrets.token_urlsafe(24)
    supabase.table('email_accounts').update({'inbound_webhook_secret': new_secret}).eq('id', account_id).execute()
    return {'inbound_webhook_secret': new_secret}


@router.post("/events/webhook/{account_id}")
async def trigger_webhook(account_id: str, request: Request, source: str = 'generic', topic: str = '',
                           x_webhook_secret: str = Header(None)):
    """External event ingestion — Shopify, Stripe, Zapier/Make, or any
    custom integration. Point it here:
      POST /events/webhook/{account_id}?source=shopify&topic=orders/create
    with header X-Webhook-Secret set to the account's inbound_webhook_secret
    (shown once, at account creation).

    Your own CRM should NOT use this route — same process, so call
    triggers.emit_event(...) directly instead of round-tripping over HTTP."""
    account = (
        supabase.table('email_accounts')
        .select('inbound_webhook_secret, encrypted_shopify_webhook_secret')
        .eq('id', account_id)
        .single()
        .execute()
        .data
    )
    if not account or not account.get('inbound_webhook_secret'):
        raise HTTPException(status_code=404, detail="Unknown account.")
    if not hmac.compare_digest(account['inbound_webhook_secret'], x_webhook_secret or ''):
        raise HTTPException(status_code=401, detail="Invalid webhook secret.")

    # Read raw bytes BEFORE any JSON parsing — a source's own signature
    # (Shopify's HMAC) is computed over the exact bytes on the wire, and
    # re-serializing JSON can silently change key order/whitespace and
    # break verification. Starlette caches the body internally, so the
    # later request.json() call below reuses these same bytes for free.
    raw_body = await request.body()
    headers_lower = {k.lower(): v for k, v in request.headers.items()}

    shopify_secret = (
        key_vault.decrypt_key(account['encrypted_shopify_webhook_secret'])
        if source == 'shopify' and account.get('encrypted_shopify_webhook_secret') else None
    )
    event_source = event_sources.get_source(source, topic=topic, webhook_secret=shopify_secret)
    if not event_source.verify(raw_body, headers_lower):
        raise HTTPException(status_code=401, detail="Invalid webhook signature.")

    raw = await request.json()
    parsed = event_source.parse(raw)
    if not parsed['event_key'] or not parsed['contact_email']:
        raise HTTPException(status_code=400, detail="Payload missing an event key or contact email after parsing.")

    return triggers.emit_event(
        account_id, parsed['event_key'], parsed['contact_email'],
        payload=parsed['payload'], external_event_id=parsed['external_event_id'],
    )


@router.post("/accounts/{account_id}/shopify-secret")
def set_shopify_secret(account_id: str, payload: dict = Body(...), user_id: str = Depends(get_current_user)):
    """Sets (or replaces) the account's Shopify webhook signing secret —
    from Shopify's app/webhook settings, not to be confused with
    inbound_webhook_secret. Encrypted at rest via key_vault, same as the
    provider API key. Never returned by any GET — write-only, same
    principle as the provider API key."""
    webhook_secret = str(payload.get('webhook_secret', '')).strip()
    if not webhook_secret:
        raise HTTPException(status_code=400, detail="webhook_secret is required.")

    account = supabase.table('email_accounts').select('owner_id').eq('id', account_id).single().execute().data
    if not account:
        raise HTTPException(status_code=404, detail="Account not found.")
    if account['owner_id'] != user_id:
        raise HTTPException(status_code=403, detail="You don't own this account.")

    supabase.table('email_accounts').update({
        'encrypted_shopify_webhook_secret': key_vault.encrypt_key(webhook_secret),
    }).eq('id', account_id).execute()
    return {'saved': True}


@router.post("/trigger-tick", dependencies=[Depends(_require_automation_secret)])
def trigger_tick():
    """Cron-only — point your scheduler here alongside /tick, every 1-3
    minutes. Sends every due (or previously capacity/hours-blocked)
    trigger event."""
    return triggers.process_due_trigger_events()


@router.post("/followup-tick", dependencies=[Depends(_require_automation_secret)])
def followup_tick():
    """Cron-only — same rhythm as /tick and /trigger-tick. Evaluates and
    sends every due campaign follow-up branch (see branching.py)."""
    return branching.process_due_followups()


# ---------------------------------------------------------------------------
# Sequences — enrollment + the cron that walks steps forward
# ---------------------------------------------------------------------------

@router.post("/sequences/{sequence_id}/enroll", dependencies=[Depends(pro_required)])
def enroll_in_sequence(sequence_id: str, payload: dict = Body(...), user_id: str = Depends(get_current_user)):
    """Enroll by explicit email list, by audience tag, or both. Sequence
    definition (email_sequences / email_sequence_steps rows) is created
    directly from the frontend, same as campaigns and triggers — this
    endpoint exists because resolving an audience tag into contact ids
    and de-duplicating against existing active enrollments needs
    server-side logic, not just an insert."""
    sequence = supabase.table('email_sequences').select('*, email_accounts(id, owner_id)').eq('id', sequence_id).single().execute().data
    if not sequence:
        raise HTTPException(status_code=404, detail="Sequence not found.")
    if sequence['email_accounts']['owner_id'] != user_id:
        raise HTTPException(status_code=403, detail="You don't own this sequence's sending account.")
    account_id = sequence['email_accounts']['id']

    audience_tag = (payload.get('audience_tag') or '').strip()
    emails = [e.strip().lower() for e in payload.get('contact_emails', []) if str(e).strip()]
    if not audience_tag and not emails:
        raise HTTPException(status_code=400, detail="Provide an audience_tag or a list of contact_emails.")

    contact_ids = []
    if audience_tag:
        matched = supabase.table('email_contacts').select('id').eq('account_id', account_id).contains('tags', [audience_tag]).execute().data or []
        contact_ids.extend(row['id'] for row in matched)
    for email in emails:
        contact_ids.append(sending.get_or_create_contact(account_id, email)['id'])

    if not contact_ids:
        return {'enrolled': 0, 'skipped': 0, 'detail': 'No matching contacts found.'}

    return sequences.enroll_contacts(sequence_id, contact_ids)


@router.post("/sequence-tick", dependencies=[Depends(_require_automation_secret)])
def sequence_tick():
    """Cron-only — same rhythm as /tick, /trigger-tick, /followup-tick.
    Sends every due sequence step and advances (or completes/stops) each
    enrollment."""
    return sequences.process_due_sequence_steps()


@router.post("/ab-test-tick", dependencies=[Depends(_require_automation_secret)])
def ab_test_tick():
    """Cron-only — can run on the same 1-3 minute rhythm as /tick; unlike
    /reputation-tick this isn't doing DNS lookups or a heavy scan, just
    checking a handful of AB-enabled campaigns' elapsed time."""
    return ab_testing.check_and_finalize_due_tests()


# ---------------------------------------------------------------------------
# CRM marketing bridge — CrmMarketing.tsx's "Send Broadcast" button used to
# just insert a fake 'sent' row into campaign_emails and stop. This is the
# real send it was missing.
# ---------------------------------------------------------------------------

@router.post("/crm/dispatch", dependencies=[Depends(pro_required)])
def crm_dispatch(payload: dict = Body(...), user_id: str = Depends(get_current_user)):
    """Resolves a CRM audience_list's filter against the CRM's own
    contacts table, provisions matching people as email_contacts under
    the chosen sending account (matched/created by email — see
    sending.get_or_create_contact), creates a real email_campaigns row
    with those exact recipients pre-populated, and sends the first batch
    immediately — functionally identical to clicking 'Send Now' on a
    campaign created the normal way, just entered from the CRM side."""
    account_id = str(payload.get('account_id', '')).strip()
    audience_list_id = str(payload.get('audience_list_id', '')).strip()
    subject = str(payload.get('subject', '')).strip()
    body_html = str(payload.get('body_html', '')).strip()
    if not account_id or not audience_list_id or not subject or not body_html:
        raise HTTPException(status_code=400, detail="account_id, audience_list_id, subject, and body_html are all required.")

    account = supabase.table('email_accounts').select('owner_id').eq('id', account_id).single().execute().data
    if not account:
        raise HTTPException(status_code=404, detail="Sending account not found.")
    if account['owner_id'] != user_id:
        raise HTTPException(status_code=403, detail="You don't own this sending account.")

    audience_list = supabase.table('audience_lists').select('*').eq('id', audience_list_id).single().execute().data
    if not audience_list:
        raise HTTPException(status_code=404, detail="Audience segment not found.")

    matched = crm_bridge.resolve_audience_list_contacts(audience_list.get('filter_rules'))
    matched_with_email = [c for c in matched if c.get('email')]
    skipped_no_email = len(matched) - len(matched_with_email)
    if not matched_with_email:
        return {
            'dispatched': False, 'reason': 'no_matching_contacts_with_email',
            'matched': len(matched), 'skipped_no_email': skipped_no_email,
        }

    if '{{unsubscribe_url}}' not in body_html:
        # CRM users typing a quick broadcast aren't expected to know this
        # rule the way someone building a campaign in the Email tool
        # would — append a minimal footer rather than silently refusing
        # to send, same principle as everywhere else that requires it.
        body_html += '\n\n<p style="font-size:12px;color:#888;"><a href="{{unsubscribe_url}}">Unsubscribe</a></p>'

    email_contacts = [sending.get_or_create_contact(account_id, c['email'].strip().lower()) for c in matched_with_email]

    campaign = supabase.table('email_campaigns').insert({
        'account_id': account_id,
        'name': f"CRM dispatch: {subject}"[:120],
        'subject': subject,
        'body_html': body_html,
        'status': 'draft',
    }).execute().data[0]

    rows = [{'campaign_id': campaign['id'], 'contact_id': ec['id'], 'status': 'pending'} for ec in email_contacts]
    for i in range(0, len(rows), 500):
        supabase.table('email_campaign_recipients').insert(rows[i:i + 500]).execute()

    first_batch = _send_one_batch(campaign['id'])
    return {
        'dispatched': True, 'campaign_id': campaign['id'],
        'matched_contacts': len(email_contacts), 'skipped_no_email': skipped_no_email,
        'first_batch': first_batch,
    }


# ---------------------------------------------------------------------------
# Webhook + unsubscribe
# ---------------------------------------------------------------------------

def _suppress(account_id: str, email: str, reason: str):
    supabase.table('email_suppressions').upsert(
        {'account_id': account_id, 'email': email, 'reason': reason},
        on_conflict='account_id,email',
    ).execute()


def _parse_tracking_id(r: str) -> tuple:
    """Tracking ids are '<kind>:<row_id>' as of this change. Anything
    without a colon is a link from BEFORE this change — those already
    exist in delivered inboxes and must keep resolving, so a bare id
    falls back to the original behavior: treat it as a campaign
    recipient id."""
    if ':' in r:
        kind, row_id = r.split(':', 1)
        if kind in _ENGAGEMENT_HANDLERS:
            return kind, row_id
    return 'campaign', r


def _log_campaign_engagement(row_id: str, field: str, event_type: str) -> None:
    recipient = (
        supabase.table('email_campaign_recipients')
        .select(f'id, campaign_id, {field}, email_contacts(email)')
        .eq('id', row_id)
        .single()
        .execute()
        .data
    )
    if not recipient:
        return
    if not recipient.get(field):
        supabase.table('email_campaign_recipients').update(
            {field: datetime.now(timezone.utc).isoformat()}
        ).eq('id', row_id).execute()

    campaign = supabase.table('email_campaigns').select('account_id').eq('id', recipient['campaign_id']).single().execute().data
    if campaign:
        supabase.table('email_events').insert({
            'account_id': campaign['account_id'],
            'contact_email': recipient['email_contacts']['email'],
            'event_type': event_type,
        }).execute()


def _log_denormalized_engagement(table: str, row_id: str, field: str, event_type: str) -> None:
    """Shared by triggers/follow-ups/sequences — all three send-log
    tables carry account_id + contact_email directly (see the
    2026xxxxxx_email_channel_tracking.sql migration), so unlike
    campaigns there's no join needed to find who to attribute the event
    to."""
    row = (
        supabase.table(table)
        .select(f'id, account_id, contact_email, {field}')
        .eq('id', row_id)
        .single()
        .execute()
        .data
    )
    if not row:
        return
    if not row.get(field):
        supabase.table(table).update({field: datetime.now(timezone.utc).isoformat()}).eq('id', row_id).execute()
    if row.get('account_id'):
        supabase.table('email_events').insert({
            'account_id': row['account_id'],
            'contact_email': row['contact_email'],
            'event_type': event_type,
        }).execute()


_ENGAGEMENT_HANDLERS = {
    'campaign': _log_campaign_engagement,
    'trigger': lambda row_id, field, event_type: _log_denormalized_engagement('email_trigger_events', row_id, field, event_type),
    'followup': lambda row_id, field, event_type: _log_denormalized_engagement('campaign_followup_sends', row_id, field, event_type),
    'sequence': lambda row_id, field, event_type: _log_denormalized_engagement('email_sequence_sends', row_id, field, event_type),
}


def _log_engagement_event(tracking_id: str, field: str, event_type: str) -> None:
    """Shared by open + click, across every send channel: stamp the
    right row's opened_at/clicked_at the first time only (so stats count
    unique opens/clicks, not raw hits), and always append to email_events
    for the account-level timeline."""
    kind, row_id = _parse_tracking_id(tracking_id)
    handler = _ENGAGEMENT_HANDLERS.get(kind)
    if not handler:
        print(f"Unknown tracking kind '{kind}' for id '{tracking_id}' — ignoring.")
        return
    handler(row_id, field, event_type)


@router.get("/track/open")
def track_open(r: str, t: str):
    # Never error out of a tracking pixel request — a broken/blocked pixel
    # should just look like a blank image, not a visible failure anywhere.
    if tracking.verify_open_token(r, t):
        try:
            _log_engagement_event(r, 'opened_at', 'opened')
        except Exception as err:
            print(f"Failed to log open event for recipient {r}: {err}")
    return Response(content=_PIXEL_GIF, media_type="image/gif", headers={"Cache-Control": "no-store"})


@router.get("/track/click")
def track_click(r: str, t: str, u: str):
    if not tracking.verify_click_token(r, u, t):
        raise HTTPException(status_code=400, detail="Invalid or expired tracking link.")
    try:
        _log_engagement_event(r, 'clicked_at', 'clicked')
    except Exception as err:
        print(f"Failed to log click event for recipient {r}: {err}")
    return RedirectResponse(url=u, status_code=302)


@router.get("/unsubscribe", response_class=HTMLResponse)
async def unsubscribe(account: str, email: str, token: str = ''):
    if not verify_unsubscribe_token(account, email, token):
        return HTMLResponse("<html><body style='font-family:sans-serif;padding:3rem;text-align:center;'><h2>Invalid or expired unsubscribe link.</h2></body></html>", status_code=400)
    _suppress(account, email, 'unsubscribed')
    supabase.table('email_events').insert({'account_id': account, 'contact_email': email, 'event_type': 'unsubscribed'}).execute()
    return "<html><body style='font-family:sans-serif;padding:3rem;text-align:center;'><h2>You're unsubscribed.</h2><p>You won't receive further emails from this sender.</p></body></html>"