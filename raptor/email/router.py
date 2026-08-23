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
  POST /accounts           — create account, api_key encrypted server-side
  POST /campaigns/{id}/send — process one batch right now (manual "Send Now")
  POST /tick                — cron-only, advances every sending campaign one batch
  POST /webhooks/resend     — signature-verified bounce/complaint handling
  GET  /unsubscribe         — token-verified suppression
"""
import os
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, HTTPException, Depends, Body, Request, Header
from fastapi.responses import HTMLResponse

from raptor.utility.raptor_auth import get_current_user, supabase
from . import key_vault
from .providers import get_provider
from .spintax import render_email
from .warmup import todays_allowed_volume
from .security import sign_unsubscribe_token, verify_unsubscribe_token, verify_resend_webhook

router = APIRouter()

BATCH_SIZE = 3
LOCK_STALE_MINUTES = 2  # short — batches finish in seconds now, not minutes
AUTOMATION_CRON_SECRET = os.environ.get('AUTOMATION_CRON_SECRET')  # same secret automations_router.py uses


@router.get("/status")
def status():
    return {"tool": "email-automation", "status": "operational"}


# ---------------------------------------------------------------------------
# Accounts
# ---------------------------------------------------------------------------

@router.post("/accounts")
def create_account(payload: dict = Body(...), user_id: str = Depends(get_current_user)):
    required = ['label', 'from_email', 'from_name', 'api_key']
    missing = [f for f in required if not str(payload.get(f, '')).strip()]
    if missing:
        raise HTTPException(status_code=400, detail=f"Missing required field(s): {', '.join(missing)}")

    row = {
        'owner_id': user_id,
        'label': payload['label'].strip(),
        'provider': payload.get('provider', 'resend'),
        'from_email': payload['from_email'].strip(),
        'from_name': payload['from_name'].strip(),
        'encrypted_api_key': key_vault.encrypt_key(payload['api_key'].strip()),
        'smtp_config': payload.get('smtp_config'),
    }
    resp = supabase.table('email_accounts').insert(row).execute()
    if not resp.data:
        raise HTTPException(status_code=500, detail="Could not save this account.")
    account = resp.data[0]
    account.pop('encrypted_api_key', None)
    return account


# ---------------------------------------------------------------------------
# Sending — shared batch logic used by both the manual trigger and /tick
# ---------------------------------------------------------------------------

def _within_business_hours(account: dict) -> bool:
    now_hour = datetime.now(timezone.utc).hour
    return account['business_hours_start'] <= now_hour <= account['business_hours_end']


def _already_sent_today(account_id: str) -> int:
    today_start = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0).isoformat()
    result = (
        supabase.table('email_events')
        .select('id', count='exact')
        .eq('account_id', account_id)
        .eq('event_type', 'sent')
        .gte('created_at', today_start)
        .execute()
    )
    return result.count or 0


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

        if '{{unsubscribe_url}}' not in campaign['body_html']:
            return {'skipped': 'missing_unsubscribe_placeholder'}
        if campaign['status'] == 'done':
            return {'skipped': 'already_done'}
        if not _within_business_hours(account):
            return {'skipped': 'outside_business_hours'}

        allowed_today = todays_allowed_volume(account)
        sent_today = _already_sent_today(account['id'])
        remaining = allowed_today - sent_today
        if remaining <= 0:
            return {'skipped': 'daily_cap_reached', 'sent_today': sent_today, 'allowed_today': allowed_today}

        suppressed = {
            row['email'] for row in
            supabase.table('email_suppressions').select('email').eq('account_id', account['id']).execute().data
        }

        take = min(BATCH_SIZE, remaining)
        query = supabase.table('email_campaign_recipients').select('*, email_contacts(*)').eq('campaign_id', campaign_id).eq('status', 'pending')
        if campaign.get('audience_tag'):
            query = query.contains('email_contacts.tags', [campaign['audience_tag']])
        recipients = query.limit(take).execute().data

        if not recipients:
            supabase.table('email_campaigns').update({'status': 'done'}).eq('id', campaign_id).execute()
            return {'skipped': 'no_pending_recipients', 'campaign_marked_done': True}

        supabase.table('email_campaigns').update({'status': 'sending'}).eq('id', campaign_id).execute()

        decrypted_account = dict(account)
        decrypted_account['api_key'] = key_vault.decrypt_key(account['encrypted_api_key']) if account.get('encrypted_api_key') else None
        provider = get_provider(decrypted_account)

        sent, failed, skipped = 0, 0, 0
        for recipient in recipients:
            contact = recipient['email_contacts']
            if contact['email'] in suppressed:
                supabase.table('email_campaign_recipients').update({'status': 'skipped_suppressed'}).eq('id', recipient['id']).execute()
                skipped += 1
                continue

            token = sign_unsubscribe_token(account['id'], contact['email'])
            unsubscribe_url = f"{os.environ['APP_BASE_URL']}/unsubscribe?account={account['id']}&email={contact['email']}&token={token}"
            subject = render_email(campaign['subject'], contact, unsubscribe_url)
            body = render_email(campaign['body_html'], contact, unsubscribe_url)

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
            except Exception as err:
                supabase.table('email_campaign_recipients').update({'status': 'failed'}).eq('id', recipient['id']).execute()
                failed += 1
                print(f"Failed to send to {contact['email']}: {err}")

        return {'sent': sent, 'failed': failed, 'skipped_suppressed': skipped}
    finally:
        _release_lock(campaign_id)


@router.post("/campaigns/{campaign_id}/send")
def trigger_send(campaign_id: str, user_id: str = Depends(get_current_user)):
    campaign = supabase.table('email_campaigns').select('*, email_accounts(owner_id)').eq('id', campaign_id).single().execute().data
    if not campaign:
        raise HTTPException(status_code=404, detail="Campaign not found.")
    if campaign['email_accounts']['owner_id'] != user_id:
        raise HTTPException(status_code=403, detail="You don't own this campaign's sending account.")
    return _send_one_batch(campaign_id)


def _require_automation_secret(x_automation_secret: str = Header(None)):
    if not AUTOMATION_CRON_SECRET or x_automation_secret != AUTOMATION_CRON_SECRET:
        raise HTTPException(status_code=401, detail="Invalid or missing automation secret.")


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
# Webhook + unsubscribe
# ---------------------------------------------------------------------------

def _suppress(account_id: str, email: str, reason: str):
    supabase.table('email_suppressions').upsert(
        {'account_id': account_id, 'email': email, 'reason': reason},
        on_conflict='account_id,email',
    ).execute()


@router.post("/webhooks/resend")
async def resend_webhook(request: Request):
    body = await request.body()
    verify_resend_webhook(body, dict(request.headers))
    payload = await request.json()
    event_type = payload.get('type')
    data = payload.get('data', {})
    to_list = data.get('to', [])
    email = to_list[0] if to_list else None

    event_row = (
        supabase.table('email_events')
        .select('account_id')
        .eq('provider_message_id', data.get('email_id'))
        .limit(1)
        .execute()
        .data
    )
    account_id = event_row[0]['account_id'] if event_row else None

    if account_id and email:
        if event_type == 'email.bounced':
            _suppress(account_id, email, 'bounced')
            supabase.table('email_events').insert({'account_id': account_id, 'contact_email': email, 'event_type': 'bounced'}).execute()
        elif event_type == 'email.complained':
            _suppress(account_id, email, 'complained')
            supabase.table('email_events').insert({'account_id': account_id, 'contact_email': email, 'event_type': 'complained'}).execute()

    return {'ok': True}


@router.get("/unsubscribe", response_class=HTMLResponse)
async def unsubscribe(account: str, email: str, token: str = ''):
    if not verify_unsubscribe_token(account, email, token):
        return HTMLResponse("<html><body style='font-family:sans-serif;padding:3rem;text-align:center;'><h2>Invalid or expired unsubscribe link.</h2></body></html>", status_code=400)
    _suppress(account, email, 'unsubscribed')
    supabase.table('email_events').insert({'account_id': account, 'contact_email': email, 'event_type': 'unsubscribed'}).execute()
    return "<html><body style='font-family:sans-serif;padding:3rem;text-align:center;'><h2>You're unsubscribed.</h2><p>You won't receive further emails from this sender.</p></body></html>"
