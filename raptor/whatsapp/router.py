"""
router.py — WhatsApp automation: broadcasts, drip sequences, trigger-based
auto-reply, all three sharing the same account/warmup/suppression
foundation as the email module.

Broadcast creation and sequence/step/trigger CRUD are plain Supabase
inserts from the frontend (RLS-protected, no credentials involved) — only
things that touch the Meta access token or actually send a message go
through this router. Same division of labor as the email module.

SEND RULE, enforced by which function you call, not by convention: any
business-initiated send (a broadcast, a sequence step) uses send_template()
— Meta requires a pre-approved template for anything outside the 24h
customer-service window, which a cold broadcast always is. Only a
trigger-based auto-reply — which by definition fires in response to an
inbound message, so it's inside that window — uses send_text().

Endpoints:
  POST /accounts                    — create, access_token encrypted server-side
  POST /broadcasts/{id}/send        — one batch right now
  POST /sequences/{id}/enroll       — add contacts to a running sequence
  POST /tick                        — cron-only, advances broadcasts + due sequence steps
  GET  /webhook                     — Meta's one-time verification handshake
  POST /webhook                     — inbound messages: opt-out keywords, trigger matching, status updates
"""
import os
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, HTTPException, Depends, Body, Request, Header
from fastapi.responses import PlainTextResponse

from raptor.utility.raptor_auth import get_current_user, supabase
from . import key_vault
from .providers import get_provider
from .warmup import todays_allowed_volume
from .security import verify_meta_webhook, META_WEBHOOK_VERIFY_TOKEN

router = APIRouter()

BATCH_SIZE = 5
LOCK_STALE_MINUTES = 2
AUTOMATION_CRON_SECRET = os.environ.get('AUTOMATION_CRON_SECRET')
OPT_OUT_KEYWORDS = {'stop', 'unsubscribe', 'opt out', 'optout'}


@router.get("/status")
def status():
    return {"tool": "whatsapp-automation", "status": "operational"}


@router.post("/accounts")
def create_account(payload: dict = Body(...), user_id: str = Depends(get_current_user)):
    required = ['label', 'phone_number_id', 'waba_id', 'access_token']
    missing = [f for f in required if not str(payload.get(f, '')).strip()]
    if missing:
        raise HTTPException(status_code=400, detail=f"Missing required field(s): {', '.join(missing)}")

    row = {
        'owner_id': user_id,
        'label': payload['label'].strip(),
        'phone_number_id': payload['phone_number_id'].strip(),
        'waba_id': payload['waba_id'].strip(),
        'encrypted_access_token': key_vault.encrypt_key(payload['access_token'].strip()),
    }
    resp = supabase.table('whatsapp_accounts').insert(row).execute()
    if not resp.data:
        raise HTTPException(status_code=500, detail="Could not save this account.")
    account = resp.data[0]
    account.pop('encrypted_access_token', None)
    return account


def _within_business_hours(account: dict) -> bool:
    now_hour = datetime.now(timezone.utc).hour
    return account['business_hours_start'] <= now_hour <= account['business_hours_end']


def _already_sent_today(account_id: str) -> int:
    today_start = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0).isoformat()
    result = (
        supabase.table('whatsapp_events')
        .select('id', count='exact')
        .eq('account_id', account_id)
        .eq('event_type', 'sent')
        .gte('created_at', today_start)
        .execute()
    )
    return result.count or 0


def _decrypted_provider(account: dict):
    token = key_vault.decrypt_key(account['encrypted_access_token'])
    return get_provider({'phone_number_id': account['phone_number_id'], 'access_token': token})


def _try_acquire_lock(table: str, row_id: str) -> bool:
    stale_cutoff = (datetime.now(timezone.utc) - timedelta(minutes=LOCK_STALE_MINUTES)).isoformat()
    now_iso = datetime.now(timezone.utc).isoformat()
    resp = supabase.table(table).update({'locked_at': now_iso}).eq('id', row_id).or_(f'locked_at.is.null,locked_at.lt.{stale_cutoff}').execute()
    return bool(resp.data)


def _release_lock(table: str, row_id: str) -> None:
    supabase.table(table).update({'locked_at': None}).eq('id', row_id).execute()


def _send_broadcast_batch(broadcast_id: str) -> dict:
    if not _try_acquire_lock('whatsapp_broadcasts', broadcast_id):
        return {'skipped': 'locked_by_another_run'}
    try:
        broadcast = supabase.table('whatsapp_broadcasts').select('*, whatsapp_accounts(*)').eq('id', broadcast_id).single().execute().data
        if not broadcast:
            return {'skipped': 'not_found'}
        account = broadcast['whatsapp_accounts']

        if broadcast['status'] == 'done':
            return {'skipped': 'already_done'}
        if not _within_business_hours(account):
            return {'skipped': 'outside_business_hours'}

        allowed_today = todays_allowed_volume(account)
        sent_today = _already_sent_today(account['id'])
        remaining = allowed_today - sent_today
        if remaining <= 0:
            return {'skipped': 'daily_cap_reached'}

        suppressed = {r['phone'] for r in supabase.table('whatsapp_suppressions').select('phone').eq('account_id', account['id']).execute().data}

        take = min(BATCH_SIZE, remaining)
        query = supabase.table('whatsapp_broadcast_recipients').select('*, whatsapp_contacts(*)').eq('broadcast_id', broadcast_id).eq('status', 'pending')
        if broadcast.get('audience_tag'):
            query = query.contains('whatsapp_contacts.tags', [broadcast['audience_tag']])
        recipients = query.limit(take).execute().data

        if not recipients:
            supabase.table('whatsapp_broadcasts').update({'status': 'done'}).eq('id', broadcast_id).execute()
            return {'skipped': 'no_pending_recipients', 'marked_done': True}

        supabase.table('whatsapp_broadcasts').update({'status': 'sending'}).eq('id', broadcast_id).execute()
        provider = _decrypted_provider(account)

        sent, failed, skipped = 0, 0, 0
        for recipient in recipients:
            contact = recipient['whatsapp_contacts']
            if contact['phone'] in suppressed:
                supabase.table('whatsapp_broadcast_recipients').update({'status': 'skipped_suppressed'}).eq('id', recipient['id']).execute()
                skipped += 1
                continue
            try:
                params = [contact.get('first_name') or 'there'] if broadcast.get('template_params_use_name') else []
                message_id = provider.send_template(contact['phone'], broadcast['template_name'], broadcast.get('template_language', 'en_US'), params)
                supabase.table('whatsapp_broadcast_recipients').update({'status': 'sent', 'provider_message_id': message_id, 'sent_at': datetime.now(timezone.utc).isoformat()}).eq('id', recipient['id']).execute()
                supabase.table('whatsapp_events').insert({'account_id': account['id'], 'contact_phone': contact['phone'], 'direction': 'outbound', 'event_type': 'sent', 'provider_message_id': message_id}).execute()
                sent += 1
            except Exception as err:
                supabase.table('whatsapp_broadcast_recipients').update({'status': 'failed'}).eq('id', recipient['id']).execute()
                failed += 1
                print(f"Failed to send to {contact['phone']}: {err}")

        return {'sent': sent, 'failed': failed, 'skipped_suppressed': skipped}
    finally:
        _release_lock('whatsapp_broadcasts', broadcast_id)


@router.post("/broadcasts/{broadcast_id}/send")
def trigger_broadcast(broadcast_id: str, user_id: str = Depends(get_current_user)):
    broadcast = supabase.table('whatsapp_broadcasts').select('*, whatsapp_accounts(owner_id)').eq('id', broadcast_id).single().execute().data
    if not broadcast:
        raise HTTPException(status_code=404, detail="Broadcast not found.")
    if broadcast['whatsapp_accounts']['owner_id'] != user_id:
        raise HTTPException(status_code=403, detail="You don't own this broadcast's account.")
    return _send_broadcast_batch(broadcast_id)


@router.post("/sequences/{sequence_id}/enroll")
def enroll_contacts(sequence_id: str, payload: dict = Body(...), user_id: str = Depends(get_current_user)):
    """Body: {"contact_ids": ["...", "..."]}"""
    sequence = supabase.table('whatsapp_sequences').select('*, whatsapp_accounts(owner_id)').eq('id', sequence_id).single().execute().data
    if not sequence:
        raise HTTPException(status_code=404, detail="Sequence not found.")
    if sequence['whatsapp_accounts']['owner_id'] != user_id:
        raise HTTPException(status_code=403, detail="You don't own this sequence's account.")

    contact_ids = payload.get('contact_ids') or []
    rows = [{'sequence_id': sequence_id, 'contact_id': cid, 'current_step': 0, 'next_send_at': datetime.now(timezone.utc).isoformat(), 'status': 'active'} for cid in contact_ids]
    if rows:
        supabase.table('whatsapp_sequence_enrollments').upsert(rows, on_conflict='sequence_id,contact_id').execute()
    return {'enrolled': len(rows)}


def _advance_due_enrollments() -> dict:
    now_iso = datetime.now(timezone.utc).isoformat()
    due = (
        supabase.table('whatsapp_sequence_enrollments')
        .select('*, whatsapp_sequences(*, whatsapp_accounts(*)), whatsapp_contacts(*)')
        .eq('status', 'active')
        .lte('next_send_at', now_iso)
        .limit(BATCH_SIZE)
        .execute()
        .data
    )
    processed, sent, failed, suppressed_count = 0, 0, 0, 0

    for enrollment in due:
        sequence = enrollment['whatsapp_sequences']
        account = sequence['whatsapp_accounts']
        contact = enrollment['whatsapp_contacts']
        processed += 1

        is_suppressed = supabase.table('whatsapp_suppressions').select('id').eq('account_id', account['id']).eq('phone', contact['phone']).limit(1).execute().data
        if is_suppressed:
            supabase.table('whatsapp_sequence_enrollments').update({'status': 'stopped'}).eq('id', enrollment['id']).execute()
            suppressed_count += 1
            continue

        steps = supabase.table('whatsapp_sequence_steps').select('*').eq('sequence_id', sequence['id']).order('step_order').execute().data
        step_index = enrollment['current_step']
        if step_index >= len(steps):
            supabase.table('whatsapp_sequence_enrollments').update({'status': 'completed'}).eq('id', enrollment['id']).execute()
            continue

        step = steps[step_index]
        try:
            provider = _decrypted_provider(account)
            message_id = provider.send_template(contact['phone'], step['template_name'], step.get('template_language', 'en_US'), [])
            supabase.table('whatsapp_events').insert({'account_id': account['id'], 'contact_phone': contact['phone'], 'direction': 'outbound', 'event_type': 'sent', 'provider_message_id': message_id}).execute()
            sent += 1

            next_step_index = step_index + 1
            if next_step_index < len(steps):
                delay_hours = steps[next_step_index]['delay_hours']
                next_send_at = (datetime.now(timezone.utc) + timedelta(hours=delay_hours)).isoformat()
                supabase.table('whatsapp_sequence_enrollments').update({'current_step': next_step_index, 'next_send_at': next_send_at}).eq('id', enrollment['id']).execute()
            else:
                supabase.table('whatsapp_sequence_enrollments').update({'current_step': next_step_index, 'status': 'completed'}).eq('id', enrollment['id']).execute()
        except Exception as err:
            failed += 1
            print(f"Sequence step failed for {contact['phone']}: {err}")

    return {'processed': processed, 'sent': sent, 'failed': failed, 'suppressed': suppressed_count}


def _require_automation_secret(x_automation_secret: str = Header(None)):
    if not AUTOMATION_CRON_SECRET or x_automation_secret != AUTOMATION_CRON_SECRET:
        raise HTTPException(status_code=401, detail="Invalid or missing automation secret.")


@router.post("/tick", dependencies=[Depends(_require_automation_secret)])
def tick():
    active_broadcasts = supabase.table('whatsapp_broadcasts').select('id').eq('status', 'sending').execute().data or []
    broadcast_results = {row['id']: _send_broadcast_batch(row['id']) for row in active_broadcasts}
    sequence_results = _advance_due_enrollments()
    return {'broadcasts_processed': len(active_broadcasts), 'broadcast_results': broadcast_results, 'sequences': sequence_results}


@router.get("/webhook")
def verify_webhook(request: Request):
    # Meta calls this with hub.mode / hub.verify_token / hub.challenge query
    # params (dots included) — FastAPI can't declare dotted param names
    # directly, so they're read straight off request.query_params instead.
    mode = request.query_params.get('hub.mode')
    token = request.query_params.get('hub.verify_token')
    challenge = request.query_params.get('hub.challenge')
    if mode == 'subscribe' and token == META_WEBHOOK_VERIFY_TOKEN:
        return PlainTextResponse(challenge or '')
    raise HTTPException(status_code=403, detail="Verification failed.")


@router.post("/webhook")
async def inbound_webhook(request: Request, x_hub_signature_256: str = Header(None)):
    body = await request.body()
    verify_meta_webhook(body, x_hub_signature_256)
    payload = await request.json()

    for entry in payload.get('entry', []):
        for change in entry.get('changes', []):
            value = change.get('value', {})
            phone_number_id = value.get('metadata', {}).get('phone_number_id')
            account = supabase.table('whatsapp_accounts').select('id').eq('phone_number_id', phone_number_id).single().execute().data if phone_number_id else None
            if not account:
                continue
            account_id = account['id']

            for message in value.get('messages', []):
                from_phone = message.get('from')
                text_body = (message.get('text', {}) or {}).get('body', '')
                supabase.table('whatsapp_events').insert({'account_id': account_id, 'contact_phone': from_phone, 'direction': 'inbound', 'event_type': 'received', 'body_text': text_body}).execute()

                normalized = text_body.strip().lower()
                if normalized in OPT_OUT_KEYWORDS:
                    supabase.table('whatsapp_suppressions').upsert(
                        {'account_id': account_id, 'phone': from_phone, 'reason': 'opted_out'},
                        on_conflict='account_id,phone',
                    ).execute()
                    supabase.table('whatsapp_events').insert({'account_id': account_id, 'contact_phone': from_phone, 'direction': 'inbound', 'event_type': 'opted_out'}).execute()
                    continue

                triggers = supabase.table('whatsapp_triggers').select('*').eq('account_id', account_id).eq('is_active', True).execute().data or []
                for trig in triggers:
                    keyword = trig['keyword'].strip().lower()
                    matched = normalized == keyword if trig.get('match_type') == 'exact' else keyword in normalized
                    if matched:
                        account_row = supabase.table('whatsapp_accounts').select('*').eq('id', account_id).single().execute().data
                        try:
                            provider = _decrypted_provider(account_row)
                            message_id = provider.send_text(from_phone, trig['reply_text'])
                            supabase.table('whatsapp_events').insert({'account_id': account_id, 'contact_phone': from_phone, 'direction': 'outbound', 'event_type': 'sent', 'provider_message_id': message_id}).execute()
                        except Exception as err:
                            print(f"Trigger auto-reply failed for {from_phone}: {err}")
                        break  # first matching trigger wins, not a cascade of replies

            for status_update in value.get('statuses', []):
                supabase.table('whatsapp_events').insert({
                    'account_id': account_id,
                    'contact_phone': status_update.get('recipient_id', ''),
                    'direction': 'outbound',
                    'event_type': status_update.get('status', 'unknown'),
                    'provider_message_id': status_update.get('id'),
                }).execute()

    return {'ok': True}
