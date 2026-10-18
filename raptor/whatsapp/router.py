"""
router.py — WhatsApp automation: broadcasts, drip sequences, trigger-based
auto-reply, all three sharing the same account/warmup/suppression
foundation as the email module.

PHASE 1 ADDITION (CRM linkage): every send/receive path now also calls
_log_interaction(), which writes into the shared `interactions` table
IF AND ONLY IF the whatsapp_contacts row for that phone/account has a
crm_contact_id (set by the sync_whatsapp_contact_from_crm trigger on the
contacts table — see phase1_crm_linkage_migration.sql). No crm_contact_id
means the number isn't a known CRM contact, so nothing is logged — this
keeps cold-broadcast noise out of the CRM timeline.

Broadcast creation and sequence/step/trigger CRUD are plain Supabase
inserts from the frontend (RLS-protected, no credentials involved) — only
things that touch the Meta access token or actually send a message go
through this router. Same division of labor as the email module.

SEND RULE, enforced by which function you call, not by convention: any
business-initiated send (a broadcast, a sequence step) uses send_template()
— Meta requires a pre-approved template for anything outside the 24h
customer-service window, which a cold broadcast always is. Only a
trigger-based auto-reply or a manual agent reply from the CRM — both fire
in response to (or during) an inbound conversation window — use send_text().

Endpoints:
  POST /accounts                    — create, access_token encrypted server-side
  POST /broadcasts/{id}/send        — one batch right now
  POST /crm/dispatch                — sends the WhatsApp messages the CRM pipeline queued (button / automatic mode)
  POST /sequences/{id}/enroll       — add contacts to a running sequence
  POST /reply                       — manual free-text reply from the CRM ContactPanel
  POST /send-now                    — one message delivered immediately to any number (free text inside the 24h window, or an approved template)
  POST /tick                        — cron-only, advances broadcasts + due sequence steps
  GET  /webhook                     — Meta's one-time verification handshake
  POST /webhook                     — inbound messages: opt-out keywords, trigger matching, status updates
"""
import os
import re
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

import httpx
from fastapi import APIRouter, HTTPException, Depends, Body, Request, Header
from fastapi.responses import PlainTextResponse

from raptor.utility.raptor_auth import get_current_user, supabase, pro_required, _billing_user_id
from . import key_vault
from . import flow_engine
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


@router.post("/accounts", dependencies=[Depends(pro_required)])
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
        'catalog_id': (payload.get('catalog_id') or '').strip() or None,
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


# ---------------------------------------------------------------------------
# CRM linkage helpers (Phase 1)
# ---------------------------------------------------------------------------

def _crm_contact_id_for(account_id: str, phone: str) -> str | None:
    """Looks up whether this account+phone pair is linked to a CRM contact.
    Returns None for numbers that aren't (e.g. a cold broadcast target with
    no matching CRM record) — callers use this to decide whether to log."""
    row = (
        supabase.table('whatsapp_contacts')
        .select('crm_contact_id')
        .eq('account_id', account_id)
        .eq('phone', phone)
        .limit(1)
        .execute()
        .data
    )
    return row[0]['crm_contact_id'] if row and row[0].get('crm_contact_id') else None


def _touch_conversation(account_id: str, phone: str, direction: str, preview: str,
                         crm_contact_id: str | None = None, agent_id: str | None = None) -> str:
    """Upserts the whatsapp_conversations thread for this account+phone and
    returns its id, so the caller can stamp it onto the whatsapp_events row.

    Status rules (Phase 2, no AI flow engine yet — that's Phase 4):
      inbound  -> bumps unread_count; 'resolved' or new conversation reopens
                  to 'waiting' (needs a human to look at it)
      outbound with agent_id -> a human just replied: status 'human', and
                  claims the conversation if nobody has yet
      outbound without agent_id -> an automated send (trigger/broadcast/
                  sequence). If it was 'waiting', this means a trigger just
                  auto-handled it, so it flips back to 'bot'.
    """
    now_iso = datetime.now(timezone.utc).isoformat()
    preview = (preview or '')[:180]
    existing = (
        supabase.table('whatsapp_conversations')
        .select('*')
        .eq('account_id', account_id)
        .eq('contact_phone', phone)
        .limit(1)
        .execute()
        .data
    )

    if existing:
        conv = existing[0]
        updates: dict = {'last_message_at': now_iso, 'last_message_preview': preview}
        if crm_contact_id and not conv.get('crm_contact_id'):
            updates['crm_contact_id'] = crm_contact_id

        if direction == 'inbound':
            updates['unread_count'] = (conv.get('unread_count') or 0) + 1
            if conv['status'] in ('resolved', 'bot'):
                updates['status'] = 'waiting'
        else:
            updates['unread_count'] = 0
            if agent_id:
                updates['status'] = 'human'
                if not conv.get('assigned_agent_id'):
                    updates['assigned_agent_id'] = agent_id
            elif conv['status'] == 'waiting':
                updates['status'] = 'bot'

        supabase.table('whatsapp_conversations').update(updates).eq('id', conv['id']).execute()
        return conv['id']

    row = {
        'account_id': account_id,
        'contact_phone': phone,
        'crm_contact_id': crm_contact_id,
        'last_message_at': now_iso,
        'last_message_preview': preview,
        'unread_count': 1 if direction == 'inbound' else 0,
        'status': 'waiting' if direction == 'inbound' else ('human' if agent_id else 'bot'),
        'assigned_agent_id': agent_id,
    }
    resp = supabase.table('whatsapp_conversations').insert(row).execute()
    return resp.data[0]['id']


def _log_interaction(crm_contact_id: str | None, direction: str, content: str) -> None:
    """Writes a WhatsApp message into the shared `interactions` table so it
    shows up on the CRM contact timeline, and bumps last_interaction_at.
    No-op if crm_contact_id is None (not a known CRM contact)."""
    if not crm_contact_id:
        return
    try:
        supabase.table('interactions').insert({
            'contact_id': crm_contact_id,
            'type': 'whatsapp',
            'direction': direction,
            'content': content or '[template message]',
        }).execute()
        supabase.table('contacts').update({
            'last_interaction_at': datetime.now(timezone.utc).isoformat()
        }).eq('id', crm_contact_id).execute()
    except Exception as err:
        # Never let CRM logging break a send/receive path.
        print(f"Failed to log CRM interaction for contact {crm_contact_id}: {err}")


# ---------------------------------------------------------------------------
# Broadcasts
# ---------------------------------------------------------------------------

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
                preview = f"[Broadcast] {broadcast['template_name']}"
                conversation_id = _touch_conversation(account['id'], contact['phone'], 'outbound', preview, contact.get('crm_contact_id'))
                supabase.table('whatsapp_events').insert({'account_id': account['id'], 'contact_phone': contact['phone'], 'direction': 'outbound', 'event_type': 'sent', 'provider_message_id': message_id, 'conversation_id': conversation_id}).execute()
                _log_interaction(contact.get('crm_contact_id'), 'outbound', f"[Broadcast: {broadcast['name']}] template '{broadcast['template_name']}'")
                sent += 1
            except Exception as err:
                supabase.table('whatsapp_broadcast_recipients').update({'status': 'failed'}).eq('id', recipient['id']).execute()
                failed += 1
                print(f"Failed to send to {contact['phone']}: {err}")

        return {'sent': sent, 'failed': failed, 'skipped_suppressed': skipped}
    finally:
        _release_lock('whatsapp_broadcasts', broadcast_id)


@router.post("/broadcasts/{broadcast_id}/send", dependencies=[Depends(pro_required)])
def trigger_broadcast(broadcast_id: str, user_id: str = Depends(get_current_user)):
    broadcast = supabase.table('whatsapp_broadcasts').select('*, whatsapp_accounts(owner_id)').eq('id', broadcast_id).single().execute().data
    if not broadcast:
        raise HTTPException(status_code=404, detail="Broadcast not found.")
    if broadcast['whatsapp_accounts']['owner_id'] != user_id:
        raise HTTPException(status_code=403, detail="You don't own this broadcast's account.")
    return _send_broadcast_batch(broadcast_id)


# ---------------------------------------------------------------------------
# CRM pipeline: the WhatsApp button and automatic mode
# ---------------------------------------------------------------------------
# The database decides WHETHER a deal's contact gets a message (db/migrations/2026-10-14_crm_whatsapp.sql: modes, consent,
# skip rules) and queues it as a deal_whatsapp row with status 'pending'. Sending needs the encrypted access token, which only
# lives here, so this function does it: the web app calls POST /crm/dispatch whenever a message is waiting.
#
# Rules on top of the queue: the account's own business hours (in ITS timezone) and daily limit, opt-outs checked again
# right before sending, one claim per message so two open tabs can never send it twice, and a message whose outcome is
# unknown (the process died mid-send) is marked failed instead of being sent again.

CRM_BATCH_SIZE = 5
CRM_MAX_ATTEMPTS = 5
CRM_STALE_SENDING_MINUTES = 10


def _account_zone(account: dict) -> ZoneInfo:
    try:
        return ZoneInfo(account.get('timezone') or 'UTC')
    except (ZoneInfoNotFoundError, KeyError, ValueError):
        return ZoneInfo('UTC')


def _within_local_hours(account: dict, now: datetime) -> bool:
    """Business hours judged on the account's own clock. (The older broadcast code compares them with the UTC hour.)"""
    local_hour = now.astimezone(_account_zone(account)).hour
    return account['business_hours_start'] <= local_hour <= account['business_hours_end']


def _meta_error_text(err: Exception) -> str:
    """The reason Meta gave (for example "(#131030) Recipient phone number not in allowed list"), not just "Bad Request"."""
    response = getattr(err, 'response', None)
    if response is not None:
        try:
            detail = response.json().get('error', {})
            message = detail.get('message') or ''
            code = detail.get('code')
            if message:
                return (f"(#{code}) {message}" if code else message)[:300]
        except Exception:
            pass
        return f"WhatsApp refused the message (HTTP {response.status_code})."
    return str(err)[:300] or err.__class__.__name__


def _is_temporary(err: Exception) -> bool:
    """A network problem, Meta being down or rate-limiting: worth trying again. A 4xx other than 429 is a real refusal."""
    response = getattr(err, 'response', None)
    if response is None:
        return isinstance(err, (httpx.TimeoutException, httpx.TransportError))
    return response.status_code == 429 or response.status_code >= 500


def _dispatch_crm_whatsapp(owner_id: str, provider_for=None, now: datetime = None) -> dict:
    provider_for = provider_for or _decrypted_provider
    now = now or datetime.now(timezone.utc)
    table = supabase.table
    result = {'sent': 0, 'failed': 0, 'waiting': 0, 'skipped': 0}

    # A message stuck in 'sending' means the process died mid-send. Whether it went out is unknown, so do not send it again.
    stale = (now - timedelta(minutes=CRM_STALE_SENDING_MINUTES)).isoformat()
    table('deal_whatsapp').update({
        'status': 'failed', 'updated_at': now.isoformat(),
        'error': 'The outcome is unknown (it may or may not have been sent). Check the WhatsApp inbox before retrying.',
    }).eq('owner_id', owner_id).eq('status', 'sending').lt('updated_at', stale).execute()

    rows = (table('deal_whatsapp').select('*').eq('owner_id', owner_id).eq('status', 'pending')
            .order('created_at').limit(CRM_BATCH_SIZE).execute().data) or []

    accounts: dict = {}
    sent_now: dict = {}
    for row in rows:
        def note(text: str, **extra):
            table('deal_whatsapp').update({'error': text, 'updated_at': now.isoformat(), **extra}).eq('deal_id', row['deal_id']).execute()

        account_id = row.get('account_id')
        if account_id not in accounts:
            found = table('whatsapp_accounts').select('*').eq('id', account_id).limit(1).execute().data if account_id else None
            accounts[account_id] = found[0] if found else None
        account = accounts[account_id]
        if not account:
            note('The WhatsApp number for this message is no longer connected.', status='failed')
            result['failed'] += 1
            continue

        blocked = table('whatsapp_suppressions').select('phone').eq('account_id', account['id']).eq('phone', row['to_phone']).limit(1).execute().data
        if blocked:
            note('This person opted out of WhatsApp messages.', status='skipped')
            result['skipped'] += 1
            continue

        if not _within_local_hours(account, now):
            note(f"Waiting for business hours ({account['business_hours_start']:02d}:00 to {account['business_hours_end']:02d}:00 {account.get('timezone') or 'UTC'})")
            result['waiting'] += 1
            continue

        remaining = todays_allowed_volume(account) - _already_sent_today(account['id']) - sent_now.get(account['id'], 0)
        if remaining <= 0:
            note("Today's WhatsApp sending limit is reached; it will go out tomorrow.")
            result['waiting'] += 1
            continue

        # One claim per message: only the caller whose update matches a still-'pending' row may send it.
        claimed = (table('deal_whatsapp').update({'status': 'sending', 'attempts': (row.get('attempts') or 0) + 1, 'error': None, 'updated_at': now.isoformat()})
                   .eq('deal_id', row['deal_id']).eq('status', 'pending').execute().data)
        if not claimed:
            continue

        try:
            provider = provider_for(account)
            message_id = provider.send_template(row['to_phone'], row['template_name'], row.get('template_language') or 'en_US', row.get('params') or [])
        except Exception as err:
            if _is_temporary(err) and (row.get('attempts') or 0) + 1 < CRM_MAX_ATTEMPTS:
                note('A temporary problem stopped this message; it will be tried again.', status='pending')
                result['waiting'] += 1
            else:
                note(_meta_error_text(err), status='failed')
                result['failed'] += 1
                print(f"CRM WhatsApp to {row['to_phone']} failed: {err}")
            continue

        table('deal_whatsapp').update({'status': 'sent', 'message_id': message_id, 'sent_at': now.isoformat(), 'error': None,
                                       'updated_at': now.isoformat()}).eq('deal_id', row['deal_id']).execute()
        sent_now[account['id']] = sent_now.get(account['id'], 0) + 1
        result['sent'] += 1
        try:
            preview = f"[CRM] {row['template_name']}"
            conversation_id = _touch_conversation(account['id'], row['to_phone'], 'outbound', preview, row.get('contact_id'))
            table('whatsapp_events').insert({'account_id': account['id'], 'contact_phone': row['to_phone'], 'direction': 'outbound',
                                             'event_type': 'sent', 'provider_message_id': message_id, 'conversation_id': conversation_id}).execute()
            _log_interaction(row.get('contact_id'), 'outbound', f"[WhatsApp from the pipeline] template '{row['template_name']}'")
        except Exception as err:
            print(f"WhatsApp was sent but logging it failed for {row['to_phone']}: {err}")  # the message is out; never undo that

    left = table('deal_whatsapp').select('deal_id', count='exact').eq('owner_id', owner_id).eq('status', 'pending').execute()
    result['pending_left'] = left.count or 0
    return result


@router.post("/crm/dispatch", dependencies=[Depends(pro_required)])
def crm_dispatch(user_id: str = Depends(get_current_user)):
    """Sends the caller's organization's queued CRM WhatsApp messages (a few at a time). Safe to call as often as you like."""
    return _dispatch_crm_whatsapp(_billing_user_id(user_id))


# ---------------------------------------------------------------------------
# Sequences
# ---------------------------------------------------------------------------

@router.post("/sequences/{sequence_id}/enroll", dependencies=[Depends(pro_required)])
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
            preview = f"[Sequence: {sequence['name']}] step {step_index + 1}"
            conversation_id = _touch_conversation(account['id'], contact['phone'], 'outbound', preview, contact.get('crm_contact_id'))
            supabase.table('whatsapp_events').insert({'account_id': account['id'], 'contact_phone': contact['phone'], 'direction': 'outbound', 'event_type': 'sent', 'provider_message_id': message_id, 'conversation_id': conversation_id}).execute()
            _log_interaction(contact.get('crm_contact_id'), 'outbound', f"[Sequence: {sequence['name']}, step {step_index + 1}] template '{step['template_name']}'")
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


# ---------------------------------------------------------------------------
# Manual reply from the CRM ContactPanel (Phase 1)
# ---------------------------------------------------------------------------

@router.post("/reply", dependencies=[Depends(pro_required)])
def send_manual_reply(payload: dict = Body(...), user_id: str = Depends(get_current_user)):
    """Body: {"account_id": "...", "phone": "...", "text": "..."}

    Free-text send, same rule as trigger auto-replies: only legal within
    Meta's 24h customer-service window (i.e. the contact messaged recently).
    Meta itself will reject the call if the window has closed — we surface
    that as a normal 400 rather than a 500."""
    account_id = str(payload.get('account_id') or '').strip()
    phone = str(payload.get('phone') or '').strip()
    text = str(payload.get('text') or '').strip()
    if not account_id or not phone or not text:
        raise HTTPException(status_code=400, detail="account_id, phone, and text are all required.")

    account = supabase.table('whatsapp_accounts').select('*').eq('id', account_id).single().execute().data
    if not account:
        raise HTTPException(status_code=404, detail="WhatsApp account not found.")
    if account['owner_id'] != user_id:
        raise HTTPException(status_code=403, detail="You don't own this WhatsApp account.")

    is_suppressed = supabase.table('whatsapp_suppressions').select('id').eq('account_id', account_id).eq('phone', phone).limit(1).execute().data
    if is_suppressed:
        raise HTTPException(status_code=400, detail="This contact has opted out — cannot send.")

    try:
        provider = _decrypted_provider(account)
        message_id = provider.send_text(phone, text)
    except Exception as err:
        raise HTTPException(status_code=400, detail=f"Meta rejected this message — the 24-hour reply window may have closed. ({err})")

    crm_contact_id = _crm_contact_id_for(account_id, phone)
    conversation_id = _touch_conversation(account_id, phone, 'outbound', text, crm_contact_id, agent_id=user_id)

    supabase.table('whatsapp_events').insert({
        'account_id': account_id, 'contact_phone': phone, 'direction': 'outbound',
        'event_type': 'sent', 'body_text': text, 'provider_message_id': message_id,
        'conversation_id': conversation_id,
    }).execute()

    _log_interaction(crm_contact_id, 'outbound', text)

    return {'ok': True, 'provider_message_id': message_id}


# ---------------------------------------------------------------------------
# Send one message right now (no scheduler, no queue)
# ---------------------------------------------------------------------------

SEND_NOW_LIMIT, SEND_NOW_WINDOW = 30, 600
_send_now_times: dict = {}
_TEMPLATE_NAME = re.compile(r'^[a-z0-9_]{1,512}$')
_LANGUAGE = re.compile(r'^[a-z]{2,3}(_[A-Za-z]{2})?$')


def _send_now_allowed(user_id: str) -> bool:
    now = datetime.now(timezone.utc).timestamp()
    recent = [t for t in _send_now_times.get(user_id, []) if now - t < SEND_NOW_WINDOW]
    if len(recent) >= SEND_NOW_LIMIT:
        _send_now_times[user_id] = recent
        return False
    _send_now_times[user_id] = recent + [now]
    return True


@router.post("/send-now", dependencies=[Depends(pro_required)])
def send_message_now(payload: dict = Body(...), user_id: str = Depends(get_current_user)):
    """One WhatsApp message, delivered immediately, to any number.

    Body: {"account_id", "phone", "text"}                                  free text: Meta only allows it if that person wrote to you
                                                                           in the last 24 hours
       or {"account_id", "phone", "template": {"name", "language", "params": [...]}}   an approved template: works at any time

    This is the "I want it delivered now" path: nothing is queued and nothing waits for the tick. Opt-outs are still respected (a person who
    wrote STOP is never messaged), and a person may send up to SEND_NOW_LIMIT of these per SEND_NOW_WINDOW seconds."""
    account_id = str(payload.get('account_id') or '').strip()
    phone = re.sub(r'\D', '', str(payload.get('phone') or ''))
    text = str(payload.get('text') or '').strip()
    template = payload.get('template') if isinstance(payload.get('template'), dict) else None
    if not account_id:
        raise HTTPException(status_code=400, detail="Choose which WhatsApp number to send from.")
    if not 8 <= len(phone) <= 15:
        raise HTTPException(status_code=400, detail="Enter the phone number with its country code, for example 919876543210.")
    if bool(text) == bool(template):
        raise HTTPException(status_code=400, detail="Send either a text message or an approved template, not both and not neither.")
    if text and len(text) > 4096:
        raise HTTPException(status_code=400, detail="A WhatsApp message can be up to 4096 characters.")
    name = language = None
    params: list = []
    if template:
        name = str(template.get('name') or '').strip()
        language = str(template.get('language') or 'en_US').strip()
        params = template.get('params') if isinstance(template.get('params'), list) else []
        if not _TEMPLATE_NAME.match(name):
            raise HTTPException(status_code=400, detail="Type the template's name exactly as it appears in WhatsApp Manager (lowercase letters, numbers and underscores).")
        if not _LANGUAGE.match(language):
            raise HTTPException(status_code=400, detail="The template language looks like en_US or hi.")
        params = [str(p).strip()[:1024] for p in params][:10]
        if any(not p for p in params):
            raise HTTPException(status_code=400, detail="Fill in every variable of the template.")

    account = supabase.table('whatsapp_accounts').select('*').eq('id', account_id).limit(1).execute().data
    account = account[0] if account else None
    if not account:
        raise HTTPException(status_code=404, detail="WhatsApp account not found.")
    if account['owner_id'] != user_id:
        raise HTTPException(status_code=403, detail="You don't own this WhatsApp account.")
    if supabase.table('whatsapp_suppressions').select('id').eq('account_id', account_id).eq('phone', phone).limit(1).execute().data:
        raise HTTPException(status_code=400, detail="This person has opted out, so they cannot be messaged.")
    if not _send_now_allowed(user_id):
        raise HTTPException(status_code=429, detail="That is a lot of messages in a short time. Wait a few minutes.")

    try:
        provider = _decrypted_provider(account)
        message_id = provider.send_template(phone, name, language, params) if template else provider.send_text(phone, text)
    except Exception as err:
        if template:
            raise HTTPException(status_code=400, detail=f"Meta did not accept the template. Check its name, language and number of variables against WhatsApp Manager, and that it is approved. ({str(err)[:200]})")
        raise HTTPException(status_code=400, detail=f"Meta did not accept this message. A free text can only be sent within 24 hours of the person's last message: use an approved template instead. ({str(err)[:200]})")

    shown = f"[Template: {name}] " + ", ".join(params) if template else text
    crm_contact_id = _crm_contact_id_for(account_id, phone)
    conversation_id = _touch_conversation(account_id, phone, 'outbound', shown, crm_contact_id, agent_id=user_id)
    supabase.table('whatsapp_events').insert({
        'account_id': account_id, 'contact_phone': phone, 'direction': 'outbound',
        'event_type': 'sent', 'body_text': shown, 'provider_message_id': message_id, 'conversation_id': conversation_id,
    }).execute()
    _log_interaction(crm_contact_id, 'outbound', shown)
    return {'ok': True, 'provider_message_id': message_id, 'mode': 'template' if template else 'text'}


# ---------------------------------------------------------------------------
# Tick (cron)
# ---------------------------------------------------------------------------

def _require_automation_secret(x_automation_secret: str = Header(None)):
    if not AUTOMATION_CRON_SECRET or x_automation_secret != AUTOMATION_CRON_SECRET:
        raise HTTPException(status_code=401, detail="Invalid or missing automation secret.")


@router.post("/tick", dependencies=[Depends(_require_automation_secret)])
def tick():
    active_broadcasts = supabase.table('whatsapp_broadcasts').select('id').eq('status', 'sending').execute().data or []
    broadcast_results = {row['id']: _send_broadcast_batch(row['id']) for row in active_broadcasts}
    sequence_results = _advance_due_enrollments()
    return {'broadcasts_processed': len(active_broadcasts), 'broadcast_results': broadcast_results, 'sequences': sequence_results}


# ---------------------------------------------------------------------------
# Webhook
# ---------------------------------------------------------------------------

@router.get("/webhook")
def verify_webhook(request: Request):
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
                msg_type = message.get('type')

                # Phase 3: a tapped button/list option arrives as an
                # "interactive" message, not "text" — its id is what
                # trigger keywords should match against, while its title
                # is what we show/log as human-readable text.
                if msg_type == 'interactive':
                    interactive = message.get('interactive', {})
                    if interactive.get('type') == 'button_reply':
                        reply = interactive['button_reply']
                    else:
                        reply = interactive.get('list_reply', {})
                    text_body = reply.get('title', '')
                    match_key = (reply.get('id') or '').strip().lower()
                else:
                    text_body = (message.get('text', {}) or {}).get('body', '')
                    match_key = text_body.strip().lower()

                crm_contact_id = _crm_contact_id_for(account_id, from_phone)

                conversation_id = _touch_conversation(account_id, from_phone, 'inbound', text_body, crm_contact_id)
                supabase.table('whatsapp_events').insert({'account_id': account_id, 'contact_phone': from_phone, 'direction': 'inbound', 'event_type': 'received', 'body_text': text_body, 'conversation_id': conversation_id}).execute()
                _log_interaction(crm_contact_id, 'inbound', text_body)

                if match_key in OPT_OUT_KEYWORDS:
                    supabase.table('whatsapp_suppressions').upsert(
                        {'account_id': account_id, 'phone': from_phone, 'reason': 'opted_out'},
                        on_conflict='account_id,phone',
                    ).execute()
                    supabase.table('whatsapp_events').insert({'account_id': account_id, 'contact_phone': from_phone, 'direction': 'inbound', 'event_type': 'opted_out', 'conversation_id': conversation_id}).execute()
                    supabase.table('whatsapp_conversations').update({'status': 'resolved'}).eq('id', conversation_id).execute()
                    continue

                account_row = supabase.table('whatsapp_accounts').select('*').eq('id', account_id).single().execute().data

                # Phase 4: an active flow session takes priority over
                # everything else — the contact is mid-conversation with a
                # bot flow and this message is their answer to it.
                active_session = flow_engine.get_active_session(supabase, account_id, from_phone)
                if active_session:
                    try:
                        decrypted_token = key_vault.decrypt_key(account_row['encrypted_access_token'])
                        provider = get_provider({'phone_number_id': account_row['phone_number_id'], 'access_token': decrypted_token})
                        flow_engine.advance_flow_session(
                            supabase, provider, account_row, from_phone, active_session,
                            match_key, text_body, crm_contact_id, conversation_id,
                            touch_conversation_fn=_touch_conversation,
                            log_interaction_fn=_log_interaction,
                        )
                    except Exception as err:
                        print(f"Flow session advance failed for {from_phone}: {err}")
                    continue

                # No active session — does this message START a flow?
                # Flows are checked before plain keyword triggers; if a
                # message could match both, the flow wins.
                matched_flow = flow_engine.find_flow_for_keyword(supabase, account_id, match_key)
                if matched_flow:
                    start_node_id = flow_engine.get_flow_start_node_id(matched_flow['definition'])
                    if start_node_id:
                        try:
                            decrypted_token = key_vault.decrypt_key(account_row['encrypted_access_token'])
                            provider = get_provider({'phone_number_id': account_row['phone_number_id'], 'access_token': decrypted_token})
                            flow_engine.run_flow(
                                supabase, provider, account_row, from_phone, matched_flow, start_node_id,
                                {}, crm_contact_id, conversation_id, text_body,
                                touch_conversation_fn=_touch_conversation,
                                log_interaction_fn=_log_interaction,
                            )
                        except Exception as err:
                            print(f"Flow start failed for {from_phone}: {err}")
                        continue

                triggers = supabase.table('whatsapp_triggers').select('*').eq('account_id', account_id).eq('is_active', True).execute().data or []
                for trig in triggers:
                    keyword = trig['keyword'].strip().lower()
                    matched = match_key == keyword if trig.get('match_type') == 'exact' else keyword in match_key
                    if matched:
                        try:
                            provider = _decrypted_provider(account_row)
                            reply_kind = trig.get('reply_kind', 'text')
                            payload = trig.get('reply_payload') or {}

                            if reply_kind == 'buttons':
                                message_id = provider.send_interactive_buttons(from_phone, payload.get('body', ''), payload.get('buttons', []))
                                sent_preview = payload.get('body', '')
                            elif reply_kind == 'list':
                                message_id = provider.send_interactive_list(from_phone, payload.get('body', ''), payload.get('button_label', 'View options'), payload.get('rows', []))
                                sent_preview = payload.get('body', '')
                            elif reply_kind == 'catalog':
                                message_id = provider.send_catalog_message(from_phone, payload.get('body', ''), payload.get('thumbnail_product_retailer_id'))
                                sent_preview = payload.get('body', '')
                            elif reply_kind == 'product':
                                if not account_row.get('catalog_id'):
                                    print(f"Skipped product trigger for {from_phone}: account has no catalog_id set.")
                                    break
                                message_id = provider.send_single_product(from_phone, account_row['catalog_id'], payload.get('product_retailer_id', ''))
                                sent_preview = f"[Product: {payload.get('product_retailer_id', '')}]"
                            elif reply_kind == 'product_list':
                                if not account_row.get('catalog_id'):
                                    print(f"Skipped product_list trigger for {from_phone}: account has no catalog_id set.")
                                    break
                                message_id = provider.send_product_list(from_phone, account_row['catalog_id'], payload.get('body', ''), payload.get('sections', []))
                                sent_preview = payload.get('body', '')
                            else:
                                message_id = provider.send_text(from_phone, trig['reply_text'])
                                sent_preview = trig['reply_text']

                            # No agent_id here -> _touch_conversation flips 'waiting' back to
                            # 'bot' since this was handled automatically, not by a human.
                            _touch_conversation(account_id, from_phone, 'outbound', sent_preview, crm_contact_id)
                            supabase.table('whatsapp_events').insert({'account_id': account_id, 'contact_phone': from_phone, 'direction': 'outbound', 'event_type': 'sent', 'provider_message_id': message_id, 'body_text': sent_preview, 'conversation_id': conversation_id}).execute()
                            _log_interaction(crm_contact_id, 'outbound', sent_preview)
                        except Exception as err:
                            print(f"Trigger auto-reply failed for {from_phone}: {err}")
                        break  # first matching trigger wins, not a cascade of replies

            for status_update in value.get('statuses', []):
                recipient_phone = status_update.get('recipient_id', '')
                existing_conv = (
                    supabase.table('whatsapp_conversations')
                    .select('id')
                    .eq('account_id', account_id)
                    .eq('contact_phone', recipient_phone)
                    .limit(1)
                    .execute()
                    .data
                )
                supabase.table('whatsapp_events').insert({
                    'account_id': account_id,
                    'contact_phone': recipient_phone,
                    'direction': 'outbound',
                    'event_type': status_update.get('status', 'unknown'),
                    'provider_message_id': status_update.get('id'),
                    'conversation_id': existing_conv[0]['id'] if existing_conv else None,
                }).execute()

    return {'ok': True}