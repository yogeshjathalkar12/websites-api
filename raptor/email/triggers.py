"""
triggers.py — event-driven single-recipient sends ("behavioral
triggers"): signup, cart abandoned, purchase, or anything else your CRM
or an outside system reports. Two pieces of an event drive the whole
thing — account_id (whose triggers to check) and event_key (which
trigger(s) care) — everything else is optional context (order total,
checkout URL, whatever) passed straight through as merge fields.

Kept deliberately separate from the campaign batch-sending path in
router.py: a campaign fans ONE message out to MANY pre-selected
recipients; a trigger fans out to exactly ONE contact the moment (or
shortly after) an event happens. They share the provider/rendering/
suppression building blocks below but the selection and scheduling logic
is different enough to earn its own file.

emit_event() is the single entry point for two different callers:
  - Your own CRM code, same process, calling it as a plain function —
    e.g. from wherever a contact row gets created:
        from raptor.email.triggers import emit_event
        emit_event(account_id, 'signup', contact['email'])
  - The /events/webhook/{account_id} route in router.py, for anything
    outside this process (Shopify, Stripe, etc.), after event_sources.py
    has normalized the payload into the same shape.

emit_event() only ever enqueues a row in email_trigger_events — it never
sends synchronously, so a slow or retried webhook can't block on mail
delivery. process_due_trigger_events() is the cron-driven half that
actually acts on it; point your scheduler at it (see /trigger-tick in
router.py) the same way you already do for /tick.

A trigger's action_type is either:
  - 'send_email' (default) — renders and sends the trigger's own
    subject/body_html, same as before.
  - 'enroll_sequence' — enrolls the contact into target_sequence_id
    instead. No email goes out from this code path at all; the
    sequence's own steps and its own cron (sequence-tick) handle
    sending from there on, with their own capacity/business-hours
    gating. This is what lets a single 'signup' trigger kick off a
    whole nurture sequence instead of only ever firing one email.
"""
import os
from datetime import datetime, timedelta, timezone

from raptor.utility.raptor_auth import supabase
from . import tracking
from . import sequences
from .spintax import render_email
from .sending import unsubscribe_url, get_ready_provider, get_or_create_contact
from .warmup import todays_allowed_volume, sent_today_count, within_business_hours


def emit_event(account_id: str, event_key: str, contact_email: str,
                payload: dict | None = None, external_event_id: str | None = None) -> dict:
    contact_email = (contact_email or '').strip().lower()
    if not contact_email:
        return {'event_key': event_key, 'matched_triggers': 0, 'enqueued': 0, 'skipped': 'no_contact_email'}

    payload = payload or {}
    triggers = (
        supabase.table('email_triggers')
        .select('id, delay_minutes')
        .eq('account_id', account_id)
        .eq('event_key', event_key)
        .eq('is_active', True)
        .execute()
        .data
    ) or []

    enqueued = 0
    for trig in triggers:
        scheduled_for = (datetime.now(timezone.utc) + timedelta(minutes=trig['delay_minutes'])).isoformat()
        row = {
            'trigger_id': trig['id'],
            'account_id': account_id,
            'contact_email': contact_email,
            'external_event_id': external_event_id,
            'payload': payload,
            'scheduled_for': scheduled_for,
            'status': 'pending',
        }
        try:
            # external_event_id + trigger_id has a unique constraint, so
            # a retried webhook delivery can't double-enqueue the same
            # event. A unique-violation here is expected and fine to
            # swallow; anything else, log it and keep processing the
            # remaining matched triggers.
            resp = supabase.table('email_trigger_events').insert(row).execute()
            if resp.data:
                enqueued += 1
        except Exception as err:
            print(f"Skipping trigger {trig['id']} for event '{event_key}' ({contact_email}): {err}")

    return {'event_key': event_key, 'matched_triggers': len(triggers), 'enqueued': enqueued}


def process_due_trigger_events(limit: int = 25) -> dict:
    """Cron-only — mirrors router.py's /tick. Sends every trigger event
    whose scheduled_for has passed. Anything skipped for capacity or
    business-hours reasons is left 'pending' so the next tick retries it,
    same as campaigns waiting out a daily cap."""
    now_iso = datetime.now(timezone.utc).isoformat()
    due = (
        supabase.table('email_trigger_events')
        .select('*, email_triggers(*, email_accounts(*))')
        .eq('status', 'pending')
        .lte('scheduled_for', now_iso)
        .limit(limit)
        .execute()
        .data
    ) or []

    results = {'sent': 0, 'failed': 0, 'skipped_suppressed': 0, 'skipped_no_capacity': 0, 'skipped_inactive': 0, 'skipped_missing_unsubscribe': 0}

    for event in due:
        trigger = event['email_triggers']
        account = trigger['email_accounts']

        if not trigger['is_active']:
            supabase.table('email_trigger_events').update({'status': 'skipped_inactive'}).eq('id', event['id']).execute()
            results['skipped_inactive'] += 1
            continue

        # Suppression applies to BOTH actions — a suppressed contact
        # shouldn't be enrolled into a sequence any more than they
        # should get a direct email. Moved ahead of the send_email-only
        # checks below (previously ran after them); the only observable
        # difference is which status wins when a non-transactional
        # trigger is both missing {{unsubscribe_url}} AND suppressed —
        # suppression now takes priority, which is the right call.
        suppressed = (
            supabase.table('email_suppressions')
            .select('email')
            .eq('account_id', account['id'])
            .eq('email', event['contact_email'])
            .execute()
            .data
        )
        if suppressed:
            supabase.table('email_trigger_events').update({'status': 'skipped_suppressed'}).eq('id', event['id']).execute()
            results['skipped_suppressed'] += 1
            continue

        action_type = trigger.get('action_type', 'send_email')

        if action_type == 'enroll_sequence':
            sequence_id = trigger.get('target_sequence_id')
            if not sequence_id:
                supabase.table('email_trigger_events').update({'status': 'failed'}).eq('id', event['id']).execute()
                results['failed'] += 1
                print(f"Trigger {trigger['id']} is action_type=enroll_sequence but has no target_sequence_id — marking event failed.")
                continue

            contact = get_or_create_contact(account['id'], event['contact_email'])
            # Enrolling doesn't send anything itself — that's
            # sequences.process_due_sequence_steps()'s job, on its own
            # cron tick, with its own capacity/business-hours checks. So
            # none of the send_email-specific gating below applies here.
            sequences.enroll_contacts(sequence_id, [contact['id']])
            supabase.table('email_trigger_events').update({
                'status': 'sent', 'sent_at': datetime.now(timezone.utc).isoformat(),
            }).eq('id', event['id']).execute()
            supabase.table('email_events').insert({
                'account_id': account['id'], 'contact_email': contact['email'],
                'event_type': 'trigger_enrolled_sequence',
            }).execute()
            results['sent'] += 1
            continue

        # action_type == 'send_email' — everything below is unchanged.
        if not trigger.get('is_transactional'):
            if '{{unsubscribe_url}}' not in trigger['body_html']:
                # Same rule campaigns already enforce in router.py — a
                # non-transactional trigger is still marketing mail and
                # needs an unsubscribe path. Transactional triggers
                # (receipts, welcome emails) are exempt, same as
                # real-world CAN-SPAM/GDPR practice.
                supabase.table('email_trigger_events').update({'status': 'skipped_missing_unsubscribe'}).eq('id', event['id']).execute()
                results['skipped_missing_unsubscribe'] += 1
                continue
            if not within_business_hours(account):
                continue  # stays 'pending' — a later tick catches it once hours open
            if sent_today_count(account) >= todays_allowed_volume(account):
                results['skipped_no_capacity'] += 1
                continue

        contact = get_or_create_contact(account['id'], event['contact_email'])
        unsub_link = unsubscribe_url(account['id'], contact['email'])

        subject = render_email(trigger['subject'], contact, unsub_link, extra_fields=event['payload'])
        body = render_email(trigger['body_html'], contact, unsub_link, extra_fields=event['payload'])
        # event['id'] already exists (this row was created back in
        # emit_event()) — no need to pre-generate anything, unlike
        # branching.py/sequences.py where the send-log row doesn't exist
        # until after the send attempt.
        body = tracking.wrap_links(body, f"trigger:{event['id']}", os.environ['APP_BASE_URL'])
        body += tracking.open_pixel_tag(f"trigger:{event['id']}", os.environ['APP_BASE_URL'])

        try:
            provider = get_ready_provider(account)
            message_id = provider.send(account['from_email'], account['from_name'], contact['email'], subject, body)

            supabase.table('email_trigger_events').update({
                'status': 'sent', 'sent_at': datetime.now(timezone.utc).isoformat(),
            }).eq('id', event['id']).execute()
            supabase.table('email_events').insert({
                'account_id': account['id'], 'contact_email': contact['email'],
                'event_type': 'trigger_sent', 'provider_message_id': message_id,
            }).execute()
            results['sent'] += 1
        except Exception as err:
            supabase.table('email_trigger_events').update({'status': 'failed'}).eq('id', event['id']).execute()
            results['failed'] += 1
            print(f"Trigger send failed for {event['contact_email']}: {err}")

    return results