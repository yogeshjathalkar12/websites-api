"""
branching.py — "if opened, send X; if not, send Y" follow-ups keyed off
a single campaign's own engagement data (email_campaign_recipients'
opened_at / clicked_at columns, added when open/click tracking was
built). Each campaign_followups row is one branch: a condition, a wait
period, and the email to send when that condition matches.

Deliberately scoped to campaigns, not a general step-N-of-a-sequence
engine — that's what a workflow builder would be for, and it isn't
built yet. What's here is simpler and stands on its own: each followup
rule is evaluated EXACTLY ONCE per recipient, wait_hours after that
recipient's original send. The result — sent, not applicable (condition
didn't match), or skipped — is permanently recorded in
campaign_followup_sends. That one-shot recording matters: without it, a
'not_opened' condition would keep matching forever (it's still true
every single tick until the day they open it), so nothing would stop it
from re-sending on every cron run.

Known edge case, accepted rather than solved here: a recipient could
open the original email in the gap between "condition met, locked in as
true" and the actual send going out (e.g. blocked briefly by a full
daily cap). The follow-up would still go out on the 'not_opened' branch
even though they've since opened it. Rare, and fixing it would mean
re-checking the condition at send time instead of at evaluation time —
worth revisiting if it turns out to matter in practice, not before.
"""
import os
import uuid
from datetime import datetime, timedelta, timezone

from raptor.utility.raptor_auth import supabase
from . import tracking
from .spintax import render_email
from .sending import unsubscribe_url, get_ready_provider
from .warmup import todays_allowed_volume, sent_today_count, within_business_hours

CONDITION_CHECKS = {
    'opened': lambda r: bool(r.get('opened_at')),
    'not_opened': lambda r: not r.get('opened_at'),
    'clicked': lambda r: bool(r.get('clicked_at')),
    'not_clicked': lambda r: not r.get('clicked_at'),
}


def _mark_evaluated(followup_id: str, recipient_id: str, condition_met: bool, status: str,
                     account_id: str | None = None, contact_email: str | None = None,
                     sent_at: str | None = None, send_id: str | None = None) -> None:
    row = {
        'followup_id': followup_id,
        'recipient_id': recipient_id,
        'condition_met': condition_met,
        'status': status,
        'account_id': account_id,
        'contact_email': contact_email,
        'sent_at': sent_at,
    }
    if send_id:
        # Pre-generated before rendering so the tracking pixel/links can
        # embed the same id this row ends up with — see process_due_followups.
        row['id'] = send_id
    supabase.table('campaign_followup_sends').insert(row).execute()


def process_due_followups(limit: int = 100) -> dict:
    """Cron-only, same rhythm as /tick and /trigger-tick. Walks every
    active followup rule, finds recipients of its source campaign who
    are past wait_hours and haven't been evaluated for this rule yet,
    and resolves each one: skip (condition not met / suppressed / no
    unsubscribe link) or send."""
    results = {
        'sent': 0, 'not_applicable': 0, 'skipped_suppressed': 0,
        'skipped_missing_unsubscribe': 0, 'skipped_no_capacity': 0, 'failed': 0,
    }

    followups = (
        supabase.table('campaign_followups')
        .select('*, email_campaigns(id, account_id, email_accounts(*))')
        .eq('is_active', True)
        .execute()
        .data
    ) or []

    processed = 0
    for followup in followups:
        if processed >= limit:
            break

        condition_check = CONDITION_CHECKS.get(followup['condition'])
        if not condition_check:
            print(f"Follow-up {followup['id']} has an unknown condition '{followup['condition']}' — skipping.")
            continue

        campaign = followup['email_campaigns']
        account = campaign['email_accounts']
        cutoff = (datetime.now(timezone.utc) - timedelta(hours=followup['wait_hours'])).isoformat()

        eligible = (
            supabase.table('email_campaign_recipients')
            .select('*, email_contacts(*)')
            .eq('campaign_id', campaign['id'])
            .eq('status', 'sent')
            .lte('sent_at', cutoff)
            .limit(limit)
            .execute()
            .data
        ) or []
        if not eligible:
            continue

        already_done = {
            row['recipient_id'] for row in
            supabase.table('campaign_followup_sends').select('recipient_id').eq('followup_id', followup['id']).execute().data
        }
        suppressed_emails = {
            row['email'] for row in
            supabase.table('email_suppressions').select('email').eq('account_id', account['id']).execute().data
        }

        for recipient in eligible:
            if processed >= limit:
                break
            if recipient['id'] in already_done:
                continue

            contact = recipient['email_contacts']

            condition_met = condition_check(recipient)
            if not condition_met:
                _mark_evaluated(followup['id'], recipient['id'], False, 'not_applicable',
                                 account_id=account['id'], contact_email=contact['email'])
                results['not_applicable'] += 1
                processed += 1
                continue

            if contact['email'] in suppressed_emails:
                _mark_evaluated(followup['id'], recipient['id'], True, 'skipped_suppressed',
                                 account_id=account['id'], contact_email=contact['email'])
                results['skipped_suppressed'] += 1
                processed += 1
                continue

            if not followup.get('is_transactional') and '{{unsubscribe_url}}' not in followup['body_html']:
                _mark_evaluated(followup['id'], recipient['id'], True, 'skipped_missing_unsubscribe',
                                 account_id=account['id'], contact_email=contact['email'])
                results['skipped_missing_unsubscribe'] += 1
                processed += 1
                continue

            if not followup.get('is_transactional'):
                # Capacity/hours blocks are left UNRECORDED on purpose —
                # no campaign_followup_sends row means a later tick will
                # try this recipient again, same as triggers.py does.
                if not within_business_hours(account):
                    continue
                if sent_today_count(account) >= todays_allowed_volume(account):
                    results['skipped_no_capacity'] += 1
                    continue

            unsub_link = unsubscribe_url(account['id'], contact['email'])
            subject = render_email(followup['subject'], contact, unsub_link)
            body = render_email(followup['body_html'], contact, unsub_link)

            # Generated before rendering so it can be embedded in the
            # tracking pixel/links, then reused as this row's actual id
            # when it's inserted below — no campaign_followup_sends row
            # exists yet at this point, unlike triggers.py where the row
            # was already created back when the event was enqueued.
            send_id = str(uuid.uuid4())
            body = tracking.wrap_links(body, f"followup:{send_id}", os.environ['APP_BASE_URL'])
            body += tracking.open_pixel_tag(f"followup:{send_id}", os.environ['APP_BASE_URL'])

            try:
                provider = get_ready_provider(account)
                message_id = provider.send(account['from_email'], account['from_name'], contact['email'], subject, body)
                _mark_evaluated(followup['id'], recipient['id'], True, 'sent',
                                 account_id=account['id'], contact_email=contact['email'],
                                 sent_at=datetime.now(timezone.utc).isoformat(), send_id=send_id)
                supabase.table('email_events').insert({
                    'account_id': account['id'], 'contact_email': contact['email'],
                    'event_type': 'followup_sent', 'provider_message_id': message_id,
                }).execute()
                results['sent'] += 1
            except Exception as err:
                _mark_evaluated(followup['id'], recipient['id'], True, 'failed',
                                 account_id=account['id'], contact_email=contact['email'], send_id=send_id)
                results['failed'] += 1
                print(f"Follow-up send failed for {contact['email']}: {err}")

            processed += 1

    return results