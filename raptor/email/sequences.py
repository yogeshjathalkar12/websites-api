"""
sequences.py — multi-step drip sequences: a person is enrolled once,
then walks through an ordered list of emails automatically, each one
gated by its own delay_hours since the previous step (or since
enrollment, for step 0).

This is the general case triggers.py and branching.py deliberately
aren't: those are each a single decision point (one event -> one email,
or one condition -> one email). A sequence is N emails in order. The
schema mirrors what's already built for WhatsApp (whatsapp_sequences /
whatsapp_sequence_steps / whatsapp_sequence_enrollments) rather than
inventing a new shape for the second channel that needs the same idea.

Someone gets INTO a sequence via enroll_contacts() below, called from
router.py's /sequences/{id}/enroll — either an explicit list of emails
or everyone matching an audience tag. There's deliberately no automatic
trigger -> sequence wiring yet; that's the natural next connection point
(a trigger's "action" becoming "enroll in sequence" instead of "send
this one email") once this stands on its own.

process_due_sequence_steps() is the cron-driven half, same rhythm as
/tick, /trigger-tick, /followup-tick.

BRANCHING: a step can optionally route to a DIFFERENT next step
depending on whether it was opened/clicked, instead of always advancing
linearly. This is implemented as a two-phase wait, not a new state
representation — current_step stays a plain integer index into the same
ordered steps list as always; a branch just means "jump this index to
an arbitrary position" instead of "always +1". The two phases:
  1. SEND phase (awaiting_branch_evaluation=False, the default/original
     behavior): send steps[current_step]. If that step has
     branch_wait_hours set, don't advance yet — flip to phase 2 instead.
  2. EVALUATE phase (awaiting_branch_evaluation=True): check the sent
     step's opened_at/clicked_at, match it against that step's
     email_sequence_step_branches rows, and jump current_step to
     whichever step the matching rule points at (or complete, if the
     rule points nowhere, or if no rule matches at all — same graceful
     fallback to linear order a step with no branching gets).

Both phases are picked up by the exact same due-enrollments query
(status='active', next_send_at<=now) — the loop just checks
awaiting_branch_evaluation to decide which phase it's in.

Known limitation, accepted rather than solved here: a branch's
next_step_id can point ANYWHERE, including backward at an earlier step
— nothing here prevents an infinite loop (step 5 branches back to step
2 forever). That's a real risk for a badly-designed sequence; worth
adding a hard cap (e.g. max N total sends per enrollment) if it turns
out to matter in practice, not before.
"""
import os
import uuid
from datetime import datetime, timedelta, timezone

from raptor.utility.raptor_auth import supabase
from . import tracking
from .spintax import render_email
from .sending import unsubscribe_url, get_ready_provider
from .warmup import todays_allowed_volume, sent_today_count, within_business_hours


def enroll_contacts(sequence_id: str, contact_ids: list) -> dict:
    steps = (
        supabase.table('email_sequence_steps')
        .select('step_order, delay_hours')
        .eq('sequence_id', sequence_id)
        .order('step_order')
        .execute()
        .data
    ) or []
    if not steps:
        return {'enrolled': 0, 'skipped': 0, 'error': 'sequence_has_no_steps'}

    contact_ids = list(dict.fromkeys(contact_ids))  # de-dupe, keep order
    if not contact_ids:
        return {'enrolled': 0, 'skipped': 0}

    existing_active = {
        row['contact_id'] for row in
        supabase.table('email_sequence_enrollments')
        .select('contact_id')
        .eq('sequence_id', sequence_id)
        .eq('status', 'active')
        .in_('contact_id', contact_ids)
        .execute()
        .data
    }
    to_enroll = [cid for cid in contact_ids if cid not in existing_active]
    if not to_enroll:
        return {'enrolled': 0, 'skipped': len(contact_ids)}

    first_delay = steps[0]['delay_hours']
    next_send_at = (datetime.now(timezone.utc) + timedelta(hours=first_delay)).isoformat()
    rows = [
        {'sequence_id': sequence_id, 'contact_id': cid, 'current_step': 0, 'next_send_at': next_send_at, 'status': 'active'}
        for cid in to_enroll
    ]
    supabase.table('email_sequence_enrollments').insert(rows).execute()
    return {'enrolled': len(to_enroll), 'skipped': len(contact_ids) - len(to_enroll)}


CONDITION_CHECKS = {
    'opened': lambda r: bool(r.get('opened_at')),
    'not_opened': lambda r: not r.get('opened_at'),
    'clicked': lambda r: bool(r.get('clicked_at')),
    'not_clicked': lambda r: not r.get('clicked_at'),
}


def _step_index_by_id(steps: list, step_id: str):
    for i, s in enumerate(steps):
        if s['id'] == step_id:
            return i
    return None


def _end_enrollment(enrollment_id: str) -> None:
    supabase.table('email_sequence_enrollments').update(
        {'status': 'completed', 'awaiting_branch_evaluation': False}
    ).eq('id', enrollment_id).execute()


def _evaluate_branch(enrollment: dict, steps: list, branches_by_step: dict) -> None:
    """Called when awaiting_branch_evaluation is True: the step at
    current_step was already sent branch_wait_hours ago; decide what's
    next based on how the recipient responded to it."""
    step = steps[enrollment['current_step']]
    rules = branches_by_step.get(step['id'], [])

    last_send = (
        supabase.table('email_sequence_sends')
        .select('opened_at, clicked_at')
        .eq('enrollment_id', enrollment['id'])
        .eq('step_id', step['id'])
        .order('sent_at', desc=True)
        .limit(1)
        .execute()
        .data
    )
    send_row = last_send[0] if last_send else {}

    matched_rule = None
    for rule in rules:
        check = CONDITION_CHECKS.get(rule['condition'])
        if check and check(send_row):
            matched_rule = rule
            break

    if not matched_rule:
        # No rule matched this outcome (e.g. only 'opened' was defined,
        # not 'not_opened') — fall back to plain linear advance, same as
        # a step with no branching at all.
        _advance_enrollment(enrollment, steps)
        return

    if not matched_rule.get('next_step_id'):
        _end_enrollment(enrollment['id'])
        return

    target_index = _step_index_by_id(steps, matched_rule['next_step_id'])
    if target_index is None:
        # Branch points at a step that's since been deleted — don't
        # crash or guess, just end the enrollment cleanly.
        _end_enrollment(enrollment['id'])
        return

    supabase.table('email_sequence_enrollments').update({
        'current_step': target_index,
        'next_send_at': datetime.now(timezone.utc).isoformat(),  # send immediately — the wait already happened
        'awaiting_branch_evaluation': False,
    }).eq('id', enrollment['id']).execute()


def _advance_or_branch(enrollment: dict, steps: list, branches_by_step: dict, sent_at: datetime) -> None:
    """Called right after a successful send: either starts the branch
    wait (if the step that was just sent has one configured) or advances
    linearly as before."""
    step = steps[enrollment['current_step']]
    rules = branches_by_step.get(step['id'], [])
    if step.get('branch_wait_hours') is not None and rules:
        eval_at = (sent_at + timedelta(hours=step['branch_wait_hours'])).isoformat()
        supabase.table('email_sequence_enrollments').update({
            'awaiting_branch_evaluation': True, 'next_send_at': eval_at,
        }).eq('id', enrollment['id']).execute()
    else:
        _advance_enrollment(enrollment, steps)


def _advance_enrollment(enrollment: dict, steps: list) -> None:
    next_index = enrollment['current_step'] + 1
    if next_index >= len(steps):
        supabase.table('email_sequence_enrollments').update(
            {'current_step': next_index, 'status': 'completed'}
        ).eq('id', enrollment['id']).execute()
    else:
        next_send_at = (datetime.now(timezone.utc) + timedelta(hours=steps[next_index]['delay_hours'])).isoformat()
        supabase.table('email_sequence_enrollments').update(
            {'current_step': next_index, 'next_send_at': next_send_at}
        ).eq('id', enrollment['id']).execute()


def process_due_sequence_steps(limit: int = 100) -> dict:
    results = {
        'sent': 0, 'completed': 0, 'stopped_suppressed': 0,
        'skipped_no_capacity': 0, 'skipped_missing_unsubscribe': 0, 'failed': 0,
        'branch_evaluated': 0,
    }

    sequences = (
        supabase.table('email_sequences')
        .select('*, email_accounts(*)')
        .eq('status', 'active')
        .execute()
        .data
    ) or []

    now_iso = datetime.now(timezone.utc).isoformat()
    processed = 0

    for seq in sequences:
        if processed >= limit:
            break

        account = seq['email_accounts']
        steps = (
            supabase.table('email_sequence_steps')
            .select('*')
            .eq('sequence_id', seq['id'])
            .order('step_order')
            .execute()
            .data
        ) or []
        if not steps:
            continue

        branches_by_step: dict = {}
        branch_rows = (
            supabase.table('email_sequence_step_branches')
            .select('*')
            .in_('step_id', [s['id'] for s in steps])
            .order('created_at')
            .execute()
            .data
        ) or []
        for row in branch_rows:
            branches_by_step.setdefault(row['step_id'], []).append(row)

        due = (
            supabase.table('email_sequence_enrollments')
            .select('*, email_contacts(*)')
            .eq('sequence_id', seq['id'])
            .eq('status', 'active')
            .lte('next_send_at', now_iso)
            .limit(limit)
            .execute()
            .data
        ) or []
        if not due:
            continue

        suppressed_emails = {
            row['email'] for row in
            supabase.table('email_suppressions').select('email').eq('account_id', account['id']).execute().data
        }

        for enrollment in due:
            if processed >= limit:
                break
            contact = enrollment['email_contacts']

            if contact['email'] in suppressed_emails:
                # Suppression stops the whole sequence, not just this
                # step — once unsubscribed, none of the remaining steps
                # should go out either.
                supabase.table('email_sequence_enrollments').update({'status': 'stopped'}).eq('id', enrollment['id']).execute()
                results['stopped_suppressed'] += 1
                processed += 1
                continue

            if enrollment.get('awaiting_branch_evaluation'):
                _evaluate_branch(enrollment, steps, branches_by_step)
                results['branch_evaluated'] += 1
                processed += 1
                continue

            step_index = enrollment['current_step']
            if step_index >= len(steps):
                supabase.table('email_sequence_enrollments').update({'status': 'completed'}).eq('id', enrollment['id']).execute()
                results['completed'] += 1
                processed += 1
                continue

            step = steps[step_index]

            if not step.get('is_transactional') and '{{unsubscribe_url}}' not in step['body_html']:
                # Don't let one bad step stall the entire sequence for
                # every enrollee behind it — skip and advance, but log
                # it so the missing unsubscribe link is visible somewhere.
                _advance_enrollment(enrollment, steps)
                supabase.table('email_events').insert({
                    'account_id': account['id'], 'contact_email': contact['email'],
                    'event_type': 'sequence_step_skipped_missing_unsubscribe',
                }).execute()
                results['skipped_missing_unsubscribe'] += 1
                processed += 1
                continue

            if not step.get('is_transactional'):
                # Left unrecorded on purpose — no advance means a later
                # tick retries this same step once capacity/hours allow.
                if not within_business_hours(account):
                    continue
                if sent_today_count(account) >= todays_allowed_volume(account):
                    results['skipped_no_capacity'] += 1
                    continue

            unsub_link = unsubscribe_url(account['id'], contact['email'])
            subject = render_email(step['subject'], contact, unsub_link)
            body = render_email(step['body_html'], contact, unsub_link)

            # No email_sequence_sends row exists yet at this point (there
            # was never one for sequences before this change at all) — 
            # generate the id up front so it can be embedded in the
            # tracking pixel/links, then reuse it as the row's actual id
            # below, same approach as branching.py's followup sends.
            send_id = str(uuid.uuid4())
            body = tracking.wrap_links(body, f"sequence:{send_id}", os.environ['APP_BASE_URL'])
            body += tracking.open_pixel_tag(f"sequence:{send_id}", os.environ['APP_BASE_URL'])

            try:
                provider = get_ready_provider(account)
                message_id = provider.send(account['from_email'], account['from_name'], contact['email'], subject, body)
                sent_at_dt = datetime.now(timezone.utc)
                supabase.table('email_events').insert({
                    'account_id': account['id'], 'contact_email': contact['email'],
                    'event_type': 'sequence_step_sent', 'provider_message_id': message_id,
                }).execute()
                supabase.table('email_sequence_sends').insert({
                    'id': send_id, 'enrollment_id': enrollment['id'], 'step_id': step['id'],
                    'account_id': account['id'], 'contact_email': contact['email'],
                    'status': 'sent', 'provider_message_id': message_id,
                    'sent_at': sent_at_dt.isoformat(),
                }).execute()
                _advance_or_branch(enrollment, steps, branches_by_step, sent_at_dt)
                results['sent'] += 1
            except Exception as err:
                supabase.table('email_sequence_sends').insert({
                    'id': send_id, 'enrollment_id': enrollment['id'], 'step_id': step['id'],
                    'account_id': account['id'], 'contact_email': contact['email'],
                    'status': 'failed',
                }).execute()
                # Enrollment stays at the same step on purpose — a
                # provider error should retry the send, not silently
                # skip a message that never went out.
                results['failed'] += 1
                print(f"Sequence step send failed for {contact['email']}: {err}")

            processed += 1

    return results