"""
ab_testing.py — splits a campaign's audience across content variants,
tracks each independently (via email_campaign_recipients.variant_id),
and picks a winner to send to the held-back rest of the audience.

Deliberately independent per campaign — no memory of "which style tends
to win" carried across campaigns. That's a real possible future
feature, not built here; keeping this simple for now.

Winner selection uses BOTH engagement metrics, not just one: the
primary metric (ab_winner_metric, default 'click_rate' — more reliable
than open rate, which Apple Mail Privacy Protection and Gmail's image
proxy both inflate for a lot of recipients regardless of genuine opens)
decides first; if variants tie on the primary metric — including tying
at zero, e.g. an announcement email with no links where click rate
can't discriminate anything — the OTHER metric breaks the tie instead
of an arbitrary coin-flip.
"""
import random
from datetime import datetime, timedelta, timezone

from raptor.utility.raptor_auth import supabase


def split_recipients_for_ab_test(campaign: dict, contacts: list) -> list:
    """Returns recipient row dicts ready to insert into
    email_campaign_recipients, with status/variant_id already decided.
    A campaign with no variants defined returns plain 'pending' rows
    with variant_id=None — i.e. behaves exactly like a non-AB campaign,
    so router.py's _ensure_recipients_populated can call this
    unconditionally without an if/else for the AB case."""
    variants = (
        supabase.table('email_campaign_variants')
        .select('id')
        .eq('campaign_id', campaign['id'])
        .order('created_at')
        .execute()
        .data
    ) or []

    if not variants:
        return [{'campaign_id': campaign['id'], 'contact_id': c['id'], 'status': 'pending', 'variant_id': None} for c in contacts]

    test_pct = campaign.get('ab_test_percentage')
    test_pct = 100 if test_pct is None else test_pct

    shuffled = list(contacts)
    random.shuffle(shuffled)

    if test_pct >= 100:
        test_group, rest_group = shuffled, []
    else:
        # At least one recipient per variant, so a tiny audience with a
        # low percentage still produces a real test rather than zero
        # data to ever pick a winner from.
        test_count = max(len(variants), round(len(shuffled) * (test_pct / 100)))
        test_count = min(test_count, len(shuffled))
        test_group, rest_group = shuffled[:test_count], shuffled[test_count:]

    rows = []
    for i, contact in enumerate(test_group):
        variant = variants[i % len(variants)]  # round-robin — even split across variants
        rows.append({'campaign_id': campaign['id'], 'contact_id': contact['id'], 'status': 'pending', 'variant_id': variant['id']})
    for contact in rest_group:
        # Held back, invisible to the normal sender (different status,
        # not just a null variant_id) until a winner is picked.
        rows.append({'campaign_id': campaign['id'], 'contact_id': contact['id'], 'status': 'awaiting_winner', 'variant_id': None})
    return rows


def _variant_stats(campaign_id: str, variant_id: str) -> dict:
    recipients = (
        supabase.table('email_campaign_recipients')
        .select('status, opened_at, clicked_at')
        .eq('campaign_id', campaign_id)
        .eq('variant_id', variant_id)
        .execute()
        .data
    ) or []
    sent = sum(1 for r in recipients if r['status'] == 'sent')
    opened = sum(1 for r in recipients if r.get('opened_at'))
    clicked = sum(1 for r in recipients if r.get('clicked_at'))
    return {
        'variant_id': variant_id,
        'sent': sent,
        'open_rate': (opened / sent) if sent else 0.0,
        'click_rate': (clicked / sent) if sent else 0.0,
    }


def pick_winner(campaign: dict):
    """Returns the winning variant's stats dict, or None if there are no
    variants at all (shouldn't happen for a real AB-enabled campaign,
    but this is called from a cron sweep — defend against a stray row)."""
    variants = supabase.table('email_campaign_variants').select('id').eq('campaign_id', campaign['id']).execute().data or []
    if not variants:
        return None

    stats = [_variant_stats(campaign['id'], v['id']) for v in variants]

    primary = campaign.get('ab_winner_metric') or 'click_rate'
    secondary = 'open_rate' if primary == 'click_rate' else 'click_rate'
    stats.sort(key=lambda s: (s[primary], s[secondary]), reverse=True)
    return stats[0]


def finalize_test(campaign: dict) -> dict:
    """Picks a winner and releases the held-back 'rest' group to send
    with the winning variant's content. Safe to call more than once —
    if ab_winner_variant_id is already set, this just re-confirms it
    rather than picking again or double-releasing recipients (the
    'awaiting_winner' rows will already have been flipped to 'pending'
    the first time this ran)."""
    winner = pick_winner(campaign)
    if not winner:
        return {'finalized': False, 'reason': 'no_variants'}

    supabase.table('email_campaigns').update({'ab_winner_variant_id': winner['variant_id']}).eq('id', campaign['id']).execute()
    supabase.table('email_campaign_recipients').update({
        'status': 'pending', 'variant_id': winner['variant_id'],
    }).eq('campaign_id', campaign['id']).eq('status', 'awaiting_winner').execute()

    return {'finalized': True, 'winner_variant_id': winner['variant_id'], 'stats': winner}


def check_and_finalize_due_tests() -> dict:
    """Cron-only. Filtering on 'ab_test_started_at + duration_hours has
    elapsed' isn't expressible as a single Supabase column filter, so
    this fetches AB-enabled, not-yet-decided campaigns and checks the
    elapsed time in Python — same pattern already used elsewhere in this
    codebase (segments.py, branching.py) for anything beyond a plain
    column comparison."""
    candidates = (
        supabase.table('email_campaigns')
        .select('*')
        .eq('ab_test_enabled', True)
        .is_('ab_winner_variant_id', 'null')
        .execute()
        .data
    ) or []

    finalized = []
    for c in candidates:
        started = c.get('ab_test_started_at')
        if not started:
            continue  # recipients haven't been populated yet — nothing to finalize
        if isinstance(started, str):
            started = datetime.fromisoformat(started.replace('Z', '+00:00'))
        duration_hours = c.get('ab_test_duration_hours') or 4
        if datetime.now(timezone.utc) >= started + timedelta(hours=duration_hours):
            result = finalize_test(c)
            if result['finalized']:
                finalized.append(c['id'])

    return {'checked': len(candidates), 'finalized': finalized}