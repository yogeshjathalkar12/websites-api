"""
analytics.py — aggregates the open/click/event data collected across
campaigns, triggers, follow-ups, and sequences into one dashboard-ready
summary. Reuses warmup.SENT_EVENT_TYPES as the canonical definition of
"this event type represents a successfully delivered send" — the same
definition sent_today_count() uses for capacity checks, so the totals
shown here and the numbers actually governing warmup pacing can't drift
apart from each other.

Aggregation happens in Python after a single filtered fetch (scoped to
account_id + date range), same level of complexity already accepted
elsewhere in this codebase (segments.py's set operations, suppression
sets built the same way). This is a real scaling limit worth knowing
about: an account sending very high volume over a long range would be
better served by a SQL-side GROUP BY (a Postgres RPC) instead of pulling
every event row across the wire. Not needed yet at the volumes this
warmup-paced sender is designed for.
"""
from collections import defaultdict
from datetime import datetime, timedelta, timezone

from raptor.utility.raptor_auth import supabase
from .warmup import SENT_EVENT_TYPES

ENGAGEMENT_EVENT_TYPES = ['opened', 'clicked', 'bounced', 'complained', 'unsubscribed']


def _rate(numerator: int, denominator: int) -> float:
    return round((numerator / denominator) * 100, 1) if denominator else 0.0


def _campaign_breakdown(account_id: str, since_iso: str, limit: int = 20) -> list:
    campaigns = (
        supabase.table('email_campaigns')
        .select('id, name, created_at')
        .eq('account_id', account_id)
        .gte('created_at', since_iso)
        .order('created_at', desc=True)
        .limit(limit)
        .execute()
        .data
    ) or []

    breakdown = []
    for c in campaigns:
        recipients = (
            supabase.table('email_campaign_recipients')
            .select('status, opened_at, clicked_at')
            .eq('campaign_id', c['id'])
            .execute()
            .data
        ) or []
        sent = sum(1 for r in recipients if r['status'] == 'sent')
        opened = sum(1 for r in recipients if r.get('opened_at'))
        clicked = sum(1 for r in recipients if r.get('clicked_at'))
        breakdown.append({
            'campaign_id': c['id'],
            'name': c['name'],
            'sent': sent,
            'opened': opened,
            'clicked': clicked,
            'open_rate': _rate(opened, sent),
            'click_rate': _rate(clicked, sent),
        })
    return breakdown


def compute_overview(account_id: str, days: int = 30) -> dict:
    since = datetime.now(timezone.utc) - timedelta(days=days)
    since_iso = since.isoformat()

    events = (
        supabase.table('email_events')
        .select('event_type, created_at')
        .eq('account_id', account_id)
        .gte('created_at', since_iso)
        .execute()
        .data
    ) or []

    totals = defaultdict(int)
    daily = defaultdict(lambda: defaultdict(int))

    for e in events:
        et = e['event_type']
        date_str = (e['created_at'] or '')[:10]
        totals[et] += 1
        daily[date_str][et] += 1
        if et in SENT_EVENT_TYPES:
            totals['_sent_total'] += 1
            daily[date_str]['_sent_total'] += 1

    total_sent = totals.get('_sent_total', 0)

    daily_series = [
        {
            'date': date_str,
            'sent': daily[date_str].get('_sent_total', 0),
            'opened': daily[date_str].get('opened', 0),
            'clicked': daily[date_str].get('clicked', 0),
            'bounced': daily[date_str].get('bounced', 0),
        }
        for date_str in sorted(daily.keys())
    ]

    channel_breakdown = {
        'campaigns': totals.get('sent', 0),
        'triggers': totals.get('trigger_sent', 0),
        'followups': totals.get('followup_sent', 0),
        'sequences': totals.get('sequence_step_sent', 0),
    }

    return {
        'range_days': days,
        'totals': {
            'sent': total_sent,
            'opened': totals.get('opened', 0),
            'clicked': totals.get('clicked', 0),
            'bounced': totals.get('bounced', 0),
            'complained': totals.get('complained', 0),
            'unsubscribed': totals.get('unsubscribed', 0),
        },
        'rates': {
            'open_rate': _rate(totals.get('opened', 0), total_sent),
            'click_rate': _rate(totals.get('clicked', 0), total_sent),
            'bounce_rate': _rate(totals.get('bounced', 0), total_sent),
            'complaint_rate': _rate(totals.get('complained', 0), total_sent),
            'unsubscribe_rate': _rate(totals.get('unsubscribed', 0), total_sent),
        },
        'daily': daily_series,
        'channel_breakdown': channel_breakdown,
        'by_campaign': _campaign_breakdown(account_id, since_iso),
    }