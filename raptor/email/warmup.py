"""
Gradual volume ramp for a sending account. Real mail providers throttle or
blocklist accounts that go from 0 to high volume overnight, regardless of
content quality — this is the single highest-leverage thing for staying
off blocklists, more than any content trick.

Ramp shape: start at daily_cap, add a fixed step every day, cap at
warmup_target. Tune WARMUP_DAILY_STEP for how aggressive you want it —
20/day is a conservative default for a fresh domain.
"""
from datetime import datetime, timezone
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from raptor.utility.raptor_auth import supabase

WARMUP_DAILY_STEP = 5


def todays_allowed_volume(account: dict) -> int:
    started = account['warmup_started_at']
    if isinstance(started, str):
        started = datetime.fromisoformat(started.replace('Z', '+00:00'))
    days_elapsed = (datetime.now(timezone.utc) - started).days
    ramped = account['daily_cap'] + (days_elapsed * WARMUP_DAILY_STEP)
    return min(ramped, account['warmup_target'])


def _account_zoneinfo(account: dict) -> ZoneInfo:
    """Falls back to UTC for a missing or invalid timezone string rather
    than raising — a typo'd timezone value on one account shouldn't take
    down sending for that account entirely."""
    tz_name = account.get('timezone') or 'UTC'
    try:
        return ZoneInfo(tz_name)
    except (ZoneInfoNotFoundError, KeyError, ValueError):
        print(f"Unknown timezone '{tz_name}' on account {account.get('id')} — falling back to UTC.")
        return ZoneInfo('UTC')


def within_business_hours(account: dict) -> bool:
    """FIXED: previously compared business_hours_start/end against UTC
    regardless of the account's own timezone column, so an account
    configured for '9am-6pm' could actually be sending in the middle of
    its local night. Now resolves the account's actual local hour first."""
    local_hour = datetime.now(_account_zoneinfo(account)).hour
    return account['business_hours_start'] <= local_hour <= account['business_hours_end']


SENT_EVENT_TYPES = ['sent', 'trigger_sent', 'followup_sent', 'sequence_step_sent']


def sent_today_count(account: dict) -> int:
    """Every channel that actually delivers mail — campaigns ('sent'),
    triggers ('trigger_sent'), follow-ups ('followup_sent'), and
    sequences ('sequence_step_sent') — counts toward the same daily cap.
    A mail provider doesn't care which internal code path sent the
    email; it's all volume from the same domain.

    FIXED: 'today' is now the account's own local calendar day, not the
    UTC calendar day. Previously the cap could quietly reset at 5:30am
    or 4pm local time depending on the account's timezone offset from
    UTC — completely disconnected from what within_business_hours()
    thinks 'today' means, since both used to disagree about time zones
    in two different ways. They now share the same account-local clock.

    NOTE: signature changed from taking account_id to the full account
    dict, since resolving 'today' now requires knowing the account's
    timezone. Every caller passes account, not account['id']."""
    local_now = datetime.now(_account_zoneinfo(account))
    local_midnight = local_now.replace(hour=0, minute=0, second=0, microsecond=0)
    today_start_utc = local_midnight.astimezone(timezone.utc).isoformat()

    result = (
        supabase.table('email_events')
        .select('id', count='exact')
        .eq('account_id', account['id'])
        .in_('event_type', SENT_EVENT_TYPES)
        .gte('created_at', today_start_utc)
        .execute()
    )
    return result.count or 0