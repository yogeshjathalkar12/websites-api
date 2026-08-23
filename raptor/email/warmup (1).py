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

WARMUP_DAILY_STEP = 5


def todays_allowed_volume(account: dict) -> int:
    started = account['warmup_started_at']
    if isinstance(started, str):
        started = datetime.fromisoformat(started.replace('Z', '+00:00'))
    days_elapsed = (datetime.now(timezone.utc) - started).days
    ramped = account['daily_cap'] + (days_elapsed * WARMUP_DAILY_STEP)
    return min(ramped, account['warmup_target'])
