"""
Same ramp shape as raptor/email/warmup.py, duplicated rather than shared
across domains for independence. Meta's Cloud API ALSO enforces its own
tiered messaging limits based on your number's quality rating (starts
around 250 unique customers/24h, scales up automatically as quality holds)
— this local daily_cap is a conservative floor underneath that, not a
replacement for it. Meta will reject sends past their own tier regardless
of what this says.
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
