"""
reputation.py — domain/reputation monitoring. Everything else in this
service (warmup pacing, suppression, business hours, the shared daily
cap) exists to PROTECT deliverability; this module is the part that
actually checks whether it's working.

Two kinds of checks, deliberately run at different cadences:
  - Send health (bounce_rate, complaint_rate) — computed from this
    account's own email_events, cheap, no network calls beyond the DB.
  - Domain authentication + blocklist (spf, dmarc, dkim, blocklist) —
    real DNS lookups. Heavier, and these don't change minute to minute,
    so /reputation-tick in router.py should run once or twice a day,
    not on the same 1-3 minute rhythm as /tick.

No new dependency for DNS: TXT lookups (SPF/DMARC/DKIM) go through
Google's public DNS-over-HTTPS JSON API via stdlib urllib rather than
adding a DNS library — this service already needs outbound HTTPS for
the Resend API, so no new network requirement either. Blocklist
checking (Spamhaus DBL) is a plain A-record lookup, which stdlib socket
already handles natively — resolves = listed, NXDOMAIN = not listed.

Alerting reuses the existing `notifications` table rather than
inventing a new mechanism, and only fires on a genuine STATUS
TRANSITION (see check_and_store) — a persistent problem shouldn't spam
a fresh notification every single tick.
"""
import json
import socket
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone

from raptor.utility.raptor_auth import supabase
from .warmup import SENT_EVENT_TYPES

BOUNCE_WARNING_PCT = 2.0    # Google/Yahoo bulk-sender guidance treats ~2%+ as a warning sign
BOUNCE_CRITICAL_PCT = 5.0   # sustained 5%+ risks throttling/blocking from major providers
COMPLAINT_WARNING_PCT = 0.1
COMPLAINT_CRITICAL_PCT = 0.3

STATUS_RANK = {'ok': 0, 'not_applicable': 0, 'unknown': 0, 'warning': 1, 'critical': 2}


def _rate_status(rate: float, warning: float, critical: float) -> str:
    if rate >= critical:
        return 'critical'
    if rate >= warning:
        return 'warning'
    return 'ok'


def check_send_health(account_id: str, window_days: int = 7) -> dict:
    since = (datetime.now(timezone.utc) - timedelta(days=window_days)).isoformat()

    events = (
        supabase.table('email_events')
        .select('event_type')
        .eq('account_id', account_id)
        .gte('created_at', since)
        .execute()
        .data
    ) or []

    counts: dict = {}
    for e in events:
        counts[e['event_type']] = counts.get(e['event_type'], 0) + 1

    sent = sum(counts.get(t, 0) for t in SENT_EVENT_TYPES)
    bounced = counts.get('bounced', 0)
    complained = counts.get('complained', 0)
    bounce_rate = round((bounced / sent) * 100, 2) if sent else 0.0
    complaint_rate = round((complained / sent) * 100, 2) if sent else 0.0

    return {
        'bounce_rate': {
            'status': _rate_status(bounce_rate, BOUNCE_WARNING_PCT, BOUNCE_CRITICAL_PCT) if sent else 'ok',
            'detail': f"{bounce_rate}% bounce rate over the last {window_days}d ({bounced}/{sent} sent)",
        },
        'complaint_rate': {
            'status': _rate_status(complaint_rate, COMPLAINT_WARNING_PCT, COMPLAINT_CRITICAL_PCT) if sent else 'ok',
            'detail': f"{complaint_rate}% complaint rate over the last {window_days}d ({complained}/{sent} sent)",
        },
    }


def _domain_of(email: str) -> str:
    return (email or '').split('@')[-1].strip().lower()


def _doh_txt_lookup(hostname: str) -> list:
    """Returns [] on any failure — no record, network hiccup, timeout —
    rather than raising. A DNS blip shouldn't crash a health check; it
    should just show up as 'not found', which is the honest answer for
    'a lookup couldn't confirm this record exists' anyway."""
    try:
        url = 'https://dns.google/resolve?' + urllib.parse.urlencode({'name': hostname, 'type': 'TXT'})
        with urllib.request.urlopen(url, timeout=5) as resp:
            data = json.loads(resp.read())
        answers = data.get('Answer') or []
        return [a['data'].strip('"') for a in answers if a.get('type') == 16]  # DNS type 16 = TXT
    except Exception as err:
        print(f"DNS TXT lookup failed for {hostname}: {err}")
        return []


def _is_domain_blocklisted(domain: str):
    """Returns True/False, or None if the check itself failed (network
    issue) — deliberately distinct from a confirmed 'not listed', so a
    transient DNS failure never gets reported as a false-positive clean
    bill of health."""
    try:
        socket.gethostbyname(f"{domain}.dbl.spamhaus.org")
        return True  # an A record resolving means Spamhaus has this domain listed
    except socket.gaierror:
        return False  # NXDOMAIN — not listed
    except Exception as err:
        print(f"Blocklist check failed for {domain}: {err}")
        return None


def check_domain_authentication(account: dict) -> dict:
    domain = _domain_of(account.get('from_email', ''))
    results = {}

    spf_records = _doh_txt_lookup(domain)
    has_spf = any(r.lower().startswith('v=spf1') for r in spf_records)
    results['spf'] = {
        'status': 'ok' if has_spf else 'warning',
        'detail': 'SPF record found' if has_spf else f'No SPF (v=spf1) TXT record found on {domain} — receiving servers can\'t verify you\'re allowed to send as this domain',
    }

    dmarc_records = _doh_txt_lookup(f"_dmarc.{domain}")
    has_dmarc = any(r.lower().startswith('v=dmarc1') for r in dmarc_records)
    results['dmarc'] = {
        'status': 'ok' if has_dmarc else 'warning',
        'detail': 'DMARC record found' if has_dmarc else f'No DMARC (v=DMARC1) TXT record found on _dmarc.{domain}',
    }

    if account.get('provider') == 'resend':
        dkim_records = _doh_txt_lookup(f"resend._domainkey.{domain}")
        has_dkim = len(dkim_records) > 0
        results['dkim'] = {
            'status': 'ok' if has_dkim else 'warning',
            'detail': 'DKIM record found' if has_dkim else f'No DKIM TXT record found at resend._domainkey.{domain} — check the DNS records Resend gave you when you added this domain',
        }
    else:
        # No generic way to know a DKIM selector for an arbitrary SMTP
        # provider — this only means anything for Resend today.
        results['dkim'] = {'status': 'not_applicable', 'detail': 'DKIM check is only implemented for the Resend provider today'}

    listed = _is_domain_blocklisted(domain)
    if listed is None:
        results['blocklist'] = {'status': 'unknown', 'detail': 'Blocklist check failed (network issue) — try again later'}
    else:
        results['blocklist'] = {
            'status': 'critical' if listed else 'ok',
            'detail': f'{domain} IS listed on Spamhaus DBL — this will badly hurt deliverability' if listed else f'{domain} is not on the Spamhaus Domain Block List',
        }

    return results


def run_full_check(account: dict) -> dict:
    checks = dict(check_send_health(account['id']))
    checks.update(check_domain_authentication(account))
    return checks


def _notify_owner(owner_id: str, check_type: str, new_status: str, detail: str) -> None:
    label = check_type.replace('_', ' ')
    if new_status == 'critical':
        ntype, title = 'alert', f"Deliverability alert: {label}"
    elif new_status == 'warning':
        ntype, title = 'warning', f"Deliverability warning: {label}"
    else:
        ntype, title = 'success', f"Resolved: {label}"

    supabase.table('notifications').insert({
        'owner_id': owner_id,
        'type': ntype,
        'display_mode': 'inbox',
        'title': title,
        'body': detail,
        'action_label': 'Review',
        'action_url': '/email/analytics',
    }).execute()


def check_and_store(account: dict) -> dict:
    """Runs every check for one account, persists current status to
    email_reputation_status (upserted, one row per account+check_type),
    and notifies the account owner only on a genuine transition — never
    on a repeat 'still critical' tick, which would just be alert spam."""
    checks = run_full_check(account)

    existing = {
        r['check_type']: r['status']
        for r in (
            supabase.table('email_reputation_status')
            .select('check_type, status')
            .eq('account_id', account['id'])
            .execute()
            .data
        ) or []
    }

    for check_type, result in checks.items():
        new_status = result['status']
        old_status = existing.get(check_type)

        if old_status is not None and old_status != new_status:
            went_worse = STATUS_RANK.get(new_status, 0) > STATUS_RANK.get(old_status, 0)
            resolved = STATUS_RANK.get(new_status, 0) == 0 and STATUS_RANK.get(old_status, 0) > 0
            if went_worse or resolved:
                _notify_owner(account['owner_id'], check_type, new_status, result['detail'])

        supabase.table('email_reputation_status').upsert({
            'account_id': account['id'],
            'check_type': check_type,
            'status': new_status,
            'detail': result['detail'],
            'checked_at': datetime.now(timezone.utc).isoformat(),
        }, on_conflict='account_id,check_type').execute()

    return checks


def check_all_accounts() -> dict:
    accounts = supabase.table('email_accounts').select('*').execute().data or []
    results = {}
    for account in accounts:
        try:
            results[account['id']] = check_and_store(account)
        except Exception as err:
            print(f"Reputation check failed for account {account['id']}: {err}")
    return {'checked': len(results), 'accounts': results}