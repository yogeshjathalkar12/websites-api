"""
crm_bridge.py — bridges CrmMarketing.tsx's audience_lists (defined
against the CRM's own `contacts` table: status, lead_score) into the
real email-sending path.

Deliberately NOT merged into segments.py: that module's conditions are
about email engagement and tags on email_contacts — a different table,
a different domain. audience_lists' filter_rules describe properties of
a CRM contact (their pipeline status, their lead score), not anything
about email history. Two resolvers for two genuinely different kinds of
"audience" is clearer than one resolver with an awkward if/else split
down the middle for which table it's filtering.
"""
from raptor.utility.raptor_auth import supabase


def resolve_audience_list_contacts(filter_rules: dict) -> list:
    """Mirrors CrmMarketing.tsx's client-side getSegmentRecipientCount
    filter logic, but run server-side so the actual dispatch always
    matches what the count shown in the UI implied — those two must
    never be allowed to drift apart."""
    rows = supabase.table('contacts').select('id, name, email, status, lead_score').execute().data or []

    rules = filter_rules or {}
    status_filter = rules.get('status')
    min_score = rules.get('min_score')

    def matches(c: dict) -> bool:
        if status_filter and status_filter != 'all' and c.get('status') != status_filter:
            return False
        if min_score and (c.get('lead_score') or 0) < min_score:
            return False
        return True

    return [c for c in rows if matches(c)]