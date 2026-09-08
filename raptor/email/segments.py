"""
segments.py — resolves a campaign's audience into a concrete list of
email_contacts. Two ways in:
  - The legacy path: a plain audience_tag string (or none, meaning
    everyone on the account).
  - A segment: an email_segments row whose `rules` column is JSON —
    {"match": "all" | "any", "conditions": [...]}. Conditions:
      {"type": "tag", "tag": "..."}
      {"type": "not_tag", "tag": "..."}
      {"type": "opened_campaign", "campaign_id": "..."}
      {"type": "not_opened_campaign", "campaign_id": "..."}
      {"type": "clicked_campaign", "campaign_id": "..."}
      {"type": "not_clicked_campaign", "campaign_id": "..."}
    The opened/clicked conditions read directly off
    email_campaign_recipients.opened_at/clicked_at for that specific past
    campaign, scoped to recipients who were actually sent to
    (status='sent') — "didn't open" only means something for someone who
    received it in the first place.

This is deliberately NOT a general-purpose query builder. Combining sets
in Python (rather than pushing the whole thing down into one SQL query)
is a real limitation on large contact lists, but it matches the level of
complexity already accepted elsewhere in this codebase (suppression
sets, etc. are built the same way) and keeps segment logic readable and
easy to extend with new condition types.

Not built yet, and worth flagging as a real gap in "richer segmentation":
segmenting on a trigger event's payload data (e.g. "orders over $100").
Payload shape is caller-defined and open-ended per trigger, which makes
it a genuinely bigger feature than tags or campaign engagement — left
for later rather than bolted on half-finished here.
"""
from raptor.utility.raptor_auth import supabase


def _condition_contact_ids(account_id: str, condition: dict) -> set:
    ctype = condition.get('type')

    if ctype == 'tag':
        rows = (
            supabase.table('email_contacts')
            .select('id')
            .eq('account_id', account_id)
            .contains('tags', [condition['tag']])
            .execute()
            .data
        ) or []
        return {r['id'] for r in rows}

    if ctype == 'not_tag':
        all_ids = {
            r['id'] for r in
            supabase.table('email_contacts').select('id').eq('account_id', account_id).execute().data or []
        }
        return all_ids - _condition_contact_ids(account_id, {'type': 'tag', 'tag': condition['tag']})

    if ctype in ('opened_campaign', 'not_opened_campaign', 'clicked_campaign', 'not_clicked_campaign'):
        campaign_id = condition.get('campaign_id')
        if not campaign_id:
            return set()
        field = 'opened_at' if 'opened' in ctype else 'clicked_at'
        recipients = (
            supabase.table('email_campaign_recipients')
            .select(f'contact_id, {field}')
            .eq('campaign_id', campaign_id)
            .eq('status', 'sent')
            .execute()
            .data
        ) or []
        matched = {r['contact_id'] for r in recipients if r.get(field)}
        if ctype.startswith('not_'):
            all_sent = {r['contact_id'] for r in recipients}
            return all_sent - matched
        return matched

    print(f"Unknown segment condition type '{ctype}' — treating as no match.")
    return set()


def resolve_segment_rules(account_id: str, rules: dict) -> list:
    conditions = (rules or {}).get('conditions') or []
    if not conditions:
        return []

    match = (rules or {}).get('match', 'all')
    sets = [_condition_contact_ids(account_id, c) for c in conditions]
    combined = sets[0]
    for s in sets[1:]:
        combined = (combined & s) if match == 'all' else (combined | s)

    if not combined:
        return []
    return supabase.table('email_contacts').select('*').in_('id', list(combined)).execute().data or []


def resolve_audience(account_id: str, segment_id: str | None, audience_tag: str | None) -> list:
    """The single entry point router.py's batch loop calls. segment_id
    takes precedence over audience_tag when both are somehow set."""
    if segment_id:
        segment = supabase.table('email_segments').select('rules').eq('id', segment_id).single().execute().data
        if not segment:
            return []
        return resolve_segment_rules(account_id, segment.get('rules') or {})

    query = supabase.table('email_contacts').select('*').eq('account_id', account_id)
    if audience_tag:
        query = query.contains('tags', [audience_tag])
    return query.execute().data or []