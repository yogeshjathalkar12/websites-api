"""
Spintax: {option one|option two|option three} -> picks one at random.
Used so every recipient in a campaign doesn't receive byte-identical text,
which is one of the stronger spam signals providers look at. Nest freely:
"{Hi|Hey} {{first_name}}, {hope you're well|hope this finds you well}."

BUGFIX: the pattern now REQUIRES at least one '|' inside the braces to
match at all. Without this, `\{([^{}]*)\}` matched the inner brace of
{{first_name}} as a one-option spintax choice (options = ["first_name"]),
silently collapsing it to the literal word "first_name" before
render_merge_fields ever ran -- every email would have shipped with the
literal text "first_name" instead of the recipient's actual name. Genuine
spintax always has at least two alternatives separated by '|'; merge
fields never contain a '|'; requiring one is what lets the regex tell
them apart.
"""
import random
import re

SPINTAX_PATTERN = re.compile(r'\{([^{}]*\|[^{}]*(?:\|[^{}]*)*)\}')


def render_spintax(text: str) -> str:
    def _pick(match: re.Match) -> str:
        options = match.group(1).split('|')
        return random.choice(options)

    while True:
        new_text, replaced = SPINTAX_PATTERN.subn(_pick, text)
        if replaced == 0:
            return new_text
        text = new_text


def render_merge_fields(text: str, contact: dict, unsubscribe_url: str, extra_fields: dict | None = None) -> str:
    replacements = {
        '{{first_name}}': contact.get('first_name') or 'there',
        '{{last_name}}': contact.get('last_name') or '',
        '{{company}}': contact.get('company') or '',
        '{{unsubscribe_url}}': unsubscribe_url,
    }
    # extra_fields carries a trigger event's payload (order_total,
    # checkout_url, etc.) — campaign sends never pass this, so it's an
    # optional add-on rather than a change to existing behavior.
    if extra_fields:
        for key, value in extra_fields.items():
            replacements[f'{{{{{key}}}}}'] = '' if value is None else str(value)
    for key, value in replacements.items():
        text = text.replace(key, value)
    return text


def render_email(template: str, contact: dict, unsubscribe_url: str, extra_fields: dict | None = None) -> str:
    """Spintax first, then merge fields — so merge fields never get consumed as spintax options."""
    spun = render_spintax(template)
    return render_merge_fields(spun, contact, unsubscribe_url, extra_fields)