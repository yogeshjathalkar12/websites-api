"""
tracking.py — open & click tracking for sent campaigns.

Every tracked link and the open pixel carry an HMAC token signed over
(recipient_id, kind, payload) — for clicks, payload is the destination
URL itself. Signing the destination URL (not just the recipient id)
means a token that leaks from one email can't be replayed to build a
redirect to an arbitrary URL; it only ever validates for the exact link
it shipped with in that exact email. Without this, /track/click would be
an open redirect sitting on your sending domain.

Own secret, EMAIL_TRACKING_SIGNING_SECRET, kept separate from
UNSUBSCRIBE_SIGNING_SECRET in security.py — no reason a leak of one
should let you forge the other.

Deliberately NOT wrapped: the unsubscribe link. An unsub click isn't
engagement — logging it as a "click" would pollute the metric — and
compliance links should stay a direct, unambiguous URL rather than a
redirect through this endpoint.
"""
import hashlib
import hmac
import os
import re
from urllib.parse import quote

_SECRET = os.environ.get('EMAIL_TRACKING_SIGNING_SECRET')
if not _SECRET:
    raise RuntimeError("EMAIL_TRACKING_SIGNING_SECRET is not set — any random 32+ char string.")

# Matches href="http://..." / href="https://..." so mailto:, tel:, and
# relative anchors are left alone.
_LINK_PATTERN = re.compile(r'href="(https?://[^"]+)"')


def _sign(recipient_id: str, kind: str, payload: str = '') -> str:
    msg = f"{recipient_id}:{kind}:{payload}".encode()
    return hmac.new(_SECRET.encode(), msg, hashlib.sha256).hexdigest()[:32]


def verify_open_token(recipient_id: str, token: str) -> bool:
    return hmac.compare_digest(_sign(recipient_id, 'open'), token or '')


def verify_click_token(recipient_id: str, url: str, token: str) -> bool:
    # `url` here is expected already-decoded (FastAPI/Starlette decodes
    # query params for you) — don't unquote it again or a URL that itself
    # contains a literal '%' will fail to verify.
    return hmac.compare_digest(_sign(recipient_id, 'click', url), token or '')


def open_pixel_tag(recipient_id: str, base_url: str) -> str:
    """A 1x1 tracking pixel appended to the rendered body. Placed last so
    it never shifts layout in a client that renders it visibly. Note:
    Apple Mail Privacy Protection and Gmail's image proxy both pre-fetch
    images for a lot of users regardless of whether the recipient ever
    opened the email — treat open rate as directional, not exact."""
    token = _sign(recipient_id, 'open')
    src = f"{base_url}/track/open?r={recipient_id}&t={token}"
    return f'<img src="{src}" width="1" height="1" alt="" style="display:none;" />'


def wrap_links(html: str, recipient_id: str, base_url: str) -> str:
    """Rewrites every absolute http(s) href to route through /track/click
    first, skipping any link containing 'unsubscribe'."""
    def _replace(match: re.Match) -> str:
        original_url = match.group(1)
        if 'unsubscribe' in original_url:
            return match.group(0)
        token = _sign(recipient_id, 'click', original_url)
        tracked = f"{base_url}/track/click?r={recipient_id}&t={token}&u={quote(original_url, safe='')}"
        return f'href="{tracked}"'

    return _LINK_PATTERN.sub(_replace, html)