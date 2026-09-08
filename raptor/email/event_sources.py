"""
event_sources.py — turns a third-party webhook payload into the plain
shape emit_event() expects: {event_key, contact_email, external_event_id,
payload}. One class per source, same interface, same pattern
providers.py already uses for outbound sending — add a new inbound
source by implementing parse(), nothing else has to change.

Every source is already gated by the account's shared
X-Webhook-Secret (see router.py's /events/webhook/{account_id}) — that
alone is enough to stop a random stranger from posting fake events.
verify() is a SECOND, optional layer: proof the request genuinely came
from the named third party's own servers, using whatever signature
scheme that party provides (Shopify's HMAC, Stripe's signature header,
etc.). The default is "no additional check", since the shared secret
already covers the baseline case and not every source has its own
signing scheme worth wiring up.
"""
import base64
import hashlib
import hmac
from abc import ABC, abstractmethod


class EventSource(ABC):
    @abstractmethod
    def parse(self, raw: dict) -> dict:
        """Returns {'event_key': str, 'contact_email': str,
        'external_event_id': str | None, 'payload': dict}."""
        ...

    def verify(self, raw_body: bytes, headers: dict) -> bool:
        """Override for sources that can verify their own request
        signature. headers is already lowercased by the caller. Default:
        no extra check beyond the shared X-Webhook-Secret."""
        return True


class GenericSource(EventSource):
    """For your own CRM (if you ever want the HTTP path instead of the
    direct Python import), Zapier/Make, or any custom integration that
    can already send our shape directly:
    {event_key, contact_email, external_event_id?, payload?}."""

    def parse(self, raw: dict) -> dict:
        return {
            'event_key': raw.get('event_key', ''),
            'contact_email': (raw.get('contact_email') or '').strip().lower(),
            'external_event_id': raw.get('external_event_id'),
            'payload': raw.get('payload') or {},
        }


class ShopifySource(EventSource):
    """Adapter for Shopify's 'orders/create' (purchase) and
    'checkouts/create' (abandoned checkout) webhook topics. Point
    Shopify's webhook at:
      POST /events/webhook/{account_id}?source=shopify&topic=orders/create
    or topic=checkouts/create for cart abandonment.

    webhook_secret is the account's Shopify app/webhook signing secret
    (see email_accounts.encrypted_shopify_webhook_secret, set via
    POST /accounts/{id}/shopify-secret) — separate from the shared
    X-Webhook-Secret every source requires. If it's not configured,
    verify() logs a warning and passes anyway rather than silently
    dropping every event: degrading to "shared-secret-only" protection
    is better than a half-finished setup meaning nothing gets through."""

    TOPIC_TO_EVENT_KEY = {
        'orders/create': 'purchase',
        'checkouts/create': 'cart_abandoned',
    }

    def __init__(self, topic: str, webhook_secret: str | None = None):
        self.topic = topic
        self.webhook_secret = webhook_secret

    def parse(self, raw: dict) -> dict:
        event_key = self.TOPIC_TO_EVENT_KEY.get(self.topic, self.topic or 'unknown')
        email = (raw.get('email') or raw.get('contact_email') or '').strip().lower()
        return {
            'event_key': event_key,
            'contact_email': email,
            'external_event_id': str(raw.get('id')) if raw.get('id') is not None else None,
            'payload': {
                'order_total': raw.get('total_price'),
                'currency': raw.get('currency'),
                'checkout_url': raw.get('abandoned_checkout_url') or raw.get('order_status_url'),
            },
        }

    def verify(self, raw_body: bytes, headers: dict) -> bool:
        if not self.webhook_secret:
            print("ShopifySource has no webhook_secret configured — skipping HMAC check (X-Webhook-Secret still applies).")
            return True

        provided = headers.get('x-shopify-hmac-sha256', '')
        # Signed over the EXACT raw request bytes — any re-serialization
        # (different key order, whitespace) would break this, which is
        # why this must run before the body is parsed as JSON.
        computed = base64.b64encode(
            hmac.new(self.webhook_secret.encode(), raw_body, hashlib.sha256).digest()
        ).decode()
        return hmac.compare_digest(computed, provided)


def get_source(name: str, **kwargs) -> EventSource:
    if name == 'shopify':
        return ShopifySource(topic=kwargs.get('topic', ''), webhook_secret=kwargs.get('webhook_secret'))
    return GenericSource()