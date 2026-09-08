"""
providers.py — Meta WhatsApp Cloud API wrapper.

Chosen over Twilio/360dialog deliberately: this is the official API direct
from Meta, no reseller markup sitting between the business and Meta's own
per-conversation pricing. "Bring your own key" here means the user brings
their own phone_number_id + access token from their own Meta app — same
shape as bringing your own Resend key for email.

THREE send methods now, not two — each maps to a real Meta platform rule,
not a style choice:

  send_template()          any business-initiated message sent OUTSIDE a
                            24-hour customer service window MUST use a
                            pre-approved template. Used by broadcasts and
                            sequence steps, which are always cold sends.

  send_text()               free-form text, legal only INSIDE that 24h
                            window (i.e. replying to something the contact
                            just sent). Used by keyword-trigger auto-replies
                            and manual agent replies from the CRM inbox.

  send_interactive_buttons() / send_interactive_list()
                            Phase 3 addition. Same 24h-window rule as
                            send_text() — these are "interactive" message
                            types, not templates, so they're also
                            reply-only, never usable for a cold broadcast.
                            Meta caps buttons at 3 and list rows at 10;
                            titles/descriptions are hard length limits on
                            Meta's side (button title 20 chars, list row
                            title 24 chars, description 72 chars), so we
                            truncate defensively rather than let Meta 400.
"""
import httpx

GRAPH_API_VERSION = "v21.0"


class MetaCloudProvider:
    def __init__(self, phone_number_id: str, access_token: str):
        self.base_url = f"https://graph.facebook.com/{GRAPH_API_VERSION}/{phone_number_id}/messages"
        self._headers = {"Authorization": f"Bearer {access_token}", "Content-Type": "application/json"}

    def _post(self, body: dict) -> str:
        resp = httpx.post(self.base_url, headers=self._headers, json=body, timeout=20)
        resp.raise_for_status()
        return resp.json()["messages"][0]["id"]

    def send_template(self, to: str, template_name: str, language_code: str, params: list) -> str:
        body = {
            "messaging_product": "whatsapp",
            "to": to,
            "type": "template",
            "template": {
                "name": template_name,
                "language": {"code": language_code},
                "components": [{"type": "body", "parameters": [{"type": "text", "text": p} for p in params]}] if params else [],
            },
        }
        return self._post(body)

    def send_text(self, to: str, body_text: str) -> str:
        body = {"messaging_product": "whatsapp", "to": to, "type": "text", "text": {"body": body_text}}
        return self._post(body)

    def send_interactive_buttons(self, to: str, body_text: str, buttons: list) -> str:
        """buttons: [{"id": "opt_pricing", "title": "Pricing"}, ...] — max 3,
        enforced by slicing rather than raising, since a trigger with 4
        buttons configured should still send the first 3 rather than fail
        outright at send time."""
        body = {
            "messaging_product": "whatsapp",
            "to": to,
            "type": "interactive",
            "interactive": {
                "type": "button",
                "body": {"text": body_text},
                "action": {
                    "buttons": [
                        {"type": "reply", "reply": {"id": b["id"], "title": b["title"][:20]}}
                        for b in buttons[:3]
                    ]
                },
            },
        }
        return self._post(body)

    def send_interactive_list(self, to: str, body_text: str, button_label: str, rows: list) -> str:
        """rows: [{"id": "opt_billing", "title": "Billing", "description": "..."}] — max 10,
        single section (Meta supports multiple sections; one is enough for
        the keyword-trigger use case this serves today)."""
        body = {
            "messaging_product": "whatsapp",
            "to": to,
            "type": "interactive",
            "interactive": {
                "type": "list",
                "body": {"text": body_text},
                "action": {
                    "button": button_label[:20],
                    "sections": [
                        {
                            "title": "Options",
                            "rows": [
                                {"id": r["id"], "title": r["title"][:24], "description": (r.get("description") or "")[:72]}
                                for r in rows[:10]
                            ],
                        }
                    ],
                },
            },
        }
        return self._post(body)

    def send_catalog_message(self, to: str, body_text: str, thumbnail_product_retailer_id: str | None = None) -> str:
        """Sends the account's whole connected Commerce Catalog with a
        'View catalog' CTA. No catalog_id needed in the payload — Meta
        resolves it from the WABA's default catalog automatically."""
        action: dict = {"name": "catalog_message"}
        if thumbnail_product_retailer_id:
            action["parameters"] = {"thumbnail_product_retailer_id": thumbnail_product_retailer_id}
        body = {
            "messaging_product": "whatsapp",
            "to": to,
            "type": "interactive",
            "interactive": {"type": "catalog_message", "body": {"text": body_text}, "action": action},
        }
        return self._post(body)

    def send_single_product(self, to: str, catalog_id: str, product_retailer_id: str) -> str:
        """Single product card — Meta pulls image/name/price live from the
        catalog, so there's no body text field to set here."""
        body = {
            "messaging_product": "whatsapp",
            "to": to,
            "type": "interactive",
            "interactive": {
                "type": "product",
                "action": {"catalog_id": catalog_id, "product_retailer_id": product_retailer_id},
            },
        }
        return self._post(body)

    def send_product_list(self, to: str, catalog_id: str, body_text: str, sections: list) -> str:
        """sections: [{"title": "...", "product_retailer_ids": ["SKU1", "SKU2"]}] — max 10
        sections, each converted to Meta's {product_retailer_id} row shape."""
        body = {
            "messaging_product": "whatsapp",
            "to": to,
            "type": "interactive",
            "interactive": {
                "type": "product_list",
                "body": {"text": body_text},
                "action": {
                    "catalog_id": catalog_id,
                    "sections": [
                        {
                            "title": s["title"][:24],
                            "product_items": [{"product_retailer_id": pid} for pid in s.get("product_retailer_ids", [])],
                        }
                        for s in sections[:10]
                    ],
                },
            },
        }
        return self._post(body)


def get_provider(account: dict) -> MetaCloudProvider:
    return MetaCloudProvider(account['phone_number_id'], account['access_token'])