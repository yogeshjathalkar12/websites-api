"""
providers.py — Meta WhatsApp Cloud API wrapper.

Chosen over Twilio/360dialog deliberately: this is the official API direct
from Meta, no reseller markup sitting between the business and Meta's own
per-conversation pricing. "Bring your own key" here means the user brings
their own phone_number_id + access token from their own Meta app — same
shape as bringing your own Resend key for email.

TWO send methods, not one, because Meta enforces a real platform rule, not
a style choice: any business-initiated message sent OUTSIDE a 24-hour
customer service window (i.e. the contact hasn't messaged you recently)
MUST use a pre-approved message template — free-form text gets rejected.
Only messages sent INSIDE that 24h window (e.g. a reply to something the
contact just sent) can be free-form. That's why broadcasts/sequences use
send_template() and trigger-based auto-replies use send_text().
"""
import httpx

GRAPH_API_VERSION = "v21.0"


class MetaCloudProvider:
    def __init__(self, phone_number_id: str, access_token: str):
        self.base_url = f"https://graph.facebook.com/{GRAPH_API_VERSION}/{phone_number_id}/messages"
        self._headers = {"Authorization": f"Bearer {access_token}", "Content-Type": "application/json"}

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
        resp = httpx.post(self.base_url, headers=self._headers, json=body, timeout=20)
        resp.raise_for_status()
        return resp.json()["messages"][0]["id"]

    def send_text(self, to: str, body_text: str) -> str:
        body = {"messaging_product": "whatsapp", "to": to, "type": "text", "text": {"body": body_text}}
        resp = httpx.post(self.base_url, headers=self._headers, json=body, timeout=20)
        resp.raise_for_status()
        return resp.json()["messages"][0]["id"]


def get_provider(account: dict) -> MetaCloudProvider:
    return MetaCloudProvider(account['phone_number_id'], account['access_token'])
