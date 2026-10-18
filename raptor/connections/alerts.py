"""Alerts: Slack, Microsoft Teams and Telegram. Raptor tells the team the moment something worth knowing happens: a payment, a bad
review, someone asking the price.

Two halves:
  * the connectors (Slack, Teams, Telegram) that deliver a message. They only SEND (Telegram also receives, so people can message the bot);
    the webhook address or bot token is the customer's own and stored encrypted.
  * derive_alerts() and dispatch(): after new signals arrive from any channel, work out which of them deserve an alert and send each one
    to every alert connection of that organization that asked for that kind of event.

An alert failing must never break the data collection that triggered it, so dispatch() swallows and logs every delivery error."""
from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import secrets
from dataclasses import dataclass
from typing import Optional

import httpx

from . import net
from .registry import Action, ConnectResult, Connector, ConnectorError, Context, Field, Signal, register

log = logging.getLogger(__name__)

ALERT_EVENTS = [
    {"value": "payment_received", "label": "A payment comes in"},
    {"value": "payment_failed", "label": "A payment fails"},
    {"value": "new_review", "label": "Any new Google review"},
    {"value": "low_review", "label": "A review of 3 stars or less"},
    {"value": "rating_drop", "label": "The Google rating drops"},
    {"value": "buying_comment", "label": "Someone shows buying interest (a comment or a message)"},
    {"value": "new_message", "label": "A message arrives on Telegram"},
    {"value": "sync_error", "label": "A connection stops working"},
]
DEFAULT_EVENTS = ["payment_received", "payment_failed", "low_review", "buying_comment", "sync_error"]
_VALID_EVENTS = {e["value"] for e in ALERT_EVENTS}

BUYING = re.compile(r"\b(price|pricing|prices|cost|how much|quote|quotation|buy|purchase|demo|trial|interested|where can i|discount|order|contact me|call me|whatsapp me|available in)\b", re.I)
SYMBOLS = {"INR": "₹", "USD": "$", "EUR": "€", "GBP": "£"}


@dataclass
class Alert:
    events: tuple          # the alert is sent to a connection that listens for ANY of these
    text: str


def money(value, currency: str = "INR") -> str:
    code = (currency or "INR").upper()
    amount = f"{float(value or 0):,.2f}"
    return f"{SYMBOLS[code]}{amount}" if code in SYMBOLS else f"{code} {amount}"


def derive_alerts(provider: str, rows: list, previous_rating: Optional[float] = None) -> list:
    """Which of the NEW signals deserve an alert. `rows` are signals as stored (name, value, text_value, entity)."""
    out = []
    for r in rows:
        name, value, text, entity = r.get("name"), r.get("value"), (r.get("text_value") or ""), (r.get("entity") or {})
        if name == "payment_received":
            who = f" from {entity['email']}" if entity.get("email") else ""
            out.append(Alert(("payment_received",), f"Payment received: {money(value, entity.get('currency'))}{who} ({entity.get('provider', 'webhook')})"))
        elif name == "payment_failed":
            why = f". Reason: {entity['reason']}" if entity.get("reason") else ""
            out.append(Alert(("payment_failed",), f"Payment failed: {money(value, entity.get('currency'))}{why}"))
        elif name == "review":
            stars = int(value or 0)
            author = f" from {entity['author']}" if entity.get("author") else ""
            body = f': "{text[:240]}"' if text else ""
            events = ("low_review", "new_review") if stars <= 3 else ("new_review",)
            out.append(Alert(events, f"New {stars}-star Google review{author}{body}"))
        elif name == "rating" and previous_rating is not None and isinstance(value, (int, float)) and value < previous_rating:
            out.append(Alert(("rating_drop",), f"Your Google rating dropped from {previous_rating:.1f} to {value:.1f}"))
        elif name == "comment" and not entity.get("mine") and BUYING.search(text):
            out.append(Alert(("buying_comment",), f'Buying interest on YouTube from {entity.get("author") or "someone"}: "{text[:240]}"'))
        elif name == "telegram_message":
            who = entity.get("from") or "someone"
            events = ("buying_comment", "new_message") if BUYING.search(text) else ("new_message",)
            out.append(Alert(events, f'Telegram message from {who}: "{text[:240]}"'))
    return out


def dispatch(db, org_id: str, alerts: list, secret_of) -> int:
    """Sends every alert to each connected alert connection of the organization that listens for it. Returns how many messages went out.
    `secret_of(connection_id)` returns the decrypted secret. Never raises."""
    if not alerts:
        return 0
    sent = 0
    try:
        rows = db.table("connections").select("*").eq("owner_id", org_id).eq("status", "connected").execute().data or []
    except Exception:
        log.exception("could not look up alert connections")
        return 0
    from . import registry
    for conn in rows:
        connector = registry.get(conn.get("provider"))
        if not connector or connector.category != "alerts":
            continue
        listening = set((conn.get("config") or {}).get("events") or DEFAULT_EVENTS)
        try:
            secret = secret_of(conn["id"])
        except Exception:
            continue
        for alert in alerts:
            if not listening.intersection(alert.events):
                continue
            try:
                connector.send(conn, secret, alert.text)
                sent += 1
                db.table("signals").insert({"owner_id": org_id, "connection_id": conn["id"], "provider": conn["provider"], "kind": "event", "name": "alert_sent",
                                            "text_value": alert.text[:300], "entity": {"event": alert.events[0]}}).execute()
            except Exception as err:
                log.warning("alert to %s failed: %s", conn.get("provider"), err)
    return sent


def clean_events(events) -> list:
    """Only known event names, in the catalogue's order."""
    wanted = set(events) if isinstance(events, (list, tuple, set)) else set()
    return [e["value"] for e in ALERT_EVENTS if e["value"] in wanted]


class _AlertConnector(Connector):
    channel = "alerts"
    category = "alerts"
    syncable = False
    settings = ("events",)
    extra = {"events": ALERT_EVENTS, "default_events": DEFAULT_EVENTS}
    actions = [Action("test_alert", "Send a test alert", "Sends a short test message so you can see it arrives.")]

    def send(self, connection: dict, secret: Optional[str], text: str) -> None:
        raise NotImplementedError

    def action(self, connection: dict, secret: Optional[str], name: str, params: dict, ctx: Context) -> dict:
        if name != "test_alert":
            raise ConnectorError("This connection does not do that.")
        self.send(connection, secret, "Test alert from Raptor. If you can read this, alerts are working.")
        return {"ok": True}


def _url_of(secret: Optional[str]) -> str:
    try:
        return str((json.loads(secret or "{}") or {}).get("url") or "")
    except ValueError:
        return ""


class Slack(_AlertConnector):
    provider = "slack"
    title = "Slack"
    description = "Post an alert to a Slack channel whenever something worth knowing happens."
    fields = [Field("webhook_url", "Slack webhook address", "https://hooks.slack.com/services/…", "Stored encrypted and never shown again.", secret=True)]
    help = [
        "In Slack open api.slack.com/apps, create an app (From scratch), and turn on “Incoming Webhooks”.",
        "Choose “Add New Webhook to Workspace”, pick the channel the alerts should go to, and copy the address.",
        "Paste it here. Raptor sends a first message to the channel to prove it works.",
        "Then tick which events you want to hear about.",
    ]
    HOSTS = ("hooks.slack.com",)

    def connect(self, inputs: dict) -> ConnectResult:
        url = (inputs.get("webhook_url") or "").strip()
        net.assert_public_url(url, self.HOSTS)
        if not url.startswith("https://hooks.slack.com/services/"):
            raise ConnectorError("A Slack webhook address looks like https://hooks.slack.com/services/…  Copy it again from Slack.")
        self.send({}, json.dumps({"url": url}), "Raptor is connected. Alerts will appear in this channel.")
        return ConnectResult(external_id=hashlib.sha1(url.encode()).hexdigest()[:20], label="Slack", config={"events": DEFAULT_EVENTS}, secret=json.dumps({"url": url}))

    def send(self, connection: dict, secret: Optional[str], text: str) -> None:
        resp = net.post_json(_url_of(secret), {"text": text[:3000]}, self.HOSTS)
        if resp.status_code != 200:
            raise ConnectorError("Slack did not accept the message (%s). The webhook may have been removed; create a new one." % resp.status_code)


class Teams(_AlertConnector):
    provider = "teams"
    title = "Microsoft Teams"
    description = "Post an alert to a Teams channel whenever something worth knowing happens."
    fields = [Field("webhook_url", "Teams webhook address", "https://….webhook.office.com/… or a Workflows address", "Stored encrypted and never shown again.", secret=True)]
    help = [
        "In Teams open the channel, choose the three dots, Workflows, and pick “Post to a channel when a webhook request is received”.",
        "Finish the short setup and copy the web address Teams gives you. (An older “Incoming Webhook” connector address also works.)",
        "Paste it here. Raptor sends a first message to the channel to prove it works.",
        "Then tick which events you want to hear about.",
    ]
    HOSTS = ("webhook.office.com", "outlook.office.com", "logic.azure.com", "powerplatform.com")

    @staticmethod
    def _payload(url: str, text: str) -> dict:
        host = url.split("/")[2].lower() if "//" in url else ""
        if host.endswith("logic.azure.com") or host.endswith("powerplatform.com"):       # Workflows expects an Adaptive Card
            return {"type": "message", "attachments": [{"contentType": "application/vnd.microsoft.card.adaptive", "content": {
                "type": "AdaptiveCard", "version": "1.4", "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                "body": [{"type": "TextBlock", "text": text[:3000], "wrap": True}]}}]}
        return {"text": text[:3000]}

    def connect(self, inputs: dict) -> ConnectResult:
        url = (inputs.get("webhook_url") or "").strip()
        net.assert_public_url(url, self.HOSTS)
        self.send({}, json.dumps({"url": url}), "Raptor is connected. Alerts will appear in this channel.")
        return ConnectResult(external_id=hashlib.sha1(url.encode()).hexdigest()[:20], label="Microsoft Teams", config={"events": DEFAULT_EVENTS}, secret=json.dumps({"url": url}))

    def send(self, connection: dict, secret: Optional[str], text: str) -> None:
        url = _url_of(secret)
        resp = net.post_json(url, self._payload(url, text), self.HOSTS)
        if resp.status_code not in (200, 201, 202):
            raise ConnectorError("Teams did not accept the message (%s). The webhook may have been removed; create a new one." % resp.status_code)


TELEGRAM_API = "https://api.telegram.org"


def _public_api() -> str:
    return os.environ.get("PUBLIC_API_URL", "https://websites-api-5wmu.onrender.com").rstrip("/")


def _telegram(token: str, method: str, payload: Optional[dict] = None) -> dict:
    try:
        resp = httpx.post(f"{TELEGRAM_API}/bot{token}/{method}", json=payload or {}, timeout=20)
    except httpx.HTTPError:
        raise ConnectorError("Could not reach Telegram right now. Try again in a minute.")
    data = {}
    try:
        data = resp.json()
    except ValueError:
        pass
    if resp.status_code != 200 or not data.get("ok"):
        if resp.status_code in (401, 404):
            raise ConnectorError("Telegram did not accept this bot token. Copy it again from BotFather.")
        raise ConnectorError("Telegram said: %s" % (data.get("description") or resp.status_code))
    return data.get("result")


def _creds(secret: Optional[str]) -> dict:
    try:
        return json.loads(secret or "{}") or {}
    except ValueError:
        return {}


class Telegram(_AlertConnector):
    provider = "telegram"
    title = "Telegram"
    channel = "telegram"
    description = "Get alerts in Telegram, and let people message your bot so their messages land in Raptor."
    inbound = True
    fields = [Field("bot_token", "Bot token", "123456:ABC-DEF…", "From BotFather. Stored encrypted and never shown again.", secret=True)]
    help = [
        "In Telegram open a chat with @BotFather and send /newbot. Follow the steps and copy the bot token it gives you.",
        "Paste the token here. Raptor connects the bot to your account.",
        "Open your new bot in Telegram and send it /start. That tells Raptor where to send alerts.",
        "Then press “Send a test alert”. Messages people send to your bot also appear in Raptor.",
    ]

    def connect(self, inputs: dict) -> ConnectResult:
        token = (inputs.get("bot_token") or "").strip()
        if not re.match(r"^\d{5,}:[A-Za-z0-9_-]{20,}$", token):
            raise ConnectorError("A bot token looks like 123456789:ABCdef… Copy it again from BotFather.")
        me = _telegram(token, "getMe")
        webhook_secret = secrets.token_urlsafe(24)
        return ConnectResult(external_id=secrets.token_urlsafe(24), label="Telegram @" + str(me.get("username") or "bot"),
                             config={"bot_username": me.get("username") or "", "events": DEFAULT_EVENTS, "chat_id": None},
                             secret=json.dumps({"bot_token": token, "webhook_secret": webhook_secret}))

    def post_connect(self, connection: dict, secret: Optional[str]) -> None:
        c = _creds(secret)
        _telegram(c.get("bot_token", ""), "setWebhook", {
            "url": f"{_public_api()}/api/raptor/hooks/{connection['external_id']}", "secret_token": c.get("webhook_secret"), "allowed_updates": ["message"],
        })

    def revoke(self, secret: Optional[str]) -> None:
        try:
            _telegram(_creds(secret).get("bot_token", ""), "deleteWebhook")
        except ConnectorError:
            pass

    def send(self, connection: dict, secret: Optional[str], text: str) -> None:
        chat_id = (connection.get("config") or {}).get("chat_id")
        if not chat_id:
            raise ConnectorError("Open your bot in Telegram and send it /start first, then try again. Raptor needs that to know where to send alerts.")
        _telegram(_creds(secret).get("bot_token", ""), "sendMessage", {"chat_id": chat_id, "text": text[:4000]})

    def ingest(self, connection: dict, secret: Optional[str], body: bytes, headers: dict) -> tuple:
        c = _creds(secret)
        given = {str(k).lower(): v for k, v in (headers or {}).items()}.get("x-telegram-bot-api-secret-token", "")
        if not c.get("webhook_secret") or not secrets.compare_digest(str(given), str(c["webhook_secret"])):
            raise ConnectorError("signature")
        try:
            update = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            raise ConnectorError("That message is not valid JSON.")
        message = (update or {}).get("message") or {}
        text = (message.get("text") or "").strip()
        chat = message.get("chat") or {}
        if not text or not chat.get("id"):
            return [], {}
        sender = message.get("from") or {}
        who = sender.get("username") and "@" + sender["username"] or sender.get("first_name") or "someone"
        patch = {}
        if text.startswith("/start") and chat.get("type") == "private":
            patch = {"chat_id": chat["id"]}
            try:
                _telegram(c.get("bot_token", ""), "sendMessage", {"chat_id": chat["id"], "text": "Connected to Raptor. Alerts will arrive in this chat."})
            except ConnectorError:
                pass
        signal = Signal("mention", "telegram_message", text_value=text[:1000], entity={"chat_id": chat["id"], "from": who}, dedupe_key=f"tg:{update.get('update_id')}")
        return [signal], patch


register(Slack())
register(Teams())
register(Telegram())
