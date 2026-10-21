"""SMS with the customer's own Twilio account. Raptor sends a text message FROM their number using THEIR key, so the cost and the
sender identity are theirs; the account SID and auth token are stored encrypted and never shown again.

Sending, receiving replies, STOP handling, sequences and auto-replies live in raptor/sms (engine.py, router.py): this connector only
checks the keys, stores them encrypted and points the Twilio number's incoming-message webhook at Raptor."""
from __future__ import annotations

import json
import re
from typing import Optional

import httpx

from .registry import Action, ConnectResult, Connector, ConnectorError, Context, Field, Signal, register

API = "https://api.twilio.com/2010-04-01/Accounts"
DAILY_CAP = 200
MAX_TEXT = 600
_E164 = re.compile(r"^\+[1-9]\d{7,14}$")
_SID = re.compile(r"^AC[0-9a-fA-F]{32}$")


def _creds(secret: Optional[str]) -> dict:
    try:
        return json.loads(secret or "{}") or {}
    except ValueError:
        return {}


def normalize_number(raw: str) -> str:
    """Spaces, dashes and brackets are removed. The number must carry its country code: +91 98765 43210."""
    cleaned = re.sub(r"[\s().-]", "", raw or "")
    if not _E164.match(cleaned):
        raise ConnectorError("Type the number with its country code, for example +919876543210.")
    return cleaned


class Twilio(Connector):
    provider = "sms_twilio"
    channel = "sms"
    title = "SMS (Twilio)"
    description = "Send text messages from your own Twilio number. You pay Twilio directly; Raptor only sends."
    category = "channel"
    syncable = False
    fields = [
        Field("account_sid", "Account SID", "AC…", "On your Twilio console home page."),
        Field("auth_token", "Auth token", "", "On the same page. Stored encrypted and never shown again.", secret=True),
        Field("from_number", "Your Twilio number", "+1…", "The number messages are sent from, with its country code."),
    ]
    help = [
        "Create a Twilio account and buy or verify a phone number that can send SMS to your customers' country.",
        "From the Twilio console copy your Account SID and Auth token, and the number you will send from.",
        "Paste them here. Raptor checks them with Twilio before saving, then points the number's incoming-message webhook at Raptor so replies and STOP reach you.",
        "Only text people who agreed to hear from you. Texts go to one person at a time, and anyone who replies STOP is never texted again.",
        "In India, marketing SMS also needs DLT registration of your sender and templates with your carrier.",
    ]
    actions = []

    def connect(self, inputs: dict) -> ConnectResult:
        sid = (inputs.get("account_sid") or "").strip()
        token = (inputs.get("auth_token") or "").strip()
        from_number = normalize_number(inputs.get("from_number") or "")
        if not _SID.match(sid):
            raise ConnectorError("An Account SID starts with AC and has 34 characters. Copy it again from the Twilio console.")
        if len(token) < 16:
            raise ConnectorError("Paste your Twilio auth token.")
        try:
            resp = httpx.get(f"{API}/{sid}.json", auth=(sid, token), timeout=20)
        except httpx.HTTPError:
            raise ConnectorError("Could not reach Twilio right now. Try again in a minute.")
        if resp.status_code in (401, 403):
            raise ConnectorError("Twilio did not accept this SID and token. Copy them again from the Twilio console.")
        if resp.status_code != 200:
            raise ConnectorError("Twilio did not accept the request (%s)." % resp.status_code)
        return ConnectResult(external_id=sid, label=f"Twilio {from_number}", config={"from_number": from_number}, secret=json.dumps({"account_sid": sid, "auth_token": token}))

    def post_connect(self, connection: dict, secret: Optional[str]) -> None:
        """Best effort: point the number's "a message comes in" webhook at Raptor so replies and STOP arrive. If Twilio has no such number
        on the account (a sender ID, a Messaging Service) the person pastes the address into Twilio themselves; the SMS page shows it."""
        try:
            from raptor.connections import meta, router as connections_router
            from raptor.sms import engine
            ok = engine.configure_webhook(_creds(secret), (connection.get("config") or {}).get("from_number", ""),
                                          engine.inbound_url(meta.public_api(), connection["id"]))
            connections_router._db().table("connections").update({"config": {**(connection.get("config") or {}), "webhook_set": ok}}).eq("id", connection["id"]).execute()
        except Exception:                                    # never blocks connecting
            return None


register(Twilio())
