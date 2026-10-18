"""SMS with the customer's own Twilio account. Raptor sends a text message FROM their number using THEIR key, so the cost and the
sender identity are theirs; the account SID and auth token are stored encrypted and never shown again.

A daily cap per connection protects against a runaway sender, and every message sent is logged as a signal."""
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
        "Paste them here. Raptor checks them with Twilio before saving.",
        "Only text people who agreed to hear from you. In India, bulk marketing SMS also needs DLT registration with your carrier.",
    ]
    actions = [Action("send", "Send a text message", "Sends one message from your number.", [
        Field("to", "To", "+919876543210", "With the country code."),
        Field("text", "Message", "", f"Up to {MAX_TEXT} characters.", multiline=True),
    ])]

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

    def action(self, connection: dict, secret: Optional[str], name: str, params: dict, ctx: Context) -> dict:
        if name != "send":
            raise ConnectorError("This connection does not do that.")
        to = normalize_number(params.get("to") or "")
        text = (params.get("text") or "").strip()
        if not text:
            raise ConnectorError("Write the message first.")
        if len(text) > MAX_TEXT:
            raise ConnectorError(f"A message can be up to {MAX_TEXT} characters.")
        if ctx.count_today("sms_sent") >= DAILY_CAP:
            raise ConnectorError("Daily message limit reached. Try again tomorrow.")
        c = _creds(secret)
        try:
            resp = httpx.post(f"{API}/{c.get('account_sid')}/Messages.json", auth=(c.get("account_sid", ""), c.get("auth_token", "")), timeout=20,
                              data={"To": to, "From": (connection.get("config") or {}).get("from_number", ""), "Body": text})
        except httpx.HTTPError:
            raise ConnectorError("Could not reach Twilio right now. The message was not sent; try again.")
        body = {}
        try:
            body = resp.json()
        except ValueError:
            pass
        if resp.status_code not in (200, 201):
            raise ConnectorError("Twilio did not send it: %s" % (body.get("message") or resp.status_code))
        sid = body.get("sid") or ""
        ctx.record(Signal("event", "sms_sent", text_value=text[:200], entity={"to": to, "sid": sid, "status": body.get("status", "")}, dedupe_key=f"sms:{sid}" if sid else None))
        return {"ok": True, "sid": sid}


register(Twilio())
