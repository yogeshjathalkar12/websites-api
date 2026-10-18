"""Payments and webhooks: data that other services PUSH to Raptor.

Each connection gets its own secret address (/api/raptor/hooks/<token>) that the customer pastes into Razorpay, Stripe or any tool
that can send a webhook (Zapier, Make, n8n, their own website). What arrives is checked, turned into signals (a payment becomes revenue,
a failed payment, a refund), and stored. Payment providers sign what they send; Raptor refuses anything whose signature does not match
the customer's own signing secret, so nobody can fake revenue by guessing the address.

The router in hooks.py is the only public door; it finds the connection by its token and calls ingest() here."""
from __future__ import annotations

import hashlib
import hmac
import json
import re
import secrets
import time
from datetime import datetime, timezone
from typing import Optional

from .registry import ConnectResult, Connector, ConnectorError, Field, Signal, register

MAX_BODY = 262_144
STRIPE_TOLERANCE_SECONDS = 300
ZERO_DECIMAL = {"BIF", "CLP", "DJF", "GNF", "JPY", "KMF", "KRW", "MGA", "PYG", "RWF", "UGX", "VND", "VUV", "XAF", "XOF", "XPF"}
THREE_DECIMAL = {"BHD", "JOD", "KWD", "OMR", "TND"}
# event names a person may send themselves (Zapier, Make, their own site) and have counted as revenue or leads
KNOWN_EVENTS = {"payment_received", "payment_failed", "refund", "lead_created"}


def minor_to_major(amount, currency: str) -> float:
    """Payment providers send money in the smallest unit (paise, cents). Returns the amount a person would read."""
    value = float(amount or 0)
    code = (currency or "").upper()
    if code in ZERO_DECIMAL:
        return value
    return value / (1000 if code in THREE_DECIMAL else 100)


def _hmac_hex(key: str, message: bytes) -> str:
    return hmac.new(key.encode(), message, hashlib.sha256).hexdigest()


def _secret_of(secret: Optional[str]) -> str:
    try:
        return str((json.loads(secret or "{}") or {}).get("signing_secret") or "")
    except ValueError:
        return ""


def _json_body(body: bytes) -> dict:
    if len(body) > MAX_BODY:
        raise ConnectorError("That message is too large.")
    try:
        data = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise ConnectorError("That message is not valid JSON.")
    if not isinstance(data, dict):
        raise ConnectorError("That message is not a JSON object.")
    return data


def _lower_headers(headers: dict) -> dict:
    return {str(k).lower(): v for k, v in (headers or {}).items()}


def _when(epoch) -> Optional[datetime]:
    try:
        return datetime.fromtimestamp(float(epoch), tz=timezone.utc)
    except (TypeError, ValueError, OverflowError, OSError):
        return None


def _new_token() -> str:
    return secrets.token_urlsafe(24)


class _Inbound(Connector):
    inbound = True
    syncable = False
    category = "data"
    channel = "payments"
    secret_required = True
    signing_label = "Signing secret"
    signing_help = ""

    def connect(self, inputs: dict) -> ConnectResult:
        signing = (inputs.get("signing_secret") or "").strip()
        if self.secret_required and len(signing) < 8:
            raise ConnectorError(f"Paste the {self.signing_label.lower()} from {self.title}. Without it anyone could send fake payments to Raptor.")
        if len(signing) > 300:
            raise ConnectorError("That secret is too long.")
        return ConnectResult(external_id=_new_token(), label=self.title, config={}, secret=json.dumps({"signing_secret": signing}))


class Razorpay(_Inbound):
    provider = "razorpay"
    title = "Razorpay"
    description = "Every captured payment, failed payment and refund from your Razorpay account becomes revenue in Raptor."
    signing_label = "Webhook secret"
    fields = [Field("signing_secret", "Webhook secret", "the secret you set on the Razorpay webhook", "Stored encrypted and never shown again.", secret=True)]
    help = [
        "Connect here first. Raptor then shows you a webhook address that belongs only to you.",
        "In Razorpay open Settings, Webhooks, Add new webhook. Paste the address and choose a secret of your own.",
        "Tick the events payment.captured, payment.failed and refund.processed, then save.",
        "Paste the same secret in the box here. Raptor refuses any message whose signature does not match it.",
    ]

    def ingest(self, connection: dict, secret: Optional[str], body: bytes, headers: dict) -> tuple:
        signing = _secret_of(secret)
        given = _lower_headers(headers).get("x-razorpay-signature", "")
        if not signing or not hmac.compare_digest(_hmac_hex(signing, body), given):
            raise ConnectorError("signature")
        data = _json_body(body)
        event = str(data.get("event") or "")
        payload = data.get("payload") or {}
        out = []
        if event in ("payment.captured", "payment.failed"):
            p = (payload.get("payment") or {}).get("entity") or {}
            if not p.get("id"):
                return [], {}
            value = minor_to_major(p.get("amount"), p.get("currency", "INR"))
            entity = {"provider": "razorpay", "id": p["id"], "currency": p.get("currency", "INR"), "email": p.get("email") or "", "phone": p.get("contact") or "", "method": p.get("method") or ""}
            if event == "payment.captured":
                out.append(Signal("event", "payment_received", value, text_value=(p.get("description") or "")[:200], entity=entity, occurred_at=_when(p.get("created_at")), dedupe_key=f"rzp:{p['id']}"))
            else:
                entity["reason"] = (p.get("error_description") or "")[:200]
                out.append(Signal("event", "payment_failed", value, text_value=entity["reason"], entity=entity, occurred_at=_when(p.get("created_at")), dedupe_key=f"rzp:fail:{p['id']}"))
        elif event == "refund.processed":
            r = (payload.get("refund") or {}).get("entity") or {}
            if r.get("id"):
                out.append(Signal("event", "refund", minor_to_major(r.get("amount"), r.get("currency", "INR")), entity={"provider": "razorpay", "id": r["id"], "payment_id": r.get("payment_id", ""), "currency": r.get("currency", "INR")},
                                  occurred_at=_when(r.get("created_at")), dedupe_key=f"rzp:refund:{r['id']}"))
        return out, {}


class Stripe(_Inbound):
    provider = "stripe"
    title = "Stripe"
    description = "Every successful payment, failed payment and refund from your Stripe account becomes revenue in Raptor."
    signing_label = "Signing secret"
    fields = [Field("signing_secret", "Signing secret", "whsec_…", "From the webhook endpoint in Stripe. Stored encrypted and never shown again.", secret=True)]
    help = [
        "Connect here first. Raptor then shows you a webhook address that belongs only to you.",
        "In Stripe open Developers, Webhooks, Add endpoint. Paste the address.",
        "Choose the events payment_intent.succeeded, payment_intent.payment_failed and charge.refunded, then add the endpoint.",
        "Copy the endpoint's Signing secret (it starts with whsec_) and paste it in the box here.",
    ]

    def ingest(self, connection: dict, secret: Optional[str], body: bytes, headers: dict) -> tuple:
        signing = _secret_of(secret)
        header = _lower_headers(headers).get("stripe-signature", "")
        parts = [p.split("=", 1) for p in header.split(",") if "=" in p]
        stamp = next((v for k, v in parts if k == "t"), "")
        signatures = [v for k, v in parts if k == "v1"]
        if not signing or not stamp.isdigit() or not signatures:
            raise ConnectorError("signature")
        expected = _hmac_hex(signing, stamp.encode() + b"." + body)
        if not any(hmac.compare_digest(expected, s) for s in signatures):
            raise ConnectorError("signature")
        if abs(time.time() - int(stamp)) > STRIPE_TOLERANCE_SECONDS:
            raise ConnectorError("signature")                      # an old, replayed message
        data = _json_body(body)
        event = str(data.get("type") or "")
        obj = (data.get("data") or {}).get("object") or {}
        if not obj.get("id"):
            return [], {}
        currency = obj.get("currency", "usd")
        entity = {"provider": "stripe", "id": obj["id"], "currency": str(currency).upper(), "email": obj.get("receipt_email") or ""}
        when = _when(data.get("created"))
        if event == "payment_intent.succeeded":
            return [Signal("event", "payment_received", minor_to_major(obj.get("amount_received") or obj.get("amount"), currency), text_value=(obj.get("description") or "")[:200], entity=entity, occurred_at=when, dedupe_key=f"stripe:{obj['id']}")], {}
        if event == "payment_intent.payment_failed":
            reason = ((obj.get("last_payment_error") or {}).get("message") or "")[:200]
            return [Signal("event", "payment_failed", minor_to_major(obj.get("amount"), currency), text_value=reason, entity={**entity, "reason": reason}, occurred_at=when, dedupe_key=f"stripe:fail:{obj['id']}")], {}
        if event == "charge.refunded":
            return [Signal("event", "refund", minor_to_major(obj.get("amount_refunded"), currency), entity={**entity, "payment_id": obj.get("payment_intent") or ""}, occurred_at=when, dedupe_key=f"stripe:refund:{obj['id']}:{obj.get('amount_refunded')}")], {}
        return [], {}


class GenericWebhook(_Inbound):
    provider = "webhook"
    title = "Webhook"
    description = "Send anything from Zapier, Make, n8n or your own website: payments, sign-ups, form entries. It shows up as events and revenue."
    secret_required = False
    signing_label = "Signing secret"
    fields = [Field("signing_secret", "Signing secret (optional)", "a password only you know", "If you set one, every message must carry a matching signature. Stored encrypted and never shown again.", secret=True, required=False)]
    help = [
        "Connect here. Raptor shows you a webhook address that belongs only to you.",
        "In Zapier, Make or n8n add a step “Webhooks, send a POST request” to that address, with a JSON body.",
        "Useful fields: event (for example payment_received, lead_created), value (a number), currency, email, text, id.",
        "To count a payment as revenue, send event payment_received with a value. To be safe against fakes, set a signing secret and send the header X-Raptor-Signature: sha256=<HMAC of the body>.",
    ]

    def ingest(self, connection: dict, secret: Optional[str], body: bytes, headers: dict) -> tuple:
        signing = _secret_of(secret)
        if signing:
            given = _lower_headers(headers).get("x-raptor-signature", "").removeprefix("sha256=")
            if not hmac.compare_digest(_hmac_hex(signing, body), given):
                raise ConnectorError("signature")
        data = _json_body(body)
        event = re.sub(r"[^a-z0-9_.-]", "_", str(data.get("event") or "webhook_event").lower())[:60] or "webhook_event"
        name = event if event in KNOWN_EVENTS else "webhook_event"
        value = data.get("value")
        value = float(value) if isinstance(value, (int, float)) and not isinstance(value, bool) else None
        entity = {"provider": "webhook", "event": event}
        for k, v in list(data.items())[:20]:
            if k in ("event", "value", "text") or not isinstance(v, (str, int, float, bool)):
                continue
            entity[str(k)[:40]] = v[:200] if isinstance(v, str) else v
        text = data.get("text")
        text = text[:500] if isinstance(text, str) else None
        ident = data.get("id")
        dedupe = f"hook:{ident}" if isinstance(ident, (str, int)) and str(ident) else None
        return [Signal("event", name, value, text_value=text, entity=entity, occurred_at=datetime.now(timezone.utc), dedupe_key=dedupe)], {}


register(Razorpay())
register(Stripe())
register(GenericWebhook())
