"""The SMS engine: sends one text at a time from the customer's own Twilio number, receives their replies, and keeps the rules that
make this targeted instead of a blast.

  * Every text goes to ONE number a person chose (a pipeline card, an enrolment of chosen deals, a reply). There is no broadcast.
  * A number that texted STOP is never messaged again until it texts START (checked again right before every send).
  * Sending hours (in the organization's own time zone) and a daily limit apply to everything Raptor starts. Replies to a person
    who just wrote to us are exempt from the hours but not from the limit.
  * A sequence stops by itself when the person answers or opts out.
  * One claim per message: two open tabs or a cron run at the same moment can never send the same text twice, and a text whose
    outcome is unknown (the process died mid-send) is marked failed instead of being sent again.

The functions take the database client (`db`, a Supabase client) as their first argument so they can be tested with a small fake;
nothing here reads the environment except where noted. Twilio is called with httpx."""
from __future__ import annotations

import base64
import hashlib
import hmac
import logging
import re
from datetime import datetime, timedelta, timezone
from typing import Callable, Optional
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

import httpx

from raptor.connections import sms as connector
from raptor.connections.registry import Signal

log = logging.getLogger(__name__)

API = connector.API
MAX_TEXT = connector.MAX_TEXT
DAILY_CAP = connector.DAILY_CAP
ENROLL_LIMIT = 25                  # most deals that can be put into a sequence in one go: chosen people, not a list
CRM_BATCH = 5
CRM_MAX_ATTEMPTS = 5
STALE_SENDING_MINUTES = 10
AUTOREPLY_GAP_MINUTES = 10         # the same number gets at most one automatic answer per gap...
AUTOREPLY_PER_DAY = 3              # ...and three per day (stops two auto-responders from talking to each other forever)
STOP_WORDS = {"stop", "stopall", "unsubscribe", "cancel", "end", "quit", "optout", "opt out"}
START_WORDS = {"start", "unstop"}
STATUS_RANK = {"queued": 0, "sent": 1, "undelivered": 2, "failed": 2, "delivered": 3}
TWILIO_STATUS = {"accepted": "queued", "queued": "queued", "sending": "sent", "sent": "sent", "delivered": "delivered",
                 "undelivered": "undelivered", "failed": "failed"}
DEFAULTS = {"mode": "off", "template": "", "country_code": "91", "sequence_id": None, "daily_limit": 100, "send_from_hour": 9,
            "send_until_hour": 21, "timezone": "Asia/Kolkata", "autoreply_enabled": True, "connection_id": None, "opt_in_confirmed_at": None}
TWILIO_REASONS = {
    21610: "This person opted out of text messages from your number.",
    21211: "Twilio says this is not a valid phone number.",
    21614: "Twilio says this number cannot receive text messages.",
    21408: "Your Twilio account is not allowed to text this country. Turn the country on in Twilio's geo permissions.",
    21608: "Your Twilio account is a trial and can only text numbers you have verified in Twilio.",
    21612: "Twilio cannot send from your number to this one.",
    21617: "The message is too long for Twilio.",
    30003: "The phone is switched off or out of reach.",
    30004: "The phone or carrier blocked the message.",
    30005: "The number does not exist or is not in use.",
    30006: "The number is a landline or cannot receive text messages.",
    30007: "The carrier filtered the message as spam. Check your sender registration (in India: DLT).",
}


class SendError(Exception):
    """The message was not sent. `temporary` means trying again later may work (a network problem, Twilio busy)."""

    def __init__(self, message: str, temporary: bool = False, code: str = ""):
        super().__init__(message)
        self.temporary, self.code = temporary, code


class Wait(Exception):
    """Not now: outside the sending hours, or today's limit is used. The message stays queued and goes out later."""


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def to_e164(raw: str, country_code: str = "91") -> Optional[str]:
    """The same rules as crm_sms_phone() in the database: +country code and digits, or None if it is not a usable number."""
    if not raw:
        return None
    digits = re.sub(r"\D", "", raw)
    if not digits:
        return None
    cc = re.sub(r"\D", "", country_code or "") or "91"
    if raw.strip().startswith("+"):
        pass
    elif digits.startswith("00"):
        digits = digits[2:]
    elif len(digits) == 10:
        digits = cc + digits
    elif digits.startswith("0") and len(digits) == 11:
        digits = cc + digits[1:]
    if len(digits) < 8 or len(digits) > 15:
        return None
    return "+" + digits


def render(template: str, variables: dict) -> str:
    """{{first_name}} style tags filled from `variables`; unknown tags disappear."""
    text = template or ""
    for key, value in (variables or {}).items():
        text = text.replace("{{" + key + "}}", str(value or ""))
    text = re.sub(r"\{\{[a-z_]+\}\}", "", text)
    return re.sub(r" {2,}", " ", text).strip()


def contact_variables(contact: dict, company: str = "", deal_title: str = "") -> dict:
    name = (contact.get("name") or "").strip()
    first = (contact.get("first_name") or "").strip() or (name.split(" ")[0] if name else "") or "there"
    return {"first_name": first, "last_name": (contact.get("last_name") or "").strip(), "name": name or first,
            "company": (company or "").strip() or "your company", "deal_title": (deal_title or "").strip()}


# ───────────────────────────── settings, hours, limits ─────────────────────────────

def settings_for(db, org_id: str) -> dict:
    rows = db.table("sms_settings").select("*").eq("owner_id", org_id).limit(1).execute().data or []
    return {**DEFAULTS, **(rows[0] if rows else {})}


def _zone(settings: dict) -> ZoneInfo:
    for name in (settings.get("timezone"), "Asia/Kolkata", "UTC"):
        try:
            return ZoneInfo(name or "UTC")
        except (ZoneInfoNotFoundError, ValueError):
            continue
    return timezone.utc  # type: ignore[return-value]


def in_sending_hours(settings: dict, now: datetime) -> bool:
    hour = now.astimezone(_zone(settings)).hour
    return int(settings["send_from_hour"]) <= hour < int(settings["send_until_hour"])


def sent_today(db, org_id: str, connection_id: str, settings: dict, now: datetime) -> int:
    local = now.astimezone(_zone(settings))
    start = local.replace(hour=0, minute=0, second=0, microsecond=0).astimezone(timezone.utc)
    rows = (db.table("sms_messages").select("id", count="exact").eq("owner_id", org_id).eq("connection_id", connection_id)
            .eq("direction", "out").neq("status", "failed").gte("created_at", start.isoformat()).execute())
    return rows.count if rows.count is not None else len(rows.data or [])


def daily_cap(settings: dict) -> int:
    return min(int(settings["daily_limit"]), DAILY_CAP)


def is_opted_out(db, org_id: str, phone: str) -> bool:
    return bool(db.table("sms_optouts").select("phone").eq("owner_id", org_id).eq("phone", phone).limit(1).execute().data)


# ───────────────────────────── Twilio ─────────────────────────────

def status_callback_url(public_api: str, connection_id: str) -> str:
    return f"{public_api}/api/raptor/sms/hook/{connection_id}/status"


def inbound_url(public_api: str, connection_id: str) -> str:
    return f"{public_api}/api/raptor/sms/hook/{connection_id}/inbound"


def twilio_send(creds: dict, from_number: str, to: str, body: str, callback: str = "") -> dict:
    data = {"To": to, "From": from_number, "Body": body}
    if callback:
        data["StatusCallback"] = callback
    try:
        resp = httpx.post(f"{API}/{creds.get('account_sid')}/Messages.json", auth=(creds.get("account_sid", ""), creds.get("auth_token", "")),
                          data=data, timeout=20)
    except httpx.HTTPError:
        raise SendError("Could not reach Twilio right now. The message was not sent.", temporary=True)
    try:
        payload = resp.json()
    except ValueError:
        payload = {}
    if resp.status_code in (200, 201):
        return payload
    code = payload.get("code")
    reason = TWILIO_REASONS.get(code) or ("Twilio did not send it: %s" % (payload.get("message") or resp.status_code))
    raise SendError(reason, temporary=resp.status_code == 429 or resp.status_code >= 500, code=str(code or resp.status_code))


def valid_signature(auth_token: str, url: str, params: dict, signature: str) -> bool:
    """Twilio signs every webhook: HMAC-SHA1 of the full URL followed by each form field (sorted by name) as name+value."""
    if not signature or not auth_token:
        return False
    text = url + "".join(f"{k}{params[k]}" for k in sorted(params))
    digest = hmac.new(auth_token.encode(), text.encode(), hashlib.sha1).digest()
    return hmac.compare_digest(base64.b64encode(digest).decode(), signature)


def configure_webhook(creds: dict, number: str, url: str) -> bool:
    """Points the Twilio number's "a message comes in" webhook at Raptor. False when Twilio has no such number on this account
    (a sender ID, a Messaging Service): the person is then shown the address to paste into Twilio themselves."""
    auth = (creds.get("account_sid", ""), creds.get("auth_token", ""))
    base = f"{API}/{creds.get('account_sid')}/IncomingPhoneNumbers"
    try:
        found = httpx.get(f"{base}.json", auth=auth, params={"PhoneNumber": number}, timeout=20)
        rows = (found.json().get("incoming_phone_numbers") or []) if found.status_code == 200 else []
        if not rows:
            return False
        done = httpx.post(f"{base}/{rows[0]['sid']}.json", auth=auth, data={"SmsUrl": url, "SmsMethod": "POST"}, timeout=20)
        return done.status_code in (200, 201)
    except (httpx.HTTPError, ValueError, KeyError):
        return False


# ───────────────────────────── sending ─────────────────────────────

def _creds(secret: Optional[str]) -> dict:
    return connector._creds(secret)


def log_interaction(db, org_id: str, contact_id: Optional[str], direction: str, text: str) -> None:
    """A text shows on the CRM contact's timeline. Never lets a failure here break sending or receiving."""
    if not contact_id:
        return
    try:
        db.table("interactions").insert({"owner_id": org_id, "contact_id": contact_id, "type": "sms",
                                         "direction": "inbound" if direction == "in" else "outbound", "content": text[:2000]}).execute()
        db.table("contacts").update({"last_interaction_at": now_utc().isoformat()}).eq("id", contact_id).execute()
    except Exception as err:
        log.warning("could not log the text on contact %s: %s", contact_id, err)


def find_contact(db, org_id: str, phone: str) -> Optional[str]:
    try:
        return db.rpc("sms_find_contact", {"p_org": org_id, "p_phone": phone}).execute().data or None
    except Exception:
        return None


def send_text(db, *, org_id: str, connection: dict, secret: Optional[str], phone: str, body: str, source: str, settings: dict,
              public_api: str, record: Optional[Callable] = None, now: Optional[datetime] = None, check_hours: bool = True,
              deal_id: Optional[str] = None, contact_id: Optional[str] = None, enrollment_id: Optional[str] = None,
              step: Optional[int] = None, sent_by: Optional[str] = None) -> dict:
    """Sends one text and stores it. Raises Wait (not now) or SendError (not sent). Returns the stored message row."""
    now = now or now_utc()
    body = (body or "").strip()
    if not body:
        raise SendError("Write the message first.")
    if len(body) > MAX_TEXT:
        raise SendError(f"A message can be up to {MAX_TEXT} characters.")
    if is_opted_out(db, org_id, phone):
        raise SendError("This person opted out of text messages.", code="opted_out")
    if check_hours and not in_sending_hours(settings, now):
        raise Wait(f"Waiting for sending hours ({int(settings['send_from_hour']):02d}:00 to {int(settings['send_until_hour']):02d}:00 {settings['timezone']})")
    if sent_today(db, org_id, connection["id"], settings, now) >= daily_cap(settings):
        raise Wait("Today's text message limit is reached; it will go out tomorrow.")
    from_number = (connection.get("config") or {}).get("from_number", "")
    row = db.table("sms_messages").insert({
        "owner_id": org_id, "connection_id": connection["id"], "phone": phone, "direction": "out", "body": body, "status": "queued",
        "source": source, "contact_id": contact_id or find_contact(db, org_id, phone), "deal_id": deal_id, "enrollment_id": enrollment_id,
        "step": step, "sent_by": sent_by, "created_at": now.isoformat(), "updated_at": now.isoformat()}).execute().data[0]
    try:
        reply = twilio_send(_creds(secret), from_number, phone, body, status_callback_url(public_api, connection["id"]))
    except SendError as err:
        db.table("sms_messages").update({"status": "failed", "error": str(err)[:300], "updated_at": now_utc().isoformat()}).eq("id", row["id"]).execute()
        if record:
            record(Signal("event", "sms_failed", text_value=str(err)[:200], entity={"to": phone}))
        raise
    sid = reply.get("sid") or ""
    db.table("sms_messages").update({"status": "sent", "provider_sid": sid, "updated_at": now_utc().isoformat()}).eq("id", row["id"]).execute()
    row.update(status="sent", provider_sid=sid)
    if record:
        record(Signal("event", "sms_sent", text_value=body[:200], entity={"to": phone, "sid": sid, "source": source}, dedupe_key=f"sms:{sid}" if sid else None))
    log_interaction(db, org_id, row.get("contact_id"), "out", body)
    return row


# ───────────────────────────── what Twilio tells us ─────────────────────────────

def ingest_status(db, connection: dict, form: dict) -> dict:
    """Twilio reports queued -> sent -> delivered (or undelivered / failed). A later report never downgrades an earlier better one."""
    sid = form.get("MessageSid") or form.get("SmsSid") or ""
    status = TWILIO_STATUS.get((form.get("MessageStatus") or form.get("SmsStatus") or "").lower())
    if not sid or not status:
        return {"ok": True, "updated": 0}
    rows = db.table("sms_messages").select("*").eq("connection_id", connection["id"]).eq("provider_sid", sid).limit(1).execute().data or []
    if not rows:
        return {"ok": True, "updated": 0}
    current = rows[0]
    if STATUS_RANK.get(status, 0) <= STATUS_RANK.get(current["status"], 0):
        return {"ok": True, "updated": 0}
    update = {"status": status, "updated_at": now_utc().isoformat()}
    if status in ("undelivered", "failed"):
        code = form.get("ErrorCode")
        try:
            update["error"] = TWILIO_REASONS.get(int(code)) or (f"The carrier could not deliver this text (error {code})." if code else "The carrier could not deliver this text.")
        except (TypeError, ValueError):
            update["error"] = "The carrier could not deliver this text."
    db.table("sms_messages").update(update).eq("id", current["id"]).execute()
    return {"ok": True, "updated": 1, "status": status}


def _normal_word(body: str) -> str:
    return re.sub(r"[^a-z ]", "", (body or "").lower()).strip()


def stop_enrollments(db, org_id: str, phone: str, status: str, reason: str, only_stop_on_reply: bool = False) -> int:
    rows = db.table("sms_enrollments").select("*").eq("owner_id", org_id).eq("phone", phone).eq("status", "active").execute().data or []
    stopped = 0
    for row in rows:
        if only_stop_on_reply:
            seq = db.table("sms_sequences").select("stop_on_reply").eq("id", row["sequence_id"]).limit(1).execute().data or []
            if seq and seq[0].get("stop_on_reply") is False:
                continue
        db.table("sms_enrollments").update({"status": status, "stop_reason": reason, "updated_at": now_utc().isoformat()}).eq("id", row["id"]).execute()
        stopped += 1
    return stopped


def _match_autoreply(rules: list, text: str) -> Optional[dict]:
    word = (text or "").strip().lower()
    for rule in rules:
        keyword = (rule.get("keyword") or "").strip().lower()
        if not keyword or not rule.get("is_active", True):
            continue
        if (rule.get("match_type") == "exact" and word == keyword) or (rule.get("match_type") != "exact" and keyword in word):
            return rule
    return None


def ingest_inbound(db, connection: dict, secret: Optional[str], form: dict, public_api: str, record: Optional[Callable] = None,
                   now: Optional[datetime] = None) -> dict:
    """A person texted our number. Stores it, honours STOP / START, ends sequences they answered, and sends at most one keyword answer."""
    now = now or now_utc()
    org_id = connection["owner_id"]
    phone = to_e164(form.get("From") or "", "") or (form.get("From") or "").strip()
    body = (form.get("Body") or "").strip()[:1600]
    sid = form.get("MessageSid") or form.get("SmsSid") or ""
    if not phone or not (body or sid):
        return {"ok": True, "action": "ignored"}
    if sid and (db.table("sms_messages").select("id").eq("connection_id", connection["id"]).eq("provider_sid", sid).limit(1).execute().data):
        return {"ok": True, "action": "duplicate"}
    contact_id = find_contact(db, org_id, phone)
    db.table("sms_messages").insert({
        "owner_id": org_id, "connection_id": connection["id"], "phone": phone, "direction": "in", "body": body, "status": "received",
        "source": "inbound", "provider_sid": sid or None, "contact_id": contact_id, "created_at": now.isoformat(), "updated_at": now.isoformat()}).execute()
    log_interaction(db, org_id, contact_id, "in", body)
    if record:
        record(Signal("event", "sms_received", text_value=body[:200], entity={"from": phone, "sid": sid}, dedupe_key=f"smsin:{sid}" if sid else None))

    word = _normal_word(body)
    if word in STOP_WORDS:
        db.table("sms_optouts").upsert({"owner_id": org_id, "phone": phone, "reason": "stop"}, on_conflict="owner_id,phone").execute()
        stop_enrollments(db, org_id, phone, "stopped", "The person opted out.")
        db.table("deal_sms").update({"status": "skipped", "error": "This person opted out of text messages.", "updated_at": now.isoformat()}) \
            .eq("owner_id", org_id).eq("to_phone", phone).eq("status", "pending").execute()
        if record:
            record(Signal("event", "sms_optout", entity={"phone": phone}))
        return {"ok": True, "action": "optout"}
    if word in START_WORDS:
        db.table("sms_optouts").delete().eq("owner_id", org_id).eq("phone", phone).execute()
        return {"ok": True, "action": "optin"}

    stop_enrollments(db, org_id, phone, "replied", "The person replied.", only_stop_on_reply=True)

    settings = settings_for(db, org_id)
    if not settings["autoreply_enabled"] or is_opted_out(db, org_id, phone):
        return {"ok": True, "action": "stored"}
    rule = _match_autoreply(db.table("sms_autoreplies").select("*").eq("owner_id", org_id).eq("is_active", True).execute().data or [], body)
    if not rule:
        return {"ok": True, "action": "stored"}
    earlier = (db.table("sms_messages").select("created_at").eq("owner_id", org_id).eq("phone", phone).eq("source", "autoreply")
               .gte("created_at", (now - timedelta(days=1)).isoformat()).execute().data or [])
    gap = (now - timedelta(minutes=AUTOREPLY_GAP_MINUTES)).isoformat()
    if len(earlier) >= AUTOREPLY_PER_DAY or any(str(r.get("created_at")) >= gap for r in earlier):
        return {"ok": True, "action": "stored", "note": "answer limit"}
    try:
        send_text(db, org_id=org_id, connection=connection, secret=secret, phone=phone, body=render(rule["reply_text"], {}), source="autoreply",
                  settings=settings, public_api=public_api, record=record, now=now, check_hours=False, contact_id=contact_id)
    except (SendError, Wait) as err:
        log.warning("auto-reply to %s not sent: %s", phone, err)
        return {"ok": True, "action": "stored", "note": str(err)}
    return {"ok": True, "action": "autoreplied", "rule": rule.get("id")}


# ───────────────────────────── sequences ─────────────────────────────

def validate_steps(steps) -> list:
    """1 to 6 steps, each a delay in hours (0 to 30 days) and a text. Raises ValueError with a message the person can act on."""
    if not isinstance(steps, list) or not 1 <= len(steps) <= 6:
        raise ValueError("A sequence has 1 to 6 texts.")
    clean = []
    for i, step in enumerate(steps, 1):
        try:
            delay = float((step or {}).get("delay_hours", 0))
        except (TypeError, ValueError):
            raise ValueError(f"Text {i}: the wait must be a number of hours.")
        text = str((step or {}).get("text") or "").strip()
        if not 0 <= delay <= 720:
            raise ValueError(f"Text {i}: the wait must be between 0 and 720 hours.")
        if not text or len(text) > 480:
            raise ValueError(f"Text {i}: write between 1 and 480 characters.")
        clean.append({"delay_hours": delay, "text": text})
    return clean


def enroll_deals(db, *, org_id: str, sequence: dict, deal_ids: list, settings: dict, connection: dict, user_id: str,
                 now: Optional[datetime] = None) -> list:
    """Puts chosen deals' contacts into a sequence. Returns one result per deal: enrolled, or the reason it was skipped."""
    now = now or now_utc()
    if len(deal_ids) > ENROLL_LIMIT:
        raise ValueError(f"Choose up to {ENROLL_LIMIT} deals at a time. Texts go to people you picked, not to a list.")
    steps = sequence["steps"]
    out = []
    for deal_id in dict.fromkeys(deal_ids):
        deal = (db.table("deals").select("*").eq("id", deal_id).eq("owner_id", org_id).limit(1).execute().data or [None])[0]
        if not deal:
            out.append({"deal_id": deal_id, "result": "skipped", "reason": "Deal not found."})
            continue
        contact = (db.table("contacts").select("*").eq("id", deal["contact_id"]).limit(1).execute().data or [None])[0] if deal.get("contact_id") else None
        phone = to_e164((contact or {}).get("phone") or "", settings["country_code"])
        if not contact or not phone:
            out.append({"deal_id": deal_id, "result": "skipped", "reason": "This deal has no contact with a valid phone number."})
            continue
        if is_opted_out(db, org_id, phone):
            out.append({"deal_id": deal_id, "result": "skipped", "reason": "This person opted out of text messages."})
            continue
        if db.table("sms_enrollments").select("id").eq("sequence_id", sequence["id"]).eq("phone", phone).eq("status", "active").limit(1).execute().data:
            out.append({"deal_id": deal_id, "result": "skipped", "reason": "Already in this sequence."})
            continue
        company = ""
        if deal.get("company_id"):
            found = db.table("companies").select("name").eq("id", deal["company_id"]).limit(1).execute().data or []
            company = found[0]["name"] if found else ""
        db.table("sms_enrollments").insert({
            "owner_id": org_id, "sequence_id": sequence["id"], "connection_id": connection["id"], "phone": phone, "contact_id": contact["id"],
            "deal_id": deal_id, "vars": contact_variables(contact, company, deal.get("title") or ""), "step": 0,
            "next_at": (now + timedelta(hours=float(steps[0]["delay_hours"]))).isoformat(), "status": "active", "created_by": user_id,
            "created_at": now.isoformat(), "updated_at": now.isoformat()}).execute()
        out.append({"deal_id": deal_id, "result": "enrolled"})
    return out


def advance_enrollments(db, *, org_id: Optional[str], get_secret: Callable, public_api: str, record_for: Callable = None,
                        now: Optional[datetime] = None, batch: int = 10) -> dict:
    """Sends the sequence texts that are due. Safe to call as often as you like (one claim per text)."""
    now = now or now_utc()
    result = {"sent": 0, "waiting": 0, "stopped": 0, "failed": 0}
    query = db.table("sms_enrollments").select("*").eq("status", "active").lte("next_at", now.isoformat())
    if org_id:
        query = query.eq("owner_id", org_id)
    for enrollment in (query.order("next_at").limit(batch).execute().data or []):
        owner = enrollment["owner_id"]
        seq = (db.table("sms_sequences").select("*").eq("id", enrollment["sequence_id"]).limit(1).execute().data or [None])[0]
        connection = (db.table("connections").select("*").eq("id", enrollment["connection_id"]).limit(1).execute().data or [None])[0] if enrollment.get("connection_id") else None

        def end(status: str, reason: str):
            db.table("sms_enrollments").update({"status": status, "stop_reason": reason, "updated_at": now.isoformat()}).eq("id", enrollment["id"]).execute()

        if not seq or not seq.get("is_active", True):
            end("stopped", "The sequence was switched off or deleted.")
            result["stopped"] += 1
            continue
        if not connection or connection.get("status") == "paused" or connection.get("provider") != "sms_twilio":
            end("stopped", "The Twilio number is no longer connected.")
            result["stopped"] += 1
            continue
        if is_opted_out(db, owner, enrollment["phone"]):
            end("stopped", "The person opted out.")
            result["stopped"] += 1
            continue
        steps = seq["steps"]
        index = enrollment["step"]
        if index >= len(steps):
            end("completed", "")
            continue
        settings = settings_for(db, owner)
        # claim: only the caller whose update still sees the old next_at may send this text
        claimed = (db.table("sms_enrollments").update({"next_at": (now + timedelta(minutes=15)).isoformat(), "updated_at": now.isoformat()})
                   .eq("id", enrollment["id"]).eq("status", "active").eq("next_at", enrollment["next_at"]).execute().data)
        if not claimed:
            continue
        text = render(steps[index]["text"], enrollment.get("vars") or {})
        try:
            send_text(db, org_id=owner, connection=connection, secret=get_secret(connection["id"]), phone=enrollment["phone"], body=text,
                      source="sequence", settings=settings, public_api=public_api, record=record_for(connection) if record_for else None, now=now,
                      contact_id=enrollment.get("contact_id"), deal_id=enrollment.get("deal_id"), enrollment_id=enrollment["id"], step=index)
        except Wait:
            db.table("sms_enrollments").update({"next_at": enrollment["next_at"]}).eq("id", enrollment["id"]).execute()   # try again at the next pass
            result["waiting"] += 1
            continue
        except SendError as err:
            if err.temporary:
                result["waiting"] += 1                       # stays claimed for 15 minutes, then tried again
            else:
                end("failed", str(err)[:300])
                result["failed"] += 1
            continue
        result["sent"] += 1
        if index + 1 >= len(steps):
            db.table("sms_enrollments").update({"step": index + 1, "status": "completed", "updated_at": now.isoformat()}).eq("id", enrollment["id"]).execute()
        else:
            db.table("sms_enrollments").update({"step": index + 1, "updated_at": now.isoformat(),
                                                "next_at": (now + timedelta(hours=float(steps[index + 1]["delay_hours"]))).isoformat()}).eq("id", enrollment["id"]).execute()
    return result


# ───────────────────────────── the CRM pipeline ─────────────────────────────

def dispatch_crm(db, *, org_id: str, get_secret: Callable, public_api: str, record_for: Callable = None, now: Optional[datetime] = None) -> dict:
    """Sends the first texts the pipeline queued (button / automatic mode): a few at a time, within sending hours and the daily limit."""
    now = now or now_utc()
    result = {"sent": 0, "failed": 0, "waiting": 0, "skipped": 0}
    stale = (now - timedelta(minutes=STALE_SENDING_MINUTES)).isoformat()
    db.table("deal_sms").update({
        "status": "failed", "updated_at": now.isoformat(),
        "error": "The outcome is unknown (it may or may not have been sent). Check the SMS inbox before sending again."}) \
        .eq("owner_id", org_id).eq("status", "sending").lt("updated_at", stale).execute()
    rows = db.table("deal_sms").select("*").eq("owner_id", org_id).eq("status", "pending").order("created_at").limit(CRM_BATCH).execute().data or []
    settings = settings_for(db, org_id)
    connections: dict = {}
    for row in rows:
        def note(text: str, **extra):
            db.table("deal_sms").update({"error": text, "updated_at": now.isoformat(), **extra}).eq("deal_id", row["deal_id"]).execute()

        cid = row.get("connection_id")
        if cid not in connections:
            found = db.table("connections").select("*").eq("id", cid).eq("owner_id", org_id).limit(1).execute().data if cid else None
            connections[cid] = found[0] if found else None
        connection = connections[cid]
        if not connection or connection.get("status") == "paused":
            note("The Twilio number for this message is no longer connected.", status="failed")
            result["failed"] += 1
            continue
        if is_opted_out(db, org_id, row["to_phone"]):
            note("This person opted out of text messages.", status="skipped")
            result["skipped"] += 1
            continue
        if not in_sending_hours(settings, now):
            note(f"Waiting for sending hours ({int(settings['send_from_hour']):02d}:00 to {int(settings['send_until_hour']):02d}:00 {settings['timezone']})")
            result["waiting"] += 1
            continue
        if sent_today(db, org_id, connection["id"], settings, now) >= daily_cap(settings):
            note("Today's text message limit is reached; it will go out tomorrow.")
            result["waiting"] += 1
            continue
        claimed = (db.table("deal_sms").update({"status": "sending", "attempts": (row.get("attempts") or 0) + 1, "error": None, "updated_at": now.isoformat()})
                   .eq("deal_id", row["deal_id"]).eq("status", "pending").execute().data)
        if not claimed:
            continue
        try:
            message = send_text(db, org_id=org_id, connection=connection, secret=get_secret(connection["id"]), phone=row["to_phone"], body=row["body"],
                                source="crm", settings=settings, public_api=public_api, record=record_for(connection) if record_for else None, now=now,
                                deal_id=row["deal_id"], contact_id=row.get("contact_id"), sent_by=row.get("sender_id"))
        except Wait as err:
            note(str(err), status="pending")
            result["waiting"] += 1
            continue
        except SendError as err:
            if err.temporary and (row.get("attempts") or 0) + 1 < CRM_MAX_ATTEMPTS:
                note("A temporary problem stopped this message; it will be tried again.", status="pending")
                result["waiting"] += 1
            else:
                note(str(err)[:300], status="failed")
                result["failed"] += 1
            continue
        db.table("deal_sms").update({"status": "sent", "message_id": message.get("provider_sid"), "sent_at": now.isoformat(), "error": None,
                                     "updated_at": now.isoformat()}).eq("deal_id", row["deal_id"]).execute()
        result["sent"] += 1
        sequence_id = settings.get("sequence_id")
        if sequence_id:
            try:
                seq = (db.table("sms_sequences").select("*").eq("id", sequence_id).eq("owner_id", org_id).eq("is_active", True).limit(1).execute().data or [None])[0]
                if seq:
                    enroll_deals(db, org_id=org_id, sequence=seq, deal_ids=[row["deal_id"]], settings=settings, connection=connection,
                                 user_id=row.get("requested_by") or org_id, now=now)
            except Exception as err:                            # the first text is out; a follow-up problem never undoes that
                log.warning("could not start the follow-up sequence for deal %s: %s", row["deal_id"], err)
    left = db.table("deal_sms").select("deal_id", count="exact").eq("owner_id", org_id).eq("status", "pending").execute()
    result["pending_left"] = left.count if left.count is not None else len(left.data or [])
    return result
