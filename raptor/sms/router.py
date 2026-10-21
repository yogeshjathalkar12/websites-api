"""HTTP surface for SMS. Mounted at /api/raptor/sms.

Reading (the inbox, status, sequences, rules) happens in the apps straight from the database under row level security; this file does
everything that sends, receives or changes something, because the Twilio key lives here, encrypted.

  POST   /send                          one text to one number {connection_id?, phone | deal_id, text}
  POST   /crm/dispatch                  sends the pipeline's queued first texts and the sequence texts that are due (safe to call often)
  POST   /sequences                     create {name, steps: [{delay_hours, text}], stop_on_reply?}
  PATCH  /sequences/{id}                change name / steps / stop_on_reply / is_active
  DELETE /sequences/{id}
  POST   /sequences/{id}/enroll         {deal_ids: [...up to 25]}: put those deals' contacts into the sequence
  POST   /enrollments/{id}/stop         end one person's sequence
  POST   /autoreplies                   create {keyword, match_type, reply_text}
  PATCH  /autoreplies/{id}              change / switch off
  DELETE /autoreplies/{id}
  POST   /optouts                       add a number that must never be texted {phone}
  GET    /webhook/{connection_id}       the address to paste into Twilio, and whether Raptor already set it
  POST   /webhook/{connection_id}/setup point the Twilio number's incoming-message webhook at Raptor
  POST   /hook/{connection_id}/inbound  PUBLIC: Twilio calls this when someone texts the number (signature checked)
  POST   /hook/{connection_id}/status   PUBLIC: Twilio calls this with delivered / undelivered (signature checked)
  POST   /tick                          cron only: sequence texts that are due, for every organization

Rules: everything belongs to the caller's ORGANIZATION. Sending and enrolling need the Pro plan and the edit permission; rules,
sequences and webhook setup need manage_automations. A broadcast does not exist on purpose: enrolling is capped at 25 chosen deals."""
from __future__ import annotations

import hmac
import logging
import os
from typing import Optional
from urllib.parse import parse_qsl

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from fastapi.responses import Response
from pydantic import BaseModel

from raptor.connections import meta, router as conn
from raptor.connections.registry import ConnectorError
from raptor.connections.sms import normalize_number
from raptor.utility.raptor_auth import get_current_user, require_pro

from . import engine

log = logging.getLogger(__name__)
router = APIRouter()
MAX_SEQUENCES = 20
MAX_AUTOREPLIES = 30
EMPTY_TWIML = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><Response></Response>"
_db = conn._db


# ───────────────────────────── helpers ─────────────────────────────

def _member(user_id: str, need_manage: bool = False) -> str:
    """The caller's organization id. Needs the Pro plan; sending needs the edit permission, configuring needs manage_automations."""
    db = _db()
    try:
        rows = db.table("org_members").select("org_id,status,is_owner,permissions").eq("user_id", user_id).limit(1).execute().data or []
    except Exception:
        rows = []
    if rows:
        row = rows[0]
        if row.get("status") != "active":
            raise HTTPException(status_code=403, detail="Your access to this organization is not active.")
        perms = row.get("permissions") or {}
        allowed = bool(row.get("is_owner")) or bool(perms.get("manage_automations" if need_manage else "edit"))
        if not allowed:
            raise HTTPException(status_code=403, detail="You need the permission to manage automations." if need_manage else "You do not have permission to send text messages.")
        org_id = row["org_id"]
    else:
        org_id = user_id
    require_pro(user_id, "Text messages are part of the Pro plan. Upgrade to Pro to use them.")
    return org_id


def _sms_connection(org_id: str, connection_id: Optional[str] = None) -> dict:
    query = _db().table("connections").select("*").eq("owner_id", org_id).eq("provider", "sms_twilio")
    if connection_id:
        query = query.eq("id", connection_id)
    rows = query.order("created_at").limit(1).execute().data or []
    if not rows:
        raise HTTPException(status_code=404, detail="Connect your Twilio number first (Connections, SMS).")
    if rows[0].get("status") == "paused":
        raise HTTPException(status_code=409, detail="This connection is paused. Resume it first.")
    return rows[0]


def _record_for(connection: dict):
    return lambda signal: conn._store_signals(connection, [signal])


def _secret(connection_id: str):
    return conn._secret_of(connection_id)


def _public() -> str:
    return meta.public_api()


def _must_exist(rows, what: str) -> dict:
    if not rows:
        raise HTTPException(status_code=404, detail=f"{what} not found.")
    return rows[0]


# ───────────────────────────── sending ─────────────────────────────

class SendBody(BaseModel):
    text: str
    phone: Optional[str] = None
    deal_id: Optional[str] = None
    connection_id: Optional[str] = None


@router.post("/send")
def send(body: SendBody, user_id: str = Depends(get_current_user)):
    org_id = _member(user_id)
    db = _db()
    settings = engine.settings_for(db, org_id)
    contact_id, deal_id = None, None
    if body.deal_id:
        deal = _must_exist(db.table("deals").select("*").eq("id", body.deal_id).eq("owner_id", org_id).limit(1).execute().data, "Deal")
        contact = _must_exist(db.table("contacts").select("*").eq("id", deal.get("contact_id")).limit(1).execute().data, "Contact") if deal.get("contact_id") else {}
        phone = engine.to_e164(contact.get("phone") or "", settings["country_code"])
        if not phone:
            raise HTTPException(status_code=422, detail="This deal has no contact with a valid phone number.")
        contact_id, deal_id = contact.get("id"), deal["id"]
    else:
        try:
            phone = normalize_number(body.phone or "")
        except ConnectorError as err:
            raise HTTPException(status_code=422, detail=str(err))
    connection = _sms_connection(org_id, body.connection_id or settings.get("connection_id"))
    # A person typing a reply to someone who texted in the last 24 hours is exempt from the sending hours; a first text is not.
    recent_inbound = (db.table("sms_messages").select("id").eq("owner_id", org_id).eq("phone", phone).eq("direction", "in")
                      .gte("created_at", (engine.now_utc() - engine.timedelta(hours=24)).isoformat()).limit(1).execute().data)
    try:
        row = engine.send_text(db, org_id=org_id, connection=connection, secret=_secret(connection["id"]), phone=phone, body=body.text,
                               source="manual", settings=settings, public_api=_public(), record=_record_for(connection),
                               check_hours=not recent_inbound, deal_id=deal_id, contact_id=contact_id, sent_by=user_id)
    except engine.Wait as err:
        raise HTTPException(status_code=429, detail=str(err))
    except engine.SendError as err:
        raise HTTPException(status_code=422, detail=str(err))
    return {"ok": True, "message": {k: row.get(k) for k in ("id", "phone", "body", "status", "provider_sid")}}


@router.post("/crm/dispatch")
def crm_dispatch(user_id: str = Depends(get_current_user)):
    """The web app and the desktop call this whenever a text is waiting or a sequence step may be due."""
    org_id = _member(user_id)
    db = _db()
    first = engine.dispatch_crm(db, org_id=org_id, get_secret=_secret, public_api=_public(), record_for=_record_for)
    follow = engine.advance_enrollments(db, org_id=org_id, get_secret=_secret, public_api=_public(), record_for=_record_for)
    return {**first, "sequence": follow}


# ───────────────────────────── sequences ─────────────────────────────

class SequenceBody(BaseModel):
    name: str
    steps: list
    stop_on_reply: bool = True


class SequencePatch(BaseModel):
    name: Optional[str] = None
    steps: Optional[list] = None
    stop_on_reply: Optional[bool] = None
    is_active: Optional[bool] = None


def _clean_steps(steps) -> list:
    try:
        return engine.validate_steps(steps)
    except ValueError as err:
        raise HTTPException(status_code=422, detail=str(err))


def _clean_name(name: str) -> str:
    name = (name or "").strip()
    if not 1 <= len(name) <= 80:
        raise HTTPException(status_code=422, detail="Give it a name of up to 80 characters.")
    return name


@router.post("/sequences")
def create_sequence(body: SequenceBody, user_id: str = Depends(get_current_user)):
    org_id = _member(user_id, need_manage=True)
    db = _db()
    if len(db.table("sms_sequences").select("id").eq("owner_id", org_id).execute().data or []) >= MAX_SEQUENCES:
        raise HTTPException(status_code=400, detail=f"You can have up to {MAX_SEQUENCES} sequences.")
    row = db.table("sms_sequences").insert({"owner_id": org_id, "name": _clean_name(body.name), "steps": _clean_steps(body.steps),
                                            "stop_on_reply": body.stop_on_reply, "created_by": user_id}).execute().data[0]
    return {"sequence": row}


@router.patch("/sequences/{sequence_id}")
def patch_sequence(sequence_id: str, body: SequencePatch, user_id: str = Depends(get_current_user)):
    org_id = _member(user_id, need_manage=True)
    db = _db()
    _must_exist(db.table("sms_sequences").select("id").eq("id", sequence_id).eq("owner_id", org_id).limit(1).execute().data, "Sequence")
    update: dict = {"updated_at": engine.now_utc().isoformat()}
    if body.name is not None:
        update["name"] = _clean_name(body.name)
    if body.steps is not None:
        update["steps"] = _clean_steps(body.steps)
    if body.stop_on_reply is not None:
        update["stop_on_reply"] = body.stop_on_reply
    if body.is_active is not None:
        update["is_active"] = body.is_active
    db.table("sms_sequences").update(update).eq("id", sequence_id).execute()
    return {"ok": True}


@router.delete("/sequences/{sequence_id}")
def delete_sequence(sequence_id: str, user_id: str = Depends(get_current_user)):
    org_id = _member(user_id, need_manage=True)
    db = _db()
    _must_exist(db.table("sms_sequences").select("id").eq("id", sequence_id).eq("owner_id", org_id).limit(1).execute().data, "Sequence")
    db.table("sms_sequences").delete().eq("id", sequence_id).execute()
    return {"ok": True}


class EnrollBody(BaseModel):
    deal_ids: list


@router.post("/sequences/{sequence_id}/enroll")
def enroll(sequence_id: str, body: EnrollBody, user_id: str = Depends(get_current_user)):
    org_id = _member(user_id)
    db = _db()
    sequence = _must_exist(db.table("sms_sequences").select("*").eq("id", sequence_id).eq("owner_id", org_id).limit(1).execute().data, "Sequence")
    if not sequence.get("is_active", True):
        raise HTTPException(status_code=409, detail="This sequence is switched off.")
    settings = engine.settings_for(db, org_id)
    if not settings.get("opt_in_confirmed_at"):
        raise HTTPException(status_code=409, detail="Confirm in the SMS settings that your contacts agreed to receive text messages.")
    connection = _sms_connection(org_id, settings.get("connection_id"))
    try:
        results = engine.enroll_deals(db, org_id=org_id, sequence=sequence, deal_ids=[str(i) for i in body.deal_ids], settings=settings,
                                      connection=connection, user_id=user_id)
    except ValueError as err:
        raise HTTPException(status_code=422, detail=str(err))
    return {"results": results, "enrolled": sum(1 for r in results if r["result"] == "enrolled")}


@router.post("/enrollments/{enrollment_id}/stop")
def stop_enrollment(enrollment_id: str, user_id: str = Depends(get_current_user)):
    org_id = _member(user_id)
    db = _db()
    _must_exist(db.table("sms_enrollments").select("id").eq("id", enrollment_id).eq("owner_id", org_id).limit(1).execute().data, "Enrolment")
    db.table("sms_enrollments").update({"status": "stopped", "stop_reason": "Stopped by a person.", "updated_at": engine.now_utc().isoformat()}) \
        .eq("id", enrollment_id).eq("status", "active").execute()
    return {"ok": True}


# ───────────────────────────── auto-replies and opt-outs ─────────────────────────────

class AutoReplyBody(BaseModel):
    keyword: str
    reply_text: str
    match_type: str = "contains"


class AutoReplyPatch(BaseModel):
    keyword: Optional[str] = None
    reply_text: Optional[str] = None
    match_type: Optional[str] = None
    is_active: Optional[bool] = None


def _clean_rule(keyword, reply_text, match_type) -> dict:
    out: dict = {}
    if keyword is not None:
        keyword = keyword.strip()
        if not 1 <= len(keyword) <= 60:
            raise HTTPException(status_code=422, detail="The keyword can be 1 to 60 characters.")
        if keyword.lower() in engine.STOP_WORDS | engine.START_WORDS:
            raise HTTPException(status_code=422, detail="STOP and START are handled by Raptor itself; pick another keyword.")
        out["keyword"] = keyword
    if reply_text is not None:
        reply_text = reply_text.strip()
        if not 1 <= len(reply_text) <= 480:
            raise HTTPException(status_code=422, detail="The answer can be 1 to 480 characters.")
        out["reply_text"] = reply_text
    if match_type is not None:
        if match_type not in ("exact", "contains"):
            raise HTTPException(status_code=422, detail="Match either the exact word or any message that contains it.")
        out["match_type"] = match_type
    return out


@router.post("/autoreplies")
def create_autoreply(body: AutoReplyBody, user_id: str = Depends(get_current_user)):
    org_id = _member(user_id, need_manage=True)
    db = _db()
    if len(db.table("sms_autoreplies").select("id").eq("owner_id", org_id).execute().data or []) >= MAX_AUTOREPLIES:
        raise HTTPException(status_code=400, detail=f"You can have up to {MAX_AUTOREPLIES} auto-replies.")
    row = db.table("sms_autoreplies").insert({"owner_id": org_id, "created_by": user_id, **_clean_rule(body.keyword, body.reply_text, body.match_type)}).execute().data[0]
    return {"autoreply": row}


@router.patch("/autoreplies/{rule_id}")
def patch_autoreply(rule_id: str, body: AutoReplyPatch, user_id: str = Depends(get_current_user)):
    org_id = _member(user_id, need_manage=True)
    db = _db()
    _must_exist(db.table("sms_autoreplies").select("id").eq("id", rule_id).eq("owner_id", org_id).limit(1).execute().data, "Auto-reply")
    update = _clean_rule(body.keyword, body.reply_text, body.match_type)
    if body.is_active is not None:
        update["is_active"] = body.is_active
    if update:
        db.table("sms_autoreplies").update(update).eq("id", rule_id).execute()
    return {"ok": True}


@router.delete("/autoreplies/{rule_id}")
def delete_autoreply(rule_id: str, user_id: str = Depends(get_current_user)):
    org_id = _member(user_id, need_manage=True)
    db = _db()
    _must_exist(db.table("sms_autoreplies").select("id").eq("id", rule_id).eq("owner_id", org_id).limit(1).execute().data, "Auto-reply")
    db.table("sms_autoreplies").delete().eq("id", rule_id).execute()
    return {"ok": True}


class OptOutBody(BaseModel):
    phone: str


@router.post("/optouts")
def add_optout(body: OptOutBody, user_id: str = Depends(get_current_user)):
    """A person told you by phone or email that they do not want texts. Only adding is possible here: a number leaves the list only when
    that person texts START themselves."""
    org_id = _member(user_id)
    try:
        phone = normalize_number(body.phone)
    except ConnectorError as err:
        raise HTTPException(status_code=422, detail=str(err))
    db = _db()
    db.table("sms_optouts").upsert({"owner_id": org_id, "phone": phone, "reason": "added by a person"}, on_conflict="owner_id,phone").execute()
    engine.stop_enrollments(db, org_id, phone, "stopped", "The person opted out.")
    return {"ok": True, "phone": phone}


# ───────────────────────────── Twilio webhook setup ─────────────────────────────

@router.get("/webhook/{connection_id}")
def webhook_info(connection_id: str, user_id: str = Depends(get_current_user)):
    org_id = _member(user_id, need_manage=True)
    connection = _sms_connection(org_id, connection_id)
    return {"url": engine.inbound_url(_public(), connection["id"]), "configured": bool((connection.get("config") or {}).get("webhook_set"))}


@router.post("/webhook/{connection_id}/setup")
def webhook_setup(connection_id: str, user_id: str = Depends(get_current_user)):
    org_id = _member(user_id, need_manage=True)
    connection = _sms_connection(org_id, connection_id)
    url = engine.inbound_url(_public(), connection["id"])
    ok = engine.configure_webhook(engine._creds(_secret(connection["id"])), (connection.get("config") or {}).get("from_number", ""), url)
    config = {**(connection.get("config") or {}), "webhook_set": ok}
    _db().table("connections").update({"config": config}).eq("id", connection["id"]).execute()
    return {"configured": ok, "url": url}


# ───────────────────────────── public doors for Twilio ─────────────────────────────

_WINDOW, _LIMIT = 60, 120
_buckets: dict = {}


def _allowed(key: str) -> bool:
    now = engine.now_utc().timestamp()
    recent = [t for t in _buckets.get(key, []) if now - t < _WINDOW]
    ok = len(recent) < _LIMIT
    if ok:
        recent.append(now)
    _buckets[key] = recent
    return ok


async def _verified(request: Request, connection_id: str, kind: str):
    """Reads a Twilio webhook and checks its signature with the connection's own auth token. Returns (connection, secret, form)."""
    if len(connection_id) < 20 or len(connection_id) > 64:
        raise HTTPException(status_code=404, detail="Not found.")
    raw = await request.body()
    if len(raw) > 20_000:
        raise HTTPException(status_code=413, detail="Too large.")
    form = dict(parse_qsl(raw.decode("utf-8", "replace"), keep_blank_values=True))
    rows = _db().table("connections").select("*").eq("id", connection_id).eq("provider", "sms_twilio").limit(1).execute().data or []
    if not rows:
        raise HTTPException(status_code=404, detail="Not found.")
    connection = rows[0]
    secret = _secret(connection["id"])
    token = engine._creds(secret).get("auth_token", "")
    url = (engine.inbound_url if kind == "inbound" else engine.status_callback_url)(_public(), connection["id"])
    if not engine.valid_signature(token, url, form, request.headers.get("x-twilio-signature", "")):
        raise HTTPException(status_code=403, detail="Invalid signature.")
    if not _allowed(connection_id):
        raise HTTPException(status_code=429, detail="Too many messages.")
    return connection, secret, form


@router.post("/hook/{connection_id}/inbound", include_in_schema=False)
async def hook_inbound(connection_id: str, request: Request):
    connection, secret, form = await _verified(request, connection_id, "inbound")
    if connection.get("status") == "paused":
        return Response(EMPTY_TWIML, media_type="text/xml")
    try:
        engine.ingest_inbound(_db(), connection, secret, form, _public(), record=_record_for(connection))
    except Exception:
        log.exception("inbound text for connection %s could not be processed", connection_id)    # Twilio must still get a 200
    return Response(EMPTY_TWIML, media_type="text/xml")


@router.post("/hook/{connection_id}/status", include_in_schema=False)
async def hook_status(connection_id: str, request: Request):
    connection, _secret_unused, form = await _verified(request, connection_id, "status")
    try:
        engine.ingest_status(_db(), connection, form)
    except Exception:
        log.exception("delivery report for connection %s could not be processed", connection_id)
    return Response("", status_code=204)


# ───────────────────────────── cron ─────────────────────────────

def _require_cron_secret(x_automation_secret: str = Header(None)):
    secret = os.environ.get("AUTOMATION_CRON_SECRET")
    if not secret or not x_automation_secret or not hmac.compare_digest(x_automation_secret.encode(), secret.encode()):
        raise HTTPException(status_code=401, detail="Invalid or missing automation secret.")


@router.post("/tick", dependencies=[Depends(_require_cron_secret)])
def tick():
    return engine.advance_enrollments(_db(), org_id=None, get_secret=_secret, public_api=_public(), record_for=_record_for, batch=25)
