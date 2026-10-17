"""HTTP surface for connections. Mounted at /api/raptor/connections.

  GET    /providers          what can be connected (and which are switched on for this server)
  GET    ""                  this organization's connections
  POST   ""                  connect one            {provider, inputs: {...}, label?}
  PATCH  /{id}               rename / pause / resume {label?, paused?}
  DELETE /{id}               disconnect (its secret and signals go with it)
  POST   /{id}/sync          fetch fresh data now (rate limited per connection)
  GET    /{id}/signals       the latest signals of one connection
  POST   /oauth/start        begin "sign in with Google" for a connector that needs it -> {url}
  GET    /oauth/google/callback   where Google sends the person back; finishes the connection, then returns them to the app
  POST   /{id}/reply         post a reply to a comment as the connected account {parent_id, text}
  POST   /tick               cron only: sync every connection that is due

Rules: everything belongs to the caller's ORGANIZATION (owner_id = org id). Connecting, changing and removing need the
manage_automations permission (the owner always has it) and the Pro plan. The browser never writes these tables itself and never
sees a secret; this file does the writing with the service role."""
from __future__ import annotations

import logging
import os
from datetime import datetime, timedelta, timezone
from typing import Optional

from urllib.parse import urlencode

from fastapi import APIRouter, Depends, Header, HTTPException, Query
from fastapi.responses import RedirectResponse
from pydantic import BaseModel

from raptor.utility import raptor_auth
from raptor.utility.raptor_auth import get_current_user, require_pro

from . import google_oauth, registry, vault
from .registry import ConnectorError

log = logging.getLogger(__name__)
router = APIRouter()

MAX_CONNECTIONS_PER_ORG = 25
MAX_REPLIES_PER_DAY = 50           # per connection: a safety net against a runaway client, far above what a person writes by hand
MAX_REPLY_LENGTH = 10000
OAUTH_STATE_SECONDS = 600
SYNC_CHUNK = 500
TICK_BATCH = 50
TICK_INTERVAL_HOURS = 6
PUBLIC_FIELDS = "id,provider,label,external_id,status,config,last_sync_at,last_error,created_at,updated_at"

registry.load_all()


def _db():
    client = raptor_auth.get_service_client()
    if not client:
        raise HTTPException(status_code=500, detail="Database credentials missing on server.")
    return client


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _org(user_id: str) -> tuple:
    """(organization id, may manage connections). A solo account (no membership row) is its own organization and its owner."""
    try:
        rows = _db().table("org_members").select("org_id,status,is_owner,permissions").eq("user_id", user_id).limit(1).execute().data or []
    except Exception:
        rows = []                                      # organization tables not installed: behave as a solo account
    if not rows:
        return user_id, True
    row = rows[0]
    if row.get("status") != "active":
        raise HTTPException(status_code=403, detail="Your access to this organization is not active.")
    can_manage = bool(row.get("is_owner")) or bool((row.get("permissions") or {}).get("manage_automations"))
    return row["org_id"], can_manage


def _manager(user_id: str) -> str:
    org_id, can_manage = _org(user_id)
    if not can_manage:
        raise HTTPException(status_code=403, detail="You need the permission to manage automations to change connections.")
    require_pro(user_id, "Connections are part of the Pro plan. Upgrade to Pro to connect channels.")
    return org_id


def _connector(provider: str):
    connector = registry.get(provider)
    if not connector:
        raise HTTPException(status_code=404, detail="Unknown connection type.")
    return connector


def _owned(org_id: str, connection_id: str) -> dict:
    rows = _db().table("connections").select("*").eq("id", connection_id).eq("owner_id", org_id).limit(1).execute().data or []
    if not rows:
        raise HTTPException(status_code=404, detail="Connection not found.")
    return rows[0]


def _public(row: dict) -> dict:
    return {k: row.get(k) for k in PUBLIC_FIELDS.split(",")}


def _as_time(value) -> Optional[datetime]:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, str) and value:
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
        except ValueError:
            return None
    return None


def _secret_of(connection_id: str) -> Optional[str]:
    rows = _db().table("connection_secrets").select("encrypted_secret").eq("connection_id", connection_id).limit(1).execute().data or []
    return vault.decrypt_secret(rows[0]["encrypted_secret"]) if rows else None


def _run_sync(connection: dict) -> int:
    """Fetches fresh signals, stores the new ones, records success or the user-readable error. Returns how many were fetched."""
    connector = registry.get(connection["provider"])
    db = _db()
    now = _now()
    if not connector:
        db.table("connections").update({"status": "error", "last_error": "This connection type is no longer available.", "updated_at": now.isoformat()}).eq("id", connection["id"]).execute()
        raise HTTPException(status_code=410, detail="This connection type is no longer available.")
    try:
        signals = connector.sync(connection, _secret_of(connection["id"]))
    except ConnectorError as err:
        db.table("connections").update({"status": "error", "last_error": str(err)[:400], "updated_at": now.isoformat()}).eq("id", connection["id"]).execute()
        raise HTTPException(status_code=422, detail=str(err))
    rows = [{
        "owner_id": connection["owner_id"], "connection_id": connection["id"], "provider": connection["provider"],
        "kind": s.kind, "name": s.name, "value": s.value, "text_value": s.text_value, "entity": s.entity or {},
        "occurred_at": (s.occurred_at or now).isoformat(), "dedupe_key": s.dedupe_key,
    } for s in signals]
    for start in range(0, len(rows), SYNC_CHUNK):
        db.table("signals").upsert(rows[start:start + SYNC_CHUNK], on_conflict="connection_id,dedupe_key", ignore_duplicates=True).execute()
    db.table("connections").update({"status": "connected", "last_error": None, "last_sync_at": now.isoformat(), "updated_at": now.isoformat()}).eq("id", connection["id"]).execute()
    return len(rows)


def _web_app_connections_url(**params) -> str:
    base = os.environ.get("WEB_APP_URL", "https://shoonyaorigins.com/ventures/raptor/app/").rstrip("/") + "/"
    return f"{base}#/connections" + ("?" + urlencode(params) if params else "")


def _store_connection(org_id: str, user_id: str, connector, result, label: Optional[str] = None) -> dict:
    """Saves a new connection (or, if this exact thing is already connected by signing in, refreshes its secret and wakes it up), then
    fetches the first data. A failure of that first fetch is recorded on the connection and does not undo the connection."""
    db = _db()
    existing = db.table("connections").select("id,provider,external_id").eq("owner_id", org_id).execute().data or []
    same = next((r for r in existing if r.get("provider") == connector.provider and r.get("external_id") == result.external_id), None)
    if same and not result.secret:
        raise HTTPException(status_code=409, detail="This is already connected.")
    now = _now().isoformat()
    if same:
        created = same
        db.table("connections").update({"status": "connected", "last_error": None, "config": result.config or {}, "updated_at": now}).eq("id", same["id"]).execute()
        db.table("connection_secrets").delete().eq("connection_id", same["id"]).execute()
    else:
        if len(existing) >= MAX_CONNECTIONS_PER_ORG:
            raise HTTPException(status_code=400, detail=f"You can have up to {MAX_CONNECTIONS_PER_ORG} connections.")
        row = {
            "owner_id": org_id, "created_by": user_id, "provider": connector.provider,
            "label": (label or result.label or connector.title)[:120], "external_id": result.external_id,
            "status": "connected", "config": result.config or {}, "created_at": now, "updated_at": now,
        }
        created = (db.table("connections").insert(row).execute().data or [row])[0]
    if result.secret:
        db.table("connection_secrets").insert({"connection_id": created["id"], "encrypted_secret": vault.encrypt_secret(result.secret)}).execute()
    full = db.table("connections").select("*").eq("id", created["id"]).limit(1).execute().data or [created]
    try:
        _run_sync(full[0])
    except HTTPException as err:
        log.warning("first sync of %s failed: %s", connector.provider, err.detail)
    fresh = db.table("connections").select(PUBLIC_FIELDS).eq("id", created["id"]).limit(1).execute().data or [created]
    return fresh[0]


# ───────────────────────── routes ─────────────────────────

@router.get("/providers")
def providers(user_id: str = Depends(get_current_user)):
    return {"providers": [c.describe() for c in registry.REGISTRY.values()]}


@router.get("")
def list_connections(user_id: str = Depends(get_current_user)):
    org_id, _ = _org(user_id)
    rows = _db().table("connections").select(PUBLIC_FIELDS).eq("owner_id", org_id).order("created_at").execute().data or []
    return {"connections": rows}


class ConnectBody(BaseModel):
    provider: str
    inputs: dict = {}
    label: Optional[str] = None


@router.post("")
def connect(body: ConnectBody, user_id: str = Depends(get_current_user)):
    org_id = _manager(user_id)
    connector = _connector(body.provider)
    if not connector.available():
        raise HTTPException(status_code=503, detail=f"{connector.title} is not switched on for this Raptor server yet.")
    if connector.auth == "oauth":
        raise HTTPException(status_code=400, detail="This one connects by signing in. Use the sign-in button.")
    inputs = {k: (v.strip() if isinstance(v, str) else v) for k, v in (body.inputs or {}).items()}
    for f in connector.fields:
        if f.required and not str(inputs.get(f.name) or "").strip():
            raise HTTPException(status_code=400, detail=f"{f.label} is required.")
    try:
        result = connector.connect(inputs)
    except ConnectorError as err:
        raise HTTPException(status_code=422, detail=str(err))
    return {"connection": _public(_store_connection(org_id, user_id, connector, result, body.label))}


class OAuthStartBody(BaseModel):
    provider: str


@router.post("/oauth/start")
def oauth_start(body: OAuthStartBody, user_id: str = Depends(get_current_user)):
    org_id = _manager(user_id)
    connector = _connector(body.provider)
    if connector.auth != "oauth":
        raise HTTPException(status_code=400, detail="This one does not use a sign-in.")
    if not connector.available():
        raise HTTPException(status_code=503, detail=f"{connector.title} is not switched on for this Raptor server yet.")
    state = vault.sign_state({"o": org_id, "u": user_id, "p": connector.provider})
    return {"url": connector.authorize_url(state, google_oauth.redirect_uri())}


@router.get("/oauth/google/callback", include_in_schema=False)
def oauth_google_callback(code: str = "", state: str = "", error: str = ""):
    """Google sends the person's browser here after they approved (or refused). There is no login token on this request, so who
    it is for comes from the signed, short-lived state made in oauth_start. Always ends by sending the person back to the app."""
    def back(**params):
        return RedirectResponse(_web_app_connections_url(**params), status_code=302)

    if error or not code:
        return back(oauth_error="You did not allow access, so nothing was connected.")
    try:
        data = vault.read_state(state, OAUTH_STATE_SECONDS)
        org_id, user_id = data["o"], data["u"]
        connector = _connector(data["p"])
        if _manager(user_id) != org_id:
            raise HTTPException(status_code=403, detail="Your organization changed. Start again.")
        result = connector.complete(code, google_oauth.redirect_uri())
        connection = _store_connection(org_id, user_id, connector, result)
    except HTTPException as err:
        return back(oauth_error=str(err.detail))
    except (ConnectorError, KeyError) as err:
        return back(oauth_error=str(err) or "The sign-in could not be completed. Try again.")
    return back(connected=connection["provider"])


class ReplyBody(BaseModel):
    parent_id: str
    text: str


@router.post("/{connection_id}/reply")
def reply(connection_id: str, body: ReplyBody, user_id: str = Depends(get_current_user)):
    org_id = _manager(user_id)
    connection = _owned(org_id, connection_id)
    connector = _connector(connection["provider"])
    if not connector.can_reply:
        raise HTTPException(status_code=400, detail="This connection cannot post replies.")
    if connection["status"] != "connected":
        raise HTTPException(status_code=409, detail="This connection needs attention before it can reply. Reconnect it first.")
    text = (body.text or "").strip()
    if not text:
        raise HTTPException(status_code=400, detail="Write a reply first.")
    if len(text) > MAX_REPLY_LENGTH:
        raise HTTPException(status_code=400, detail=f"A reply can be up to {MAX_REPLY_LENGTH} characters.")
    parent = (body.parent_id or "").strip()
    if not parent:
        raise HTTPException(status_code=400, detail="Choose the comment to reply to.")
    db = _db()
    today = _now().strftime("%Y-%m-%d")
    sent = db.table("signals").select("occurred_at").eq("connection_id", connection_id).eq("name", "reply_sent").limit(500).execute().data or []
    if sum(1 for r in sent if str(r.get("occurred_at", ""))[:10] == today) >= MAX_REPLIES_PER_DAY:
        raise HTTPException(status_code=429, detail="Daily reply limit reached. Try again tomorrow.")
    try:
        posted = connector.reply(connection, _secret_of(connection_id), parent, text)
    except ConnectorError as err:
        raise HTTPException(status_code=422, detail=str(err))
    db.table("signals").upsert([{
        "owner_id": org_id, "connection_id": connection_id, "provider": connection["provider"], "kind": "event", "name": "reply_sent",
        "text_value": text[:2000], "entity": {"parent_id": parent, "reply_id": posted, "sent_by": user_id},
        "occurred_at": _now().isoformat(), "dedupe_key": f"reply:{posted or _now().isoformat()}",
    }], on_conflict="connection_id,dedupe_key", ignore_duplicates=True).execute()
    return {"ok": True, "reply_id": posted}


class PatchBody(BaseModel):
    label: Optional[str] = None
    paused: Optional[bool] = None


@router.patch("/{connection_id}")
def patch(connection_id: str, body: PatchBody, user_id: str = Depends(get_current_user)):
    org_id = _manager(user_id)
    _owned(org_id, connection_id)
    update = {"updated_at": _now().isoformat()}
    if body.label is not None:
        update["label"] = body.label.strip()[:120]
    if body.paused is not None:
        update["status"] = "paused" if body.paused else "connected"
        if not body.paused:
            update["last_error"] = None
    _db().table("connections").update(update).eq("id", connection_id).eq("owner_id", org_id).execute()
    return {"ok": True}


@router.delete("/{connection_id}")
def disconnect(connection_id: str, user_id: str = Depends(get_current_user)):
    org_id = _manager(user_id)
    connection = _owned(org_id, connection_id)
    connector = registry.get(connection["provider"])
    if connector and connector.auth == "oauth":
        try:
            connector.revoke(_secret_of(connection_id))      # withdraw the person's approval at Google, best effort
        except Exception:
            log.warning("could not revoke access for connection %s", connection_id)
    _db().table("connections").delete().eq("id", connection_id).eq("owner_id", org_id).execute()   # secret + signals cascade
    return {"ok": True}


@router.post("/{connection_id}/sync")
def sync_now(connection_id: str, user_id: str = Depends(get_current_user)):
    org_id, _ = _org(user_id)
    require_pro(user_id, "Connections are part of the Pro plan. Upgrade to Pro to connect channels.")
    connection = _owned(org_id, connection_id)
    if connection["status"] == "paused":
        raise HTTPException(status_code=409, detail="This connection is paused. Resume it first.")
    connector = _connector(connection["provider"])
    last = _as_time(connection.get("last_sync_at"))
    if last and (_now() - last).total_seconds() < connector.min_sync_interval:
        wait = int(connector.min_sync_interval - (_now() - last).total_seconds())
        raise HTTPException(status_code=429, detail=f"Already refreshed a moment ago. Try again in {max(1, wait // 60)} min.")
    return {"signals": _run_sync(connection)}


@router.get("/{connection_id}/signals")
def signals(connection_id: str, limit: int = Query(100, ge=1, le=500), user_id: str = Depends(get_current_user)):
    org_id, _ = _org(user_id)
    _owned(org_id, connection_id)
    rows = (_db().table("signals").select("kind,name,value,text_value,entity,occurred_at")
            .eq("connection_id", connection_id).eq("owner_id", org_id).order("occurred_at", desc=True).limit(limit).execute().data or [])
    return {"signals": rows}


def _require_cron_secret(x_automation_secret: str = Header(None)):
    secret = os.environ.get("AUTOMATION_CRON_SECRET")
    if not secret or x_automation_secret != secret:
        raise HTTPException(status_code=401, detail="Invalid or missing automation secret.")


@router.post("/tick", dependencies=[Depends(_require_cron_secret)])
def tick():
    """Cron-only. Syncs connections that are connected and not refreshed for TICK_INTERVAL_HOURS. A failure on one never stops the rest."""
    cutoff = _now() - timedelta(hours=TICK_INTERVAL_HOURS)
    rows = _db().table("connections").select("*").eq("status", "connected").order("last_sync_at").limit(TICK_BATCH).execute().data or []
    done = failed = 0
    for row in rows:
        last = _as_time(row.get("last_sync_at"))
        if last and last > cutoff:
            continue
        try:
            _run_sync(row)
            done += 1
        except HTTPException:
            failed += 1
        except Exception:
            log.exception("sync of connection %s crashed", row.get("id"))
            failed += 1
    return {"synced": done, "failed": failed}
