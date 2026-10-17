"""HTTP surface for connections. Mounted at /api/raptor/connections.

  GET    /providers          what can be connected (and which are switched on for this server)
  GET    ""                  this organization's connections
  POST   ""                  connect one            {provider, inputs: {...}, label?}
  PATCH  /{id}               rename / pause / resume {label?, paused?}
  DELETE /{id}               disconnect (its secret and signals go with it)
  POST   /{id}/sync          fetch fresh data now (rate limited per connection)
  GET    /{id}/signals       the latest signals of one connection
  POST   /tick               cron only: sync every connection that is due

Rules: everything belongs to the caller's ORGANIZATION (owner_id = org id). Connecting, changing and removing need the
manage_automations permission (the owner always has it) and the Pro plan. The browser never writes these tables itself and never
sees a secret; this file does the writing with the service role."""
from __future__ import annotations

import logging
import os
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import APIRouter, Depends, Header, HTTPException, Query
from pydantic import BaseModel

from raptor.utility import raptor_auth
from raptor.utility.raptor_auth import get_current_user, require_pro

from . import registry, vault
from .registry import ConnectorError

log = logging.getLogger(__name__)
router = APIRouter()

MAX_CONNECTIONS_PER_ORG = 25
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
    db = _db()
    existing = db.table("connections").select("id,provider,external_id").eq("owner_id", org_id).execute().data or []
    if len(existing) >= MAX_CONNECTIONS_PER_ORG:
        raise HTTPException(status_code=400, detail=f"You can have up to {MAX_CONNECTIONS_PER_ORG} connections.")
    inputs = {k: (v.strip() if isinstance(v, str) else v) for k, v in (body.inputs or {}).items()}
    for f in connector.fields:
        if f.required and not str(inputs.get(f.name) or "").strip():
            raise HTTPException(status_code=400, detail=f"{f.label} is required.")
    try:
        result = connector.connect(inputs)
    except ConnectorError as err:
        raise HTTPException(status_code=422, detail=str(err))
    if any(r.get("provider") == connector.provider and r.get("external_id") == result.external_id for r in existing):
        raise HTTPException(status_code=409, detail="This is already connected.")
    now = _now().isoformat()
    row = {
        "owner_id": org_id, "created_by": user_id, "provider": connector.provider,
        "label": (body.label or result.label or connector.title)[:120], "external_id": result.external_id,
        "status": "connected", "config": result.config or {}, "created_at": now, "updated_at": now,
    }
    created = (db.table("connections").insert(row).execute().data or [row])[0]
    if result.secret:
        db.table("connection_secrets").insert({"connection_id": created["id"], "encrypted_secret": vault.encrypt_secret(result.secret)}).execute()
    try:
        _run_sync(created)                       # first data right away; a failure is recorded on the connection, not fatal here
    except HTTPException as err:
        log.warning("first sync of %s failed: %s", connector.provider, err.detail)
    fresh = db.table("connections").select(PUBLIC_FIELDS).eq("id", created["id"]).limit(1).execute().data or [created]
    return {"connection": _public(fresh[0])}


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
    _owned(org_id, connection_id)
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
