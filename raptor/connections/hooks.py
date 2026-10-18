"""The public doors for data other services push to Raptor. There is no login on these routes (Razorpay, Stripe, Telegram and Meta cannot
log in), so everything is checked in router.receive_push / router.receive_meta: tokens or signatures, sizes, rates.

  POST /api/raptor/hooks/{token}               payments, webhooks and Telegram messages (one long random token per connection)
  GET  /api/raptor/hooks/meta                  Meta checks this address once when the app's webhook is set up
  POST /api/raptor/hooks/meta                  Facebook / Instagram messages, comments and new leads (signed with the Meta app secret)
  POST /api/raptor/hooks/meta/deauthorize      a person removed Raptor in their Facebook settings (signed_request)
  POST /api/raptor/hooks/meta/data-deletion    a person asked Meta to delete their data (signed_request)
  GET  /api/raptor/hooks/meta/deletion-status  the page Meta shows the person to confirm the deletion"""
import secrets

from fastapi import APIRouter, Form, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, PlainTextResponse

from . import meta, router as connections_router
from .registry import ConnectorError

router = APIRouter()


@router.get("/meta", include_in_schema=False)
def meta_verify(mode: str = Query("", alias="hub.mode"), token: str = Query("", alias="hub.verify_token"), challenge: str = Query("", alias="hub.challenge")):
    answer = meta.verify_challenge(mode, token, challenge) if meta.enabled() else None
    if answer is None:
        raise HTTPException(status_code=403, detail="Not allowed.")
    return PlainTextResponse(answer)


@router.post("/meta", include_in_schema=False)
async def meta_receive(request: Request):
    return connections_router.receive_meta(await request.body(), dict(request.headers))


def _forget(signed_request: str) -> int:
    if not meta.enabled():
        raise HTTPException(status_code=404, detail="Not found.")
    try:
        data = meta.parse_signed_request(signed_request)
    except ConnectorError:
        raise HTTPException(status_code=401, detail="Invalid signature.")
    uid = str(data.get("user_id") or "")
    return connections_router.forget_facebook_user(uid) if uid else 0


@router.post("/meta/deauthorize", include_in_schema=False)
def meta_deauthorize(signed_request: str = Form("")):
    _forget(signed_request)
    return {"ok": True}


@router.post("/meta/data-deletion", include_in_schema=False)
def meta_data_deletion(signed_request: str = Form("")):
    removed = _forget(signed_request)
    code = secrets.token_urlsafe(9)
    return {"url": f"{meta.public_api()}/api/raptor/hooks/meta/deletion-status?code={code}", "confirmation_code": code, "removed": removed}


@router.get("/meta/deletion-status", include_in_schema=False)
def meta_deletion_status(code: str = ""):
    safe = "".join(ch for ch in code if ch.isalnum() or ch in "-_")[:40]
    return HTMLResponse(
        "<!doctype html><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'><title>Data deletion · Raptor</title>"
        "<body style='font-family:system-ui,sans-serif;max-width:560px;margin:48px auto;padding:0 16px;line-height:1.5'>"
        "<h1 style='font-size:22px'>Your Facebook and Instagram data was deleted</h1>"
        "<p>Raptor removed the saved access to your Facebook account and every message, comment and lead it had stored from your Pages and Instagram accounts.</p>"
        f"<p>Confirmation code: <b>{safe or 'none'}</b></p>"
        "<p>Contacts that a team added to its own Raptor CRM belong to that team. To have them removed too, write to support@shoonyaorigins.com.</p></body>")


@router.post("/{token}")
async def receive(token: str, request: Request):
    body = await request.body()
    return connections_router.receive_push(token, body, dict(request.headers))
