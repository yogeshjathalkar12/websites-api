"""Raptor Mobile Relay — a blind pairing/forwarding router for Live Copilot.

Mounted into the existing "Websites Central API" hub (see main.py) at
/api/raptor, alongside raptor_router.py, so this reuses the hub's already-
deployed Render service instead of standing up a separate one. Ported from
the standalone version at Raptor B2B/relay-server/main.py (kept there too,
as the source of truth for local dev / testing) - identical relay logic,
just as an APIRouter instead of its own FastAPI app.

WHY THIS EXISTS: the Raptor desktop backend (a completely separate, local-
only FastAPI process that runs on a client's own machine - not this hub)
is deliberately "sovereign": Whisper transcription and suggestion
generation run locally, using a client's local Company DNA/Pattern Engine
data that is explicitly never pushed to the cloud. The Raptor mobile app
still needs to reach that local engine from wherever the phone actually is
(not just the same Wi-Fi as the desktop), and a home/office router usually
can't be reached from the internet at all (no public IP, most residential
ISPs are behind CGNAT). This router solves ONLY that connectivity problem.
It never decodes audio, never sees a transcript's meaning, never touches
Whisper or an LLM - it's a WebSocket switchboard: the desktop app connects
out to it (works through any NAT/firewall, no port-forwarding needed) as
role=desktop for a given client_id, the Raptor mobile app connects out to
it as role=mobile for the same client_id, and every message either side
sends (JSON control frames or binary audio-chunk frames) is forwarded
verbatim to the other side. All the actual thinking still happens on the
desktop - see Raptor B2B/raptor/api/routes_calls.py and
Raptor B2B/raptor-ui/src/relayBridge.js.

No content is persisted. If a peer isn't connected, the sender gets an
"error" control frame back instead of the message vanishing.
"""
import logging
import os

import jwt as pyjwt
from jwt import PyJWKClient
from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Query

log = logging.getLogger("raptor-relay")

# Same Supabase project the Raptor desktop/mobile apps use. Falls back to
# the project's public URL/anon key (safe to ship - RLS and this router's
# own client_ids/plan claim checks do the actual access control) rather
# than hard-failing this whole hub's boot if the env vars aren't set here,
# since every other venture shares this process and shouldn't go down
# over a Raptor-relay-specific misconfiguration.
SUPABASE_URL = os.getenv("SUPABASE_URL") or "https://pcdbtcpctlnvdtbrrqoo.supabase.co"
SUPABASE_ANON_KEY = os.getenv("SUPABASE_ANON_KEY") or (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InBjZGJ0Y3BjdGxudmR0YnJycW9vIiwicm9sZSI6ImFub24iLCJpYXQiOjE3ODI2MjIxMjQsImV4cCI6MjA5ODE5ODEyNH0._y59k8mmSqvkCL9gPBWp5hfp2LwpP_IBvr5h7y3nP7Q"
)

_jwks_client = PyJWKClient(
    f"{SUPABASE_URL}/auth/v1/.well-known/jwks.json", headers={"apikey": SUPABASE_ANON_KEY}
)

router = APIRouter()


def _verify_token(token: str, client_id: str) -> dict:
    """Raises ValueError with a user-facing reason on failure."""
    try:
        signing_key = _jwks_client.get_signing_key_from_jwt(token)
        payload = pyjwt.decode(
            token, signing_key.key, algorithms=["RS256", "ES256"], audience="authenticated"
        )
    except pyjwt.ExpiredSignatureError:
        raise ValueError("Session expired, please log in again.")
    except (pyjwt.InvalidTokenError, pyjwt.exceptions.PyJWKClientError) as e:
        raise ValueError(f"Invalid session token: {e}")

    if (payload.get("plan") or "Free").lower() != "pro":
        raise ValueError("Live Copilot requires a Raptor Pro plan.")
    client_ids = set(payload.get("client_ids") or [])
    if client_id not in client_ids:
        raise ValueError("You do not have access to this client's data.")
    return payload


# client_id -> {"desktop": WebSocket|None, "mobile": WebSocket|None}
_pairs: dict = {}


def _slot(client_id: str) -> dict:
    return _pairs.setdefault(client_id, {"desktop": None, "mobile": None})


@router.get("/relay/health")
async def relay_health():
    return {"status": "ok", "active_pairs": len(_pairs)}


@router.websocket("/relay/{client_id}")
async def relay(
    websocket: WebSocket,
    client_id: str,
    role: str = Query(...),
    token: str = Query(...),
):
    if role not in ("desktop", "mobile"):
        await websocket.close(code=4400)
        return

    try:
        _verify_token(token, client_id)
    except ValueError as e:
        log.warning(f"Relay auth rejected for client {client_id} role {role}: {e}")
        await websocket.close(code=4401)
        return

    await websocket.accept()
    slot = _slot(client_id)

    # Only one connection per role per client_id — a second connect (e.g. a
    # reconnect after a network blip) replaces the stale one rather than
    # being rejected, so the previous socket is closed out from under it.
    stale = slot[role]
    slot[role] = websocket
    if stale is not None:
        try:
            await stale.close(code=4409)
        except Exception:
            pass

    other_role = "mobile" if role == "desktop" else "desktop"
    log.info(f"[{client_id}] {role} connected (peer {'connected' if slot[other_role] else 'not connected'})")

    try:
        while True:
            message = await websocket.receive()
            # The raw receive() (needed here to tell text vs binary frames
            # apart - the receive_text()/receive_json() convenience
            # wrappers collapse that distinction) does NOT auto-raise on
            # disconnect the way those wrappers do; it just hands back a
            # {"type": "websocket.disconnect"} dict. Calling receive()
            # again after that raises RuntimeError (Starlette's connection
            # state machine has already moved past DISCONNECTED) - so this
            # has to be treated as the end of the loop, not skipped.
            if message["type"] == "websocket.disconnect":
                raise WebSocketDisconnect(message.get("code", 1000))
            if message["type"] != "websocket.receive":
                continue

            peer = slot[other_role]
            if peer is None:
                await websocket.send_json({
                    "type": "error",
                    "detail": f"{'Desktop' if other_role == 'desktop' else 'Mobile app'} not connected.",
                })
                continue

            try:
                if "text" in message and message["text"] is not None:
                    await peer.send_text(message["text"])
                elif "bytes" in message and message["bytes"] is not None:
                    await peer.send_bytes(message["bytes"])
            except Exception:
                # Peer socket died between our None-check and send - drop it
                # so the next message re-triggers the "not connected" path
                # instead of raising here.
                if slot[other_role] is peer:
                    slot[other_role] = None
    except WebSocketDisconnect:
        pass
    finally:
        if slot[role] is websocket:
            slot[role] = None
        peer = slot[other_role]
        if peer is not None:
            try:
                await peer.send_json({"type": "peer_disconnected", "role": role})
            except Exception:
                pass
        if slot["desktop"] is None and slot["mobile"] is None:
            _pairs.pop(client_id, None)
        log.info(f"[{client_id}] {role} disconnected")
