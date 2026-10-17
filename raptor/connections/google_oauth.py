"""Google sign-in ("OAuth") for connectors that act on the person's own Google data (YouTube analytics, replying to comments).

Raptor has ONE Google app; every customer approves it for their own account, and what they approved is stored per connection (a
long-lived refresh token, encrypted by the vault). Server settings, all from the environment:
  GOOGLE_OAUTH_CLIENT_ID / GOOGLE_OAUTH_CLIENT_SECRET   the OAuth client of Raptor's Google Cloud project
  PUBLIC_API_URL                                         this server's public address (default: the Render address)
Until Google has reviewed the app, only the test users listed on its consent screen can sign in; that limit is Google's, not ours."""
from __future__ import annotations

import os
from urllib.parse import urlencode

import httpx

from .registry import ConnectorError

AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
TOKEN_URL = "https://oauth2.googleapis.com/token"
REVOKE_URL = "https://oauth2.googleapis.com/revoke"
SERVER_ENV = ("GOOGLE_OAUTH_CLIENT_ID", "GOOGLE_OAUTH_CLIENT_SECRET")


def redirect_uri() -> str:
    base = os.environ.get("PUBLIC_API_URL", "https://websites-api-5wmu.onrender.com").rstrip("/")
    return f"{base}/api/raptor/connections/oauth/google/callback"


def _credentials() -> tuple:
    client_id, client_secret = os.environ.get("GOOGLE_OAUTH_CLIENT_ID"), os.environ.get("GOOGLE_OAUTH_CLIENT_SECRET")
    if not client_id or not client_secret:
        raise ConnectorError("Sign in with Google is not switched on for this Raptor server yet.")
    return client_id, client_secret


def authorize_url(scopes: list, state: str, redirect: str) -> str:
    client_id, _ = _credentials()
    return AUTH_URL + "?" + urlencode({
        "client_id": client_id, "redirect_uri": redirect, "response_type": "code", "scope": " ".join(scopes),
        "access_type": "offline",            # ask for a refresh token, so Raptor keeps working without the person signing in again
        "prompt": "consent",                 # and make Google hand one over every time
        "include_granted_scopes": "true", "state": state,
    })


def _token_call(data: dict) -> dict:
    try:
        resp = httpx.post(TOKEN_URL, data=data, timeout=15)
    except httpx.HTTPError:
        raise ConnectorError("Could not reach Google right now. Try again in a minute.")
    body = {}
    try:
        body = resp.json()
    except Exception:
        pass
    if resp.status_code == 200:
        return body
    if body.get("error") == "invalid_grant":
        raise ConnectorError("Google access was removed or has expired. Sign in with Google again to reconnect.")
    raise ConnectorError("Google did not accept the sign-in (%s)." % (body.get("error") or resp.status_code))


def exchange_code(code: str, redirect: str) -> dict:
    client_id, client_secret = _credentials()
    return _token_call({"code": code, "client_id": client_id, "client_secret": client_secret,
                        "redirect_uri": redirect, "grant_type": "authorization_code"})


def access_token(refresh_token: str) -> str:
    client_id, client_secret = _credentials()
    body = _token_call({"refresh_token": refresh_token, "client_id": client_id, "client_secret": client_secret, "grant_type": "refresh_token"})
    token = body.get("access_token")
    if not token:
        raise ConnectorError("Google did not give access. Sign in with Google again to reconnect.")
    return token


def revoke(token: str) -> None:
    """Tells Google the person's approval is withdrawn. Best effort: a failure never blocks disconnecting."""
    try:
        httpx.post(REVOKE_URL, data={"token": token}, timeout=10)
    except Exception:
        pass
