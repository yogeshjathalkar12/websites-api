"""YouTube (signed in). The owner approves Raptor with their Google account, which unlocks what a public key cannot see or do:
private analytics for the last 28 days, every comment on the channel, and posting a reply as the channel.

Permissions asked from Google, and why:
  youtube.force-ssl      read all comments of the channel and post replies (the narrowest YouTube permission that can reply)
  yt-analytics.readonly  the channel's private numbers (views, minutes watched, subscribers gained)
Raptor never posts anything by itself: a reply is sent only when a person presses Send on a reply they wrote or approved."""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Optional

import httpx

from . import google_oauth
from .registry import ConnectResult, Connector, ConnectorError, register
from .youtube import (API, CommentsOff, _num, api_get, channel_signals, comment_signal, video_signals)
from .registry import Signal

ANALYTICS_API = "https://youtubeanalytics.googleapis.com/v2"
SCOPES = [
    "https://www.googleapis.com/auth/youtube.force-ssl",
    "https://www.googleapis.com/auth/yt-analytics.readonly",
]
ANALYTICS_DAYS = 28
ALL_COMMENTS = 50
# metric asked from the Analytics API -> the name Raptor stores
ANALYTICS_METRICS = {
    "views": "views_28d", "estimatedMinutesWatched": "watch_minutes_28d", "subscribersGained": "subs_gained_28d",
    "subscribersLost": "subs_lost_28d", "likes": "likes_28d", "comments": "comments_28d", "shares": "shares_28d",
}


def _refresh_token(secret: Optional[str]) -> str:
    try:
        token = (json.loads(secret or "{}") or {}).get("refresh_token")
    except ValueError:
        token = None
    if not token:
        raise ConnectorError("This connection has no saved Google access. Sign in with Google again to reconnect.")
    return token


class YouTubeAccount(Connector):
    provider = "youtube_account"
    title = "YouTube (sign in)"
    description = "Sign in with Google to see private analytics, read every comment and reply to comments from Raptor."
    category = "channel"
    auth = "oauth"
    can_reply = True
    server_env = google_oauth.SERVER_ENV
    min_sync_interval = 900
    channel = "youtube"
    help = [
        "Press “Sign in with Google” and choose the Google account that owns your YouTube channel.",
        "Allow both permissions: reading comments and analytics, and replying to comments. Raptor never posts anything by itself: a reply is sent only when you press Send.",
        "You come back here when it is done. Disconnecting withdraws Raptor's access in your Google account.",
    ]

    def authorize_url(self, state: str, redirect_uri: str) -> str:
        return google_oauth.authorize_url(SCOPES, state, redirect_uri)

    def complete(self, code: str, redirect_uri: str) -> ConnectResult:
        tokens = google_oauth.exchange_code(code, redirect_uri)
        refresh = tokens.get("refresh_token")
        if not refresh:
            raise ConnectorError("Google did not give long-term access. Remove Raptor at myaccount.google.com/permissions and try again.")
        granted = set((tokens.get("scope") or "").split())
        if not set(SCOPES) <= granted:
            raise ConnectorError("Raptor needs both permissions to read comments and analytics and to reply. Sign in again and allow them all.")
        data = api_get("channels", tokens["access_token"], part="snippet,contentDetails", mine="true")
        items = data.get("items") or []
        if not items:
            raise ConnectorError("This Google account has no YouTube channel. Sign in with the account that owns your channel.")
        item = items[0]
        uploads = (item.get("contentDetails", {}).get("relatedPlaylists", {}) or {}).get("uploads")
        return ConnectResult(
            external_id=item["id"], label=item.get("snippet", {}).get("title") or "My YouTube channel",
            config={"handle": item.get("snippet", {}).get("customUrl") or "", "uploads_playlist": uploads},
            secret=json.dumps({"refresh_token": refresh}),
        )

    def revoke(self, secret: Optional[str]) -> None:
        try:
            google_oauth.revoke(_refresh_token(secret))
        except ConnectorError:
            pass

    def sync(self, connection: dict, secret: Optional[str]) -> list:
        token = google_oauth.access_token(_refresh_token(secret))
        channel_id = connection["external_id"]
        now = datetime.now(timezone.utc)
        data = api_get("channels", token, part="statistics,contentDetails", mine="true")
        items = data.get("items") or []
        if not items:
            raise ConnectorError("The signed-in Google account no longer has this channel. Sign in with Google again.")
        uploads = (items[0].get("contentDetails", {}).get("relatedPlaylists", {}) or {}).get("uploads") \
            or (connection.get("config") or {}).get("uploads_playlist")
        signals = channel_signals(items[0].get("statistics", {}), channel_id, now)
        videos, listed = video_signals(uploads, channel_id, now, token)
        titles = dict(listed)

        try:
            threads = api_get("commentThreads", token, part="snippet", allThreadsRelatedToChannelId=channel_id,
                              maxResults=ALL_COMMENTS, order="time", textFormat="plainText").get("items", [])
        except CommentsOff:
            threads = []
        comments = []
        for thread in threads:
            sig = comment_signal(thread, titles, channel_id)
            if sig and not sig.entity.get("mine"):
                comments.append(sig)

        return signals + videos + comments + self._analytics(token, channel_id, now)

    def _analytics(self, token: str, channel_id: str, now: datetime) -> list:
        end = (now - timedelta(days=1)).date()
        start = end - timedelta(days=ANALYTICS_DAYS - 1)
        try:
            resp = httpx.get(f"{ANALYTICS_API}/reports", headers={"Authorization": f"Bearer {token}"}, timeout=20, params={
                "ids": "channel==MINE", "startDate": start.isoformat(), "endDate": end.isoformat(),
                "metrics": ",".join(ANALYTICS_METRICS),
            })
        except httpx.HTTPError:
            raise ConnectorError("Could not reach YouTube Analytics right now. Try again in a minute.")
        if resp.status_code != 200:
            reason = ""
            try:
                reason = (resp.json().get("error", {}).get("errors") or [{}])[0].get("reason", "")
            except Exception:
                pass
            if resp.status_code == 403 and reason in ("accessNotConfigured", "forbidden"):
                raise ConnectorError("YouTube Analytics is not switched on for Raptor's Google project, or access to it was not granted.")
            raise ConnectorError("YouTube Analytics did not accept the request (%s)." % (reason or resp.status_code))
        body = resp.json()
        rows = body.get("rows") or []
        if not rows:
            return []                       # a new or silent channel: no numbers yet
        day = now.strftime("%Y-%m-%d")
        out = []
        for header, value in zip([h.get("name") for h in body.get("columnHeaders", [])], rows[0]):
            name = ANALYTICS_METRICS.get(header)
            number = _num(value)
            if name and number is not None:
                out.append(Signal("metric", name, number, entity={"channel_id": channel_id, "days": ANALYTICS_DAYS}, occurred_at=now,
                                  dedupe_key=f"an28:{name}:{day}"))
        return out

    def reply(self, connection: dict, secret: Optional[str], parent_id: str, text: str) -> str:
        token = google_oauth.access_token(_refresh_token(secret))
        try:
            resp = httpx.post(f"{API}/comments", params={"part": "snippet"}, headers={"Authorization": f"Bearer {token}"}, timeout=20,
                              json={"snippet": {"parentId": parent_id, "textOriginal": text}})
        except httpx.HTTPError:
            raise ConnectorError("Could not reach YouTube right now. Your reply was not sent; try again.")
        if resp.status_code == 200:
            return str(resp.json().get("id") or "")
        if resp.status_code == 404:
            raise ConnectorError("That comment is not there any more. It may have been deleted.")
        if resp.status_code in (400, 403):
            raise ConnectorError("YouTube would not accept this reply. The comment may be closed to replies or held for review.")
        if resp.status_code == 401:
            raise ConnectorError("Google access has expired. Sign in with Google again to reconnect.")
        raise ConnectorError("YouTube did not accept the reply (%s)." % resp.status_code)


register(YouTubeAccount())
