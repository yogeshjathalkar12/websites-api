"""YouTube (public channel data). Needs NO sign-in from the user: they paste their channel link and Raptor reads what anyone can see
(subscribers, total views, video count, and the views / likes / comments of the latest videos) through the official YouTube Data API.

The API key is Raptor's own (server env YOUTUBE_API_KEY), shared by every organization, so its daily quota is ours to protect: one
sync costs 3 quota units, and the router limits how often a connection may sync. Private analytics (watch time, revenue) need the
owner to sign in with Google and are a separate connector."""
from __future__ import annotations

import os
import re
from datetime import datetime, timezone
from typing import Optional

import httpx

from .registry import ConnectResult, Connector, ConnectorError, Field, Signal, register

API = "https://www.googleapis.com/youtube/v3"
RECENT_VIDEOS = 10
_CHANNEL_ID = re.compile(r"^UC[0-9A-Za-z_-]{22}$")
_HANDLE = re.compile(r"^@[0-9A-Za-z._-]{3,60}$")


def parse_channel_reference(text: str) -> tuple:
    """Turns whatever the user pasted into ("id", "UC...") or ("handle", "@name"). Raises ConnectorError if it is not one of those."""
    raw = (text or "").strip()
    if not raw:
        raise ConnectorError("Paste your YouTube channel link, for example https://www.youtube.com/@yourchannel")
    if _CHANNEL_ID.match(raw):
        return "id", raw
    if _HANDLE.match(raw):
        return "handle", raw
    if re.match(r"^[0-9A-Za-z._-]{3,60}$", raw) and "/" not in raw:
        return "handle", "@" + raw
    candidate = raw if re.match(r"^https?://", raw, re.I) else "https://" + raw
    m = re.match(r"^https?://(?:www\.|m\.)?youtube\.com/(.*)$", candidate, re.I)
    if not m:
        raise ConnectorError("That does not look like a YouTube channel link.")
    path = m.group(1).split("?")[0].split("#")[0].strip("/")
    first = path.split("/")[0] if path else ""
    if first.startswith("@") and _HANDLE.match(first):
        return "handle", first
    parts = path.split("/")
    if parts[0] == "channel" and len(parts) > 1 and _CHANNEL_ID.match(parts[1]):
        return "id", parts[1]
    raise ConnectorError("Use your channel's @handle link (https://www.youtube.com/@yourchannel) or its /channel/ link. "
                         "Links of videos and older /c/ names cannot be looked up.")


def _key() -> str:
    key = os.environ.get("YOUTUBE_API_KEY")
    if not key:
        raise ConnectorError("YouTube is not switched on for this Raptor server yet.")
    return key


def _get(path: str, **params) -> dict:
    try:
        resp = httpx.get(f"{API}/{path}", params={**params, "key": _key()}, timeout=15)
    except httpx.HTTPError:
        raise ConnectorError("Could not reach YouTube right now. Try again in a minute.")
    if resp.status_code == 200:
        return resp.json()
    reason = ""
    try:
        reason = (resp.json().get("error", {}).get("errors") or [{}])[0].get("reason", "")
    except Exception:
        pass
    if reason in ("quotaExceeded", "rateLimitExceeded", "dailyLimitExceeded"):
        raise ConnectorError("YouTube's daily limit for Raptor is used up. It resets by itself; try again later.")
    raise ConnectorError("YouTube did not accept the request (%s)." % (reason or resp.status_code))


def _num(value) -> Optional[float]:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


class YouTubePublic(Connector):
    provider = "youtube_public"
    title = "YouTube channel"
    description = "Track your channel's subscribers, views and latest videos. Only public numbers; no sign-in needed."
    category = "data"
    fields = [Field("channel", "Channel link", "https://www.youtube.com/@yourchannel",
                    "Your channel's @handle link. Open your channel on YouTube and copy the address.")]
    server_env = ("YOUTUBE_API_KEY",)
    min_sync_interval = 900

    def connect(self, inputs: dict) -> ConnectResult:
        kind, value = parse_channel_reference(inputs.get("channel", ""))
        data = _get("channels", part="snippet,statistics,contentDetails", **({"id": value} if kind == "id" else {"forHandle": value}))
        items = data.get("items") or []
        if not items:
            raise ConnectorError("No YouTube channel was found for that link.")
        item = items[0]
        uploads = (item.get("contentDetails", {}).get("relatedPlaylists", {}) or {}).get("uploads")
        return ConnectResult(
            external_id=item["id"],
            label=item.get("snippet", {}).get("title") or value,
            config={"handle": item.get("snippet", {}).get("customUrl") or (value if kind == "handle" else ""), "uploads_playlist": uploads},
        )

    def sync(self, connection: dict, secret: Optional[str]) -> list:
        channel_id = connection["external_id"]
        now = datetime.now(timezone.utc)
        day = now.strftime("%Y-%m-%d")
        signals = []

        data = _get("channels", part="statistics,contentDetails", id=channel_id)
        items = data.get("items") or []
        if not items:
            raise ConnectorError("This channel could not be found any more. It may have been removed or renamed.")
        stats = items[0].get("statistics", {})
        uploads = (items[0].get("contentDetails", {}).get("relatedPlaylists", {}) or {}).get("uploads") \
            or (connection.get("config") or {}).get("uploads_playlist")
        for name, field_name in (("subscribers", "subscriberCount"), ("views", "viewCount"), ("videos", "videoCount")):
            if name == "subscribers" and stats.get("hiddenSubscriberCount"):
                continue                       # the owner hides the count: do not invent it
            value = _num(stats.get(field_name))
            if value is not None:
                signals.append(Signal("metric", name, value, entity={"channel_id": channel_id}, occurred_at=now,
                                      dedupe_key=f"channel:{name}:{day}"))

        if uploads:
            playlist = _get("playlistItems", part="contentDetails", playlistId=uploads, maxResults=RECENT_VIDEOS)
            ids = [i["contentDetails"]["videoId"] for i in playlist.get("items", []) if i.get("contentDetails", {}).get("videoId")]
            if ids:
                videos = _get("videos", part="snippet,statistics", id=",".join(ids))
                for v in videos.get("items", []):
                    entity = {"video_id": v["id"], "title": v.get("snippet", {}).get("title", ""), "channel_id": channel_id}
                    for name, field_name in (("video_views", "viewCount"), ("video_likes", "likeCount"), ("video_comments", "commentCount")):
                        value = _num(v.get("statistics", {}).get(field_name))
                        if value is not None:
                            signals.append(Signal("metric", name, value, entity=entity, occurred_at=now,
                                                  dedupe_key=f"video:{v['id']}:{name}:{day}"))
        return signals


register(YouTubePublic())
