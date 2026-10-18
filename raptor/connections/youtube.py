"""YouTube (public channel data). Needs NO sign-in from the user: they paste their channel link and Raptor reads what anyone can see
(subscribers, total views, video count, the views / likes / comments of the latest videos, and the public comments under them)
through the official YouTube Data API.

The API key is Raptor's own (server env YOUTUBE_API_KEY), shared by every organization, so its daily quota is ours to protect: one
sync costs about 8 quota units (3 for the numbers, 1 per video for comments), and the router limits how often a connection may
sync. Private analytics and replying need the owner to sign in with Google: see youtube_account.py, which reuses the helpers here."""
from __future__ import annotations

import html
import os
import re
from datetime import datetime, timezone
from typing import Optional

import httpx

from .registry import ConnectResult, Connector, ConnectorError, Field, Signal, register

API = "https://www.googleapis.com/youtube/v3"
RECENT_VIDEOS = 10
COMMENT_VIDEOS = 5          # public comments are read under this many of the newest videos
COMMENTS_PER_VIDEO = 20
_CHANNEL_ID = re.compile(r"^UC[0-9A-Za-z_-]{22}$")
_HANDLE = re.compile(r"^@[0-9A-Za-z._-]{3,60}$")
_TAGS = re.compile(r"<[^>]+>")


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


def _error_reason(resp) -> str:
    try:
        return (resp.json().get("error", {}).get("errors") or [{}])[0].get("reason", "")
    except Exception:
        return ""


def api_get(path: str, token: Optional[str] = None, base: str = API, **params) -> dict:
    """GET on the YouTube APIs. With a token (the person signed in) it acts as them; without, it uses Raptor's key."""
    headers = {"Authorization": f"Bearer {token}"} if token else None
    if not token:
        params["key"] = _key()
    try:
        resp = httpx.get(f"{base}/{path}", params=params, headers=headers, timeout=15) if headers \
            else httpx.get(f"{base}/{path}", params=params, timeout=15)
    except httpx.HTTPError:
        raise ConnectorError("Could not reach YouTube right now. Try again in a minute.")
    if resp.status_code == 200:
        return resp.json()
    reason = _error_reason(resp)
    if reason in ("quotaExceeded", "rateLimitExceeded", "dailyLimitExceeded"):
        raise ConnectorError("YouTube's daily limit for Raptor is used up. It resets by itself; try again later.")
    if reason == "commentsDisabled":
        raise CommentsOff()
    if reason in ("accessNotConfigured", "youtubeSignupRequired"):
        raise ConnectorError("A YouTube service is not switched on for Raptor's Google project (%s)." % reason)
    if resp.status_code == 401:
        raise ConnectorError("Google access has expired. Sign in with Google again to reconnect.")
    raise ConnectorError("YouTube did not accept the request (%s)." % (reason or resp.status_code))


class CommentsOff(ConnectorError):
    """A video with comments turned off: not an error for the person, just nothing to read."""


def _num(value) -> Optional[float]:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _plain(text: str) -> str:
    return html.unescape(_TAGS.sub("", (text or "").replace("<br>", "\n").replace("<br />", "\n"))).strip()


def _parse_time(value) -> Optional[datetime]:
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None


def channel_signals(stats: dict, channel_id: str, now: datetime) -> list:
    day = now.strftime("%Y-%m-%d")
    out = []
    for name, field_name in (("subscribers", "subscriberCount"), ("views", "viewCount"), ("videos", "videoCount")):
        if name == "subscribers" and stats.get("hiddenSubscriberCount"):
            continue                       # the owner hides the count: do not invent it
        value = _num(stats.get(field_name))
        if value is not None:
            out.append(Signal("metric", name, value, entity={"channel_id": channel_id}, occurred_at=now, dedupe_key=f"channel:{name}:{day}"))
    return out


def video_signals(uploads: Optional[str], channel_id: str, now: datetime, token: Optional[str] = None) -> tuple:
    """(signals, [(video_id, title)]) for the newest videos of an uploads playlist."""
    if not uploads:
        return [], []
    day = now.strftime("%Y-%m-%d")
    playlist = api_get("playlistItems", token, part="contentDetails", playlistId=uploads, maxResults=RECENT_VIDEOS)
    ids = [i["contentDetails"]["videoId"] for i in playlist.get("items", []) if i.get("contentDetails", {}).get("videoId")]
    if not ids:
        return [], []
    out, listed = [], []
    for v in api_get("videos", token, part="snippet,statistics", id=",".join(ids)).get("items", []):
        title = v.get("snippet", {}).get("title", "")
        listed.append((v["id"], title))
        entity = {"video_id": v["id"], "title": title, "channel_id": channel_id}
        for name, field_name in (("video_views", "viewCount"), ("video_likes", "likeCount"), ("video_comments", "commentCount")):
            value = _num(v.get("statistics", {}).get(field_name))
            if value is not None:
                out.append(Signal("metric", name, value, entity=entity, occurred_at=now, dedupe_key=f"video:{v['id']}:{name}:{day}"))
    return out, listed


def comment_signal(thread: dict, titles: dict, channel_id: str) -> Optional[Signal]:
    """One comment thread -> one 'mention' signal. The comment's own id makes it unique, so it is stored once."""
    top = (thread.get("snippet") or {}).get("topLevelComment") or {}
    snip = top.get("snippet") or {}
    comment_id = top.get("id") or thread.get("id")
    text = snip.get("textOriginal") or _plain(snip.get("textDisplay", ""))
    if not comment_id or not text:
        return None
    video_id = snip.get("videoId") or (thread.get("snippet") or {}).get("videoId") or ""
    return Signal(
        "mention", "comment", text_value=text[:2000], occurred_at=_parse_time(snip.get("publishedAt")),
        entity={"comment_id": comment_id, "video_id": video_id, "title": titles.get(video_id, ""), "channel_id": channel_id,
                "author": snip.get("authorDisplayName", ""), "author_channel": (snip.get("authorChannelUrl") or ""),
                "likes": snip.get("likeCount", 0), "replies": (thread.get("snippet") or {}).get("totalReplyCount", 0),
                "mine": bool(snip.get("authorChannelId", {}).get("value") == channel_id)},
        dedupe_key=f"comment:{comment_id}")


def public_comment_signals(listed: list, channel_id: str) -> list:
    titles = dict(listed)
    out = []
    for video_id, _title in listed[:COMMENT_VIDEOS]:
        try:
            data = api_get("commentThreads", part="snippet", videoId=video_id, maxResults=COMMENTS_PER_VIDEO, order="time", textFormat="plainText")
        except CommentsOff:
            continue
        for thread in data.get("items", []):
            sig = comment_signal(thread, titles, channel_id)
            if sig and not sig.entity.get("mine"):
                out.append(sig)
    return out


class YouTubePublic(Connector):
    provider = "youtube_public"
    title = "YouTube channel"
    description = "Track your channel's subscribers, views, latest videos and the public comments under them. No sign-in needed."
    category = "data"
    fields = [Field("channel", "Channel link", "https://www.youtube.com/@yourchannel",
                    "Your channel's @handle link. Open your channel on YouTube and copy the address.")]
    server_env = ("YOUTUBE_API_KEY",)
    min_sync_interval = 900
    channel = "youtube"
    help = [
        "Open your channel on YouTube and copy its address (it looks like https://www.youtube.com/@yourchannel).",
        "Paste it here. Nothing to sign in to: Raptor reads only the numbers anyone can see.",
        "For private numbers (watch time, new subscribers) and to reply to comments, also connect “YouTube (sign in)”.",
    ]

    def connect(self, inputs: dict) -> ConnectResult:
        kind, value = parse_channel_reference(inputs.get("channel", ""))
        data = api_get("channels", part="snippet,statistics,contentDetails", **({"id": value} if kind == "id" else {"forHandle": value}))
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
        data = api_get("channels", part="statistics,contentDetails", id=channel_id)
        items = data.get("items") or []
        if not items:
            raise ConnectorError("This channel could not be found any more. It may have been removed or renamed.")
        uploads = (items[0].get("contentDetails", {}).get("relatedPlaylists", {}) or {}).get("uploads") \
            or (connection.get("config") or {}).get("uploads_playlist")
        signals = channel_signals(items[0].get("statistics", {}), channel_id, now)
        videos, listed = video_signals(uploads, channel_id, now)
        return signals + videos + public_comment_signals(listed, channel_id)


register(YouTubePublic())
