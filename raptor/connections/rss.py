"""News feeds. Tracks news about a word or company (through Google News) or any RSS / Atom feed address, and turns each new headline into
a signal, so a competitor launching something or a customer in the news shows up without anyone searching for it.

Feeds come from an address a customer typed, so every fetch goes through net.py (public https only, size limit, redirects re-checked),
and a feed that declares a DOCTYPE or entities is refused outright: that is how XML "entity expansion" attacks are made."""
from __future__ import annotations

import hashlib
import re
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Optional
from urllib.parse import quote_plus

from . import net
from .registry import ConnectResult, Connector, ConnectorError, Field, Signal, register

MAX_ITEMS = 30
GOOGLE_NEWS = "https://news.google.com/rss/search?q={q}&hl=en-IN&gl=IN&ceid=IN:en"
_ATOM = "{http://www.w3.org/2005/Atom}"
_CLEAN = re.compile(r"<[^>]+>")


def feed_url(kind: str, value: str) -> str:
    value = (value or "").strip()
    if not value:
        raise ConnectorError("Type a word or company to follow, or paste a feed address.")
    if kind == "keyword":
        if len(value) > 120:
            raise ConnectorError("Keep the search under 120 characters.")
        return GOOGLE_NEWS.format(q=quote_plus(value))
    if not re.match(r"^https://", value, re.I):
        raise ConnectorError("A feed address must start with https://")
    return value


def _text(el, tag: str) -> str:
    found = el.find(tag)
    return (found.text or "").strip() if found is not None and found.text else ""


def _when(raw: str) -> Optional[datetime]:
    if not raw:
        return None
    try:
        parsed = parsedate_to_datetime(raw)
    except (TypeError, ValueError):
        try:
            parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        except ValueError:
            return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def parse_feed(xml_text: str) -> tuple:
    """(feed title, [items]) from RSS 2.0 or Atom. Each item is {title, url, source, published, key}."""
    head = xml_text[:4000].lower()
    if "<!doctype" in head or "<!entity" in xml_text.lower():
        raise ConnectorError("That feed uses features that are not allowed, so it was not read.")
    try:
        root = ET.fromstring(xml_text.strip())
    except ET.ParseError:
        raise ConnectorError("That address did not give a news feed. Check that it is an RSS or Atom link.")
    items = []
    if root.tag.endswith("feed"):                                   # Atom
        title = _text(root, _ATOM + "title")
        for entry in root.findall(_ATOM + "entry"):
            link = ""
            for l in entry.findall(_ATOM + "link"):
                if l.get("rel", "alternate") == "alternate":
                    link = l.get("href", "")
                    break
            items.append({"title": _text(entry, _ATOM + "title"), "url": link, "source": title, "published": _when(_text(entry, _ATOM + "updated") or _text(entry, _ATOM + "published")),
                          "key": _text(entry, _ATOM + "id") or link})
    else:                                                           # RSS
        channel = root.find("channel")
        if channel is None:
            raise ConnectorError("That address did not give a news feed. Check that it is an RSS or Atom link.")
        title = _text(channel, "title")
        for it in channel.findall("item"):
            link = _text(it, "link")
            source_el = it.find("source")
            source = (source_el.text or "").strip() if source_el is not None and source_el.text else ""
            headline = _text(it, "title")
            if not source and " - " in headline:                    # Google News writes "Headline - Publisher"
                headline, _, source = headline.rpartition(" - ")
            items.append({"title": _CLEAN.sub("", headline).strip(), "url": link, "source": source or title, "published": _when(_text(it, "pubDate")),
                          "key": _text(it, "guid") or link})
    return title, [i for i in items if i["title"]]


class NewsFeed(Connector):
    provider = "news_feed"
    channel = "news"
    title = "News feed"
    description = "Follow news about a competitor, a customer or a topic. Each new headline becomes a signal."
    category = "data"
    fields = [
        Field("kind", "What to follow", options=[{"value": "keyword", "label": "News about a word or company"}, {"value": "feed", "label": "A feed address (RSS)"}]),
        Field("value", "Word, company or address", "for example: Acme Ltd, or https://example.com/feed"),
    ]
    help = [
        "Pick “News about a word or company” and type a competitor, a customer or a topic. Raptor follows Google News for it.",
        "Or pick “A feed address” and paste any blog or news feed link (RSS or Atom).",
        "Add one for each competitor or topic you care about. New headlines appear here and in the Home tab.",
    ]
    min_sync_interval = 1800

    def connect(self, inputs: dict) -> ConnectResult:
        kind = inputs.get("kind") if inputs.get("kind") in ("keyword", "feed") else "keyword"
        value = (inputs.get("value") or "").strip()
        url = feed_url(kind, value)
        title, _items = parse_feed(net.fetch_text(url))
        external = hashlib.sha1(url.lower().encode()).hexdigest()[:20]
        label = value if kind == "keyword" else (title or value)
        return ConnectResult(external_id=external, label=label[:100], config={"url": url, "kind": kind, "query": value})

    def sync(self, connection: dict, secret: Optional[str]) -> list:
        config = connection.get("config") or {}
        url = config.get("url")
        if not url:
            raise ConnectorError("This feed has no address saved. Remove it and add it again.")
        feed_title, items = parse_feed(net.fetch_text(url))
        label = connection.get("label") or feed_title
        now = datetime.now(timezone.utc)
        items.sort(key=lambda i: i["published"] or now, reverse=True)
        signals = []
        for item in items[:MAX_ITEMS]:
            digest = hashlib.sha1((item["key"] or item["url"] or item["title"]).encode()).hexdigest()[:16]
            signals.append(Signal("mention", "news", text_value=item["title"][:300], occurred_at=item["published"] or now,
                                  entity={"url": item["url"], "source": item["source"], "feed": label, "query": config.get("query", "")},
                                  dedupe_key=f"news:{digest}"))
        return signals


register(NewsFeed())
