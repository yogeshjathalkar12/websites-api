"""Google reviews: the public star rating, the number of reviews and the latest written reviews of a business, through the official
Places API. The customer brings their OWN Google API key (the lookups cost a little per request and belong on their Google Cloud bill,
not ours); it is stored encrypted and never shown again.

Per sync: one Place Details request."""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from typing import Optional

import httpx

from .registry import ConnectResult, Connector, ConnectorError, Field, Signal, register

API = "https://places.googleapis.com/v1"
_PLACE_ID = re.compile(r"^ChIJ[0-9A-Za-z_-]{10,}$")
DETAIL_FIELDS = "id,displayName,formattedAddress,rating,userRatingCount,googleMapsUri,reviews"


def _headers(key: str, fields: str) -> dict:
    return {"X-Goog-Api-Key": key, "X-Goog-FieldMask": fields, "Content-Type": "application/json"}


def _check(resp: httpx.Response) -> dict:
    if resp.status_code == 200:
        return resp.json()
    if resp.status_code == 403:
        raise ConnectorError("Google did not accept this key. Make sure “Places API (New)” is turned on and billing is enabled for that Google Cloud project, and that the key is not limited to other APIs.")
    if resp.status_code == 400:
        raise ConnectorError("Google did not accept this key or place. Check the key and try again.")
    if resp.status_code == 404:
        raise ConnectorError("No business was found for that place. Search again with the business name and city.")
    if resp.status_code == 429:
        raise ConnectorError("Google's limit for your key is used up. It resets by itself; try again later.")
    raise ConnectorError("Google did not accept the request (%s)." % resp.status_code)


def find_place(key: str, text: str) -> str:
    text = (text or "").strip()
    if _PLACE_ID.match(text):
        return text
    if len(text) < 3:
        raise ConnectorError("Type the business name and city, or paste its Place ID.")
    try:
        resp = httpx.post(f"{API}/places:searchText", json={"textQuery": text[:200]}, headers=_headers(key, "places.id,places.displayName,places.formattedAddress"), timeout=20)
    except httpx.HTTPError:
        raise ConnectorError("Could not reach Google right now. Try again in a minute.")
    places = _check(resp).get("places") or []
    if not places:
        raise ConnectorError("No business was found for that. Try the business name with the city, or paste its Place ID.")
    return places[0]["id"]


def place_details(key: str, place_id: str) -> dict:
    try:
        resp = httpx.get(f"{API}/places/{place_id}", headers=_headers(key, DETAIL_FIELDS), timeout=20)
    except httpx.HTTPError:
        raise ConnectorError("Could not reach Google right now. Try again in a minute.")
    return _check(resp)


def _time(raw) -> Optional[datetime]:
    try:
        return datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
    except ValueError:
        return None


class GoogleReviews(Connector):
    provider = "google_reviews"
    channel = "reviews"
    title = "Google reviews"
    description = "Watch your star rating and read new reviews as they arrive. Works with your own Google key."
    category = "data"
    fields = [
        Field("place", "Business", "for example: Acme Interiors, Pune", "The business name with its city, or the Place ID."),
        Field("api_key", "Your Google API key", "AIza…", "Stored encrypted and never shown again.", secret=True),
    ]
    help = [
        "In Google Cloud, use a project of yours with billing turned on, and enable “Places API (New)”.",
        "Create an API key (APIs and Services, Credentials). It stays on your own Google bill: a check costs a fraction of a rupee.",
        "Paste the key and the business name with its city. Raptor then reads the public rating and the latest reviews.",
        "Google shows up to five recent reviews per check. Raptor keeps each one it sees, so the list grows over time.",
    ]
    min_sync_interval = 3600

    def connect(self, inputs: dict) -> ConnectResult:
        key = (inputs.get("api_key") or "").strip()
        if len(key) < 20:
            raise ConnectorError("Paste your Google API key.")
        place_id = find_place(key, inputs.get("place") or "")
        data = place_details(key, place_id)
        name = (data.get("displayName") or {}).get("text") or "Your business"
        return ConnectResult(external_id=place_id, label=name[:100], secret=json.dumps({"api_key": key}),
                             config={"place_id": place_id, "address": data.get("formattedAddress", ""), "maps_url": data.get("googleMapsUri", "")})

    def sync(self, connection: dict, secret: Optional[str]) -> list:
        try:
            key = (json.loads(secret or "{}") or {}).get("api_key")
        except ValueError:
            key = None
        if not key:
            raise ConnectorError("This connection has no saved key. Remove it and add it again.")
        data = place_details(key, connection["external_id"])
        now = datetime.now(timezone.utc)
        day = now.strftime("%Y-%m-%d")
        out = []
        entity = {"place": (data.get("displayName") or {}).get("text", ""), "maps_url": data.get("googleMapsUri", "")}
        if isinstance(data.get("rating"), (int, float)):
            out.append(Signal("metric", "rating", float(data["rating"]), entity=entity, occurred_at=now, dedupe_key=f"rating:{day}"))
        if isinstance(data.get("userRatingCount"), (int, float)):
            out.append(Signal("metric", "review_count", float(data["userRatingCount"]), entity=entity, occurred_at=now, dedupe_key=f"review_count:{day}"))
        for review in data.get("reviews") or []:
            rid = review.get("name")
            text = ((review.get("text") or review.get("originalText") or {}).get("text") or "").strip()
            stars = review.get("rating")
            if not rid or not isinstance(stars, (int, float)):
                continue
            out.append(Signal("mention", "review", float(stars), text_value=text[:1500],
                              entity={"author": (review.get("authorAttribution") or {}).get("displayName", ""), "rating": stars, "maps_url": data.get("googleMapsUri", "")},
                              occurred_at=_time(review.get("publishTime")) or now, dedupe_key=f"review:{rid}"))
        return out


register(GoogleReviews())
