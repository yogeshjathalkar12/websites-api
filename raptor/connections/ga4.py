"""Google Analytics (GA4), read through a SERVICE ACCOUNT.

The customer creates a service account in their own Google Cloud project, adds its e-mail address as a Viewer of their Analytics
property, and pastes the key file. Raptor then reads their numbers with the official Analytics Data API. Nothing here needs Google to
review Raptor, and Raptor never sees the customer's Google password. The key file is stored encrypted and is never shown again.

Per sync (4 requests): the last 28 days against the 28 before, the daily sessions, the top pages and the top sources."""
from __future__ import annotations

import base64
import json
import re
import time
from datetime import datetime, timedelta, timezone
from typing import Optional

import httpx
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

from .registry import ConnectResult, Connector, ConnectorError, Field, Signal, register

TOKEN_URL = "https://oauth2.googleapis.com/token"        # fixed on purpose: the key file's own token_uri is never trusted
DATA_API = "https://analyticsdata.googleapis.com/v1beta"
SCOPE = "https://www.googleapis.com/auth/analytics.readonly"
TOP_ITEMS = 8


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def parse_key_file(text: str) -> dict:
    try:
        info = json.loads(text)
    except (TypeError, ValueError):
        raise ConnectorError("That is not a service account key file. Paste the whole contents of the .json file you downloaded.")
    if not isinstance(info, dict) or info.get("type") != "service_account" or not info.get("client_email") or not info.get("private_key"):
        raise ConnectorError("That is not a service account key file. Paste the whole contents of the .json file you downloaded.")
    try:
        serialization.load_pem_private_key(str(info["private_key"]).encode(), password=None)
    except Exception:
        raise ConnectorError("The key inside that file could not be read. Download a new key file and paste it again.")
    return info


def access_token(info: dict) -> str:
    now = int(time.time())
    header = {"alg": "RS256", "typ": "JWT"}
    claims = {"iss": info["client_email"], "scope": SCOPE, "aud": TOKEN_URL, "iat": now, "exp": now + 3600}
    signing_input = _b64(json.dumps(header).encode()) + "." + _b64(json.dumps(claims).encode())
    key = serialization.load_pem_private_key(str(info["private_key"]).encode(), password=None)
    signature = key.sign(signing_input.encode(), padding.PKCS1v15(), hashes.SHA256())
    try:
        resp = httpx.post(TOKEN_URL, data={"grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer", "assertion": signing_input + "." + _b64(signature)}, timeout=20)
    except httpx.HTTPError:
        raise ConnectorError("Could not reach Google right now. Try again in a minute.")
    if resp.status_code != 200 or not resp.json().get("access_token"):
        raise ConnectorError("Google did not accept this key file. It may have been deleted or disabled in Google Cloud. Create a new key and paste it.")
    return resp.json()["access_token"]


def run_report(token: str, property_id: str, body: dict, client_email: str = "") -> dict:
    try:
        resp = httpx.post(f"{DATA_API}/properties/{property_id}:runReport", json=body, headers={"Authorization": f"Bearer {token}"}, timeout=30)
    except httpx.HTTPError:
        raise ConnectorError("Could not reach Google Analytics right now. Try again in a minute.")
    if resp.status_code == 200:
        return resp.json()
    if resp.status_code == 403:
        raise ConnectorError(f"Google Analytics says this account has no access. In Analytics go to Admin, Property access management, and add {client_email or 'the service account address'} as a Viewer. "
                             "Also make sure the Google Analytics Data API is enabled in your Google Cloud project.")
    if resp.status_code == 400:
        raise ConnectorError("Google Analytics did not accept that property number. Use the numeric Property ID from Admin, Property details.")
    if resp.status_code == 429:
        raise ConnectorError("Google Analytics' daily limit for your project is used up. It resets by itself; try again later.")
    raise ConnectorError("Google Analytics did not accept the request (%s)." % resp.status_code)


def _num(value) -> Optional[float]:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


class GoogleAnalytics(Connector):
    provider = "ga4"
    channel = "analytics"
    title = "Google Analytics"
    description = "Sessions, visitors, top pages and where your visitors come from, from your own Google Analytics."
    category = "data"
    fields = [
        Field("property_id", "Property ID", "for example: 412345678", "Analytics, Admin, Property details: the number called Property ID."),
        Field("service_account", "Service account key file", "paste the whole .json file here", "Stored encrypted and never shown again.", secret=True, multiline=True),
    ]
    help = [
        "In Google Cloud, create a project (or use one you have) and turn on the “Google Analytics Data API”.",
        "Create a service account, then add a key of type JSON and download the file.",
        "In Google Analytics, open Admin, Property access management, and add the service account's e-mail address as a Viewer.",
        "Paste the Property ID and the whole JSON file here. Raptor reads your numbers; it can never change anything in Analytics.",
    ]
    min_sync_interval = 3600

    def connect(self, inputs: dict) -> ConnectResult:
        property_id = re.sub(r"\D", "", inputs.get("property_id") or "")
        if not (5 <= len(property_id) <= 15):
            raise ConnectorError("The Property ID is a number of 8 to 10 digits. Find it in Analytics, Admin, Property details.")
        info = parse_key_file(inputs.get("service_account") or "")
        token = access_token(info)
        run_report(token, property_id, {"dateRanges": [{"startDate": "7daysAgo", "endDate": "yesterday"}], "metrics": [{"name": "sessions"}]}, info["client_email"])
        compact = json.dumps({"type": "service_account", "client_email": info["client_email"], "private_key": info["private_key"]})
        return ConnectResult(external_id=property_id, label=f"Analytics property {property_id}",
                             config={"property_id": property_id, "client_email": info["client_email"]}, secret=compact)

    def sync(self, connection: dict, secret: Optional[str]) -> list:
        info = parse_key_file(secret or "")
        property_id = connection["external_id"]
        email = info["client_email"]
        token = access_token(info)
        now = datetime.now(timezone.utc)
        today = now.strftime("%Y-%m-%d")
        out = []

        # 1) the last 28 complete days against the 28 before
        totals = run_report(token, property_id, {
            "dateRanges": [{"startDate": "28daysAgo", "endDate": "yesterday"}, {"startDate": "56daysAgo", "endDate": "29daysAgo"}],
            "metrics": [{"name": "sessions"}, {"name": "totalUsers"}, {"name": "newUsers"}, {"name": "engagementRate"}, {"name": "keyEvents"}],
        }, email)
        names = ["ga_sessions", "ga_users", "ga_new_users", "ga_engagement_rate", "ga_key_events"]
        headers = [h.get("name") for h in totals.get("dimensionHeaders", [])]
        for row in totals.get("rows", []):
            which = 0
            if "dateRange" in headers:
                which = 1 if row["dimensionValues"][headers.index("dateRange")]["value"] == "date_range_1" else 0
            suffix = "28d" if which == 0 else "prev28d"
            for name, cell in zip(names, row.get("metricValues", [])):
                v = _num(cell.get("value"))
                if v is not None:
                    out.append(Signal("metric", f"{name}_{suffix}", v, entity={"property": property_id}, occurred_at=now, dedupe_key=f"ga:{name}_{suffix}:{today}"))

        # 2) sessions by day (complete days only, so a stored day never changes)
        daily = run_report(token, property_id, {
            "dateRanges": [{"startDate": "28daysAgo", "endDate": "yesterday"}], "dimensions": [{"name": "date"}],
            "metrics": [{"name": "sessions"}, {"name": "totalUsers"}], "orderBys": [{"dimension": {"dimensionName": "date"}}],
        }, email)
        for row in daily.get("rows", []):
            raw = row["dimensionValues"][0]["value"]
            try:
                day = datetime.strptime(raw, "%Y%m%d").replace(tzinfo=timezone.utc)
            except ValueError:
                continue
            sessions, users = (_num(c.get("value")) for c in row["metricValues"][:2])
            if sessions is not None:
                out.append(Signal("metric", "ga_sessions_day", sessions, entity={"users": users or 0, "date": day.strftime("%Y-%m-%d")}, occurred_at=day + timedelta(hours=12), dedupe_key=f"ga:day:{raw}"))

        # 3) and 4) what is read most and where visitors come from: one signal each, per day
        for dimension, metric, name in (("pagePath", "screenPageViews", "ga_top_pages"), ("sessionSourceMedium", "sessions", "ga_top_sources")):
            top = run_report(token, property_id, {
                "dateRanges": [{"startDate": "28daysAgo", "endDate": "yesterday"}], "dimensions": [{"name": dimension}], "metrics": [{"name": metric}],
                "orderBys": [{"metric": {"metricName": metric}, "desc": True}], "limit": TOP_ITEMS,
            }, email)
            items = [{"label": r["dimensionValues"][0]["value"][:120], "value": _num(r["metricValues"][0].get("value")) or 0} for r in top.get("rows", [])]
            if items:
                out.append(Signal("metric", name, sum(i["value"] for i in items), entity={"items": items}, occurred_at=now, dedupe_key=f"ga:{name}:{today}"))
        return out


register(GoogleAnalytics())
