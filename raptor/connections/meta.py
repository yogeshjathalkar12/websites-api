"""Meta channels: Facebook Pages, Lead Ads and Instagram, through ONE "Connect with Facebook" sign-in.

The person signs in once and chooses which Pages to share (Meta's own dialog asks). For every shared Page Raptor creates a Facebook Page
connection and a Lead Ads connection, and, if an Instagram professional account is linked to that Page, an Instagram connection. Each keeps
the Page's access token, encrypted, and nothing else of the person's Facebook account.

Meta pushes new messages, comments and leads to ONE address for the whole app (hooks.py, /api/raptor/hooks/meta). The request carries a
signature made with the app secret, and Raptor refuses anything that does not match. Raptor reads what arrives, finds the connections that
belong to that Page or account, and stores signals. Replies are sent only when a person presses Send, and only inside the 24 hours after the
other person last wrote (Meta's rule).

SWITCHED OFF BY DEFAULT. Until Meta approves the app for public use only people with a role on the Meta app can sign in, so this is built
behind a flag: it needs META_CHANNELS_ENABLED=true plus META_APP_ID, META_APP_SECRET and META_WEBHOOK_VERIFY_TOKEN on the server, and
META_ALLOWED_ORGS (organization ids, comma separated) can limit it to approved test accounts. Remove that limit after approval.
Optional: META_GRAPH_VERSION (default v23.0) and META_LOGIN_CONFIG_ID (when the Meta app uses "Facebook Login for Business").

Nothing here has been run against the real Meta. It follows Meta's documented Graph API flows; Raptor B2B/docs/META_APP_SETUP.md has the
setup and what to check on the first real sign-in (permissions, webhook subscriptions, the Graph version)."""
from __future__ import annotations

import hashlib
import hmac
import json
import os
from datetime import datetime, timedelta, timezone
from typing import Optional
from urllib.parse import urlencode

import httpx

from .registry import Action, ConnectResult, Connector, ConnectorError, Context, Field, Signal, register

META_PROVIDERS = ("meta_page", "meta_leads", "meta_instagram")
# Everything Raptor asks Meta for. While the app is in development mode these work for people with a role on the app; for everyone else
# each needs Meta's app review (see docs/META_APP_SETUP.md for the use-case text of each).
SCOPES = [
    "pages_show_list", "pages_read_engagement", "pages_manage_metadata", "pages_messaging", "pages_manage_engagement", "pages_manage_ads",
    "leads_retrieval", "instagram_basic", "instagram_manage_messages", "instagram_manage_comments", "business_management",
]
OPTIONAL_SCOPES = {"business_management"}
SUBSCRIBED_FIELDS = "messages,messaging_postbacks,feed,leadgen"
MESSAGE_WINDOW = timedelta(hours=24)
DAILY_REPLY_CAP = 200
MAX_PAGES = 25

EXPIRED = "Facebook access has expired or was removed. Connect with Facebook again."
UNAVAILABLE_NOTE = "Facebook and Instagram connections are open to approved test accounts only, until Meta approves Raptor. Once approved, this opens for everyone."


# ───────────── settings from the server's environment ─────────────

def graph_base() -> str:
    return f"https://graph.facebook.com/{os.environ.get('META_GRAPH_VERSION', 'v23.0')}"


def public_api() -> str:
    return os.environ.get("PUBLIC_API_URL", "https://websites-api-5wmu.onrender.com").rstrip("/")


def redirect_uri() -> str:
    return f"{public_api()}/api/raptor/connections/oauth/meta/callback"


def enabled() -> bool:
    flag = os.environ.get("META_CHANNELS_ENABLED", "").strip().lower() in ("1", "true", "yes", "on")
    return flag and all(os.environ.get(k) for k in ("META_APP_ID", "META_APP_SECRET", "META_WEBHOOK_VERIFY_TOKEN"))


def allowed_orgs() -> set:
    return {o.strip() for o in os.environ.get("META_ALLOWED_ORGS", "").split(",") if o.strip()}


def _app() -> tuple:
    app_id, secret = os.environ.get("META_APP_ID"), os.environ.get("META_APP_SECRET")
    if not app_id or not secret:
        raise ConnectorError("Facebook and Instagram are not switched on for this Raptor server yet.")
    return app_id, secret


# ───────────── talking to the Graph API ─────────────

def _raise(resp) -> None:
    err = {}
    try:
        err = resp.json().get("error") or {}
    except Exception:
        pass
    code, sub = err.get("code"), err.get("error_subcode")
    if code == 190 or resp.status_code == 401:
        raise ConnectorError(EXPIRED)
    if sub == 2018278 or (code == 10 and "window" in str(err.get("message", "")).lower()):
        raise ConnectorError("Facebook only allows a reply within 24 hours of the person's last message, and that time has passed.")
    if code in (10, 299) or (isinstance(code, int) and 200 <= code < 300):
        raise ConnectorError("Facebook says Raptor is missing a permission. Connect with Facebook again and allow everything it asks for.")
    if code in (4, 17, 32, 613) or resp.status_code == 429:
        raise ConnectorError("Facebook's limit was reached. It resets by itself; try again in a few minutes.")
    raise ConnectorError("Facebook did not accept the request (%s)." % (str(err.get("message") or resp.status_code)[:140]))


def graph(method: str, path: str, token: Optional[str] = None, params: Optional[dict] = None, body: Optional[dict] = None):
    query = dict(params or {})
    if token:
        query["access_token"] = token
    url = f"{graph_base()}/{path.lstrip('/')}"
    try:
        if method == "GET":
            resp = httpx.get(url, params=query, timeout=20)
        else:
            resp = httpx.post(url, params=query, json=body, timeout=20)
    except httpx.HTTPError:
        raise ConnectorError("Could not reach Facebook right now. Try again in a minute.")
    if resp.status_code != 200:
        _raise(resp)
    return resp.json()


def _name_of(token: str, user_id: str, fields: str = "name") -> str:
    """The name of a person who messaged. Best effort: a failure just means the message shows without a name."""
    try:
        data = graph("GET", user_id, token, {"fields": fields})
        return str(data.get("name") or data.get("username") or "")
    except ConnectorError:
        return ""


def _creds(secret: Optional[str]) -> dict:
    try:
        return json.loads(secret or "{}") or {}
    except ValueError:
        return {}


def _when(value) -> Optional[datetime]:
    try:
        if isinstance(value, (int, float)):
            return datetime.fromtimestamp(float(value) / (1000 if value > 1e11 else 1), tz=timezone.utc)
        return datetime.fromisoformat(str(value).replace("Z", "+00:00").replace("+0000", "+00:00"))
    except (ValueError, TypeError, OverflowError, OSError):
        return None


# ───────────── sign-in ─────────────

def authorize_url(state: str) -> str:
    app_id, _ = _app()
    query = {"client_id": app_id, "redirect_uri": redirect_uri(), "state": state, "response_type": "code"}
    config_id = os.environ.get("META_LOGIN_CONFIG_ID")
    if config_id:
        # "Facebook Login for Business": the permissions are chosen in a configuration made in the Meta dashboard, not in the address.
        query.update({"config_id": config_id, "override_default_response_type": "true"})
    else:
        query["scope"] = ",".join(SCOPES)
    return f"https://www.facebook.com/{os.environ.get('META_GRAPH_VERSION', 'v23.0')}/dialog/oauth?" + urlencode(query)


def _long_lived_token(code: str) -> str:
    app_id, secret = _app()
    short = graph("GET", "oauth/access_token", None, {"client_id": app_id, "client_secret": secret, "redirect_uri": redirect_uri(), "code": code})
    if not short.get("access_token"):
        raise ConnectorError("Facebook did not give access. Connect with Facebook again.")
    long = graph("GET", "oauth/access_token", None, {"grant_type": "fb_exchange_token", "client_id": app_id, "client_secret": secret, "fb_exchange_token": short["access_token"]})
    return long.get("access_token") or short["access_token"]


def _list_pages(token: str) -> list:
    pages, params, path = [], {"fields": "id,name,access_token,instagram_business_account{id,username}", "limit": 100}, "me/accounts"
    for _ in range(5):
        data = graph("GET", path, token, params)
        pages += data.get("data") or []
        nxt = (data.get("paging") or {}).get("next")
        if not nxt or len(pages) >= MAX_PAGES:
            break
        try:
            resp = httpx.get(nxt, timeout=20)
        except httpx.HTTPError:
            break
        if resp.status_code != 200:
            break
        data, path, params = resp.json(), None, None
        pages += data.get("data") or []
        nxt = (data.get("paging") or {}).get("next")
        if not nxt:
            break
    return pages[:MAX_PAGES]


def subscribe_page(page_id: str, page_token: str) -> None:
    graph("POST", f"{page_id}/subscribed_apps", page_token, {"subscribed_fields": SUBSCRIBED_FIELDS})


# ───────────── the signature on what Meta sends ─────────────

def verify_signature(body: bytes, headers: dict) -> bool:
    """Meta signs every webhook with the app secret: X-Hub-Signature-256: sha256=<hex of HMAC-SHA256(body)>."""
    secret = os.environ.get("META_APP_SECRET")
    given = {str(k).lower(): v for k, v in (headers or {}).items()}.get("x-hub-signature-256", "")
    if not secret or not given.startswith("sha256="):
        return False
    return hmac.compare_digest(hmac.new(secret.encode(), body, hashlib.sha256).hexdigest(), given[7:])


def verify_challenge(mode: str, token: str, challenge: str) -> Optional[str]:
    """Meta checks the callback address once with a GET. Returns the challenge to echo back, or None to refuse."""
    expected = os.environ.get("META_WEBHOOK_VERIFY_TOKEN")
    if mode == "subscribe" and expected and hmac.compare_digest(str(token or ""), expected):
        return challenge
    return None


def _b64url(text: str) -> bytes:
    import base64
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def parse_signed_request(signed_request: str) -> dict:
    """The data-deletion and deauthorize callbacks carry `signed_request`: <signature>.<payload>, signed with the app secret."""
    secret = os.environ.get("META_APP_SECRET")
    try:
        sig_part, payload_part = (signed_request or "").split(".", 1)
        expected = hmac.new((secret or "").encode(), payload_part.encode(), hashlib.sha256).digest()
        if not secret or not hmac.compare_digest(expected, _b64url(sig_part)):
            raise ValueError
        data = json.loads(_b64url(payload_part))
    except (ValueError, TypeError, KeyError):
        raise ConnectorError("signature")
    if not isinstance(data, dict) or data.get("algorithm", "").upper() != "HMAC-SHA256":
        raise ConnectorError("signature")
    return data


# ───────────── what a lead looks like ─────────────

def lead_signal(lead: dict, page_id: str) -> Signal:
    answers = {}
    for item in lead.get("field_data") or []:
        values = item.get("values") or []
        if item.get("name") and values:
            answers[str(item["name"])[:60]] = str(values[0])[:300]
    first, last = answers.get("first_name", ""), answers.get("last_name", "")
    name = answers.get("full_name") or f"{first} {last}".strip()
    email = answers.get("email", "")
    phone = answers.get("phone_number") or answers.get("phone", "")
    summary = " · ".join(x for x in (name, email, phone) if x) or "New lead"
    return Signal("lead", "lead", text_value=summary[:300], occurred_at=_when(lead.get("created_time")),
                  entity={"lead_id": lead.get("id"), "name": name, "email": email, "phone": phone, "company": answers.get("company_name", ""),
                          "form_id": lead.get("form_id", ""), "ad_name": lead.get("ad_name", ""), "campaign_name": lead.get("campaign_name", ""),
                          "platform": lead.get("platform", ""), "answers": answers, "page_id": page_id},
                  dedupe_key=f"lead:{lead.get('id')}")


LEAD_FIELDS = "id,created_time,field_data,form_id,ad_name,campaign_name,platform"


# ───────────── the three connectors ─────────────

class _MetaBase(Connector):
    auth = "oauth"
    inbound = False            # Meta pushes to its own address (hooks.py /meta), not to a per-connection token address
    unavailable_note = UNAVAILABLE_NOTE
    server_env = ("META_APP_ID", "META_APP_SECRET", "META_WEBHOOK_VERIFY_TOKEN")
    min_sync_interval = 900

    def available(self) -> bool:
        return enabled()

    def allowed_for(self, org_id: str) -> bool:
        limit = allowed_orgs()
        return not limit or org_id in limit

    def redirect_uri(self) -> str:
        return redirect_uri()

    def authorize_url(self, state: str, redirect: str) -> str:
        return authorize_url(state)

    def complete(self, code: str, redirect: str) -> list:
        token = _long_lived_token(code)
        perms = graph("GET", "me/permissions", token).get("data") or []
        declined = [p["permission"] for p in perms if p.get("status") != "granted" and p.get("permission") in SCOPES and p["permission"] not in OPTIONAL_SCOPES]
        if declined:
            raise ConnectorError("Raptor needs these permissions to work: " + ", ".join(sorted(declined)) + ". Connect with Facebook again and allow them all.")
        me = graph("GET", "me", token, {"fields": "id,name"})
        pages = _list_pages(token)
        if not pages:
            raise ConnectorError("No Facebook Page was shared with Raptor. Connect again and choose the Pages to allow.")
        results = []
        for page in pages:
            if not page.get("id") or not page.get("access_token"):
                continue
            base = {"page_id": page["id"], "page_name": page.get("name", ""), "fb_user_id": me.get("id", "")}
            secret = json.dumps({"page_token": page["access_token"], "page_id": page["id"]})
            results.append(ConnectResult(page["id"], page.get("name") or "Facebook Page", dict(base), secret, provider="meta_page"))
            results.append(ConnectResult(page["id"], f"{page.get('name') or 'Facebook Page'} · Lead Ads", dict(base), secret, provider="meta_leads"))
            ig = page.get("instagram_business_account") or {}
            if ig.get("id"):
                results.append(ConnectResult(ig["id"], "@" + (ig.get("username") or ig["id"]), {**base, "ig_id": ig["id"], "ig_username": ig.get("username", "")}, secret, provider="meta_instagram"))
        if not results:
            raise ConnectorError("Facebook did not give access to any Page. Connect again and choose the Pages to allow.")
        return results

    def _token(self, secret: Optional[str]) -> str:
        token = _creds(secret).get("page_token")
        if not token:
            raise ConnectorError("This connection has no saved access. Connect with Facebook again.")
        return token

    # --- replying (shared) ---
    def _send(self, connection: dict, secret: Optional[str], params: dict, ctx: Context, inbound_name: str, sent_name: str) -> dict:
        recipient = str(params.get("recipient_id") or "").strip()
        text = (params.get("text") or "").strip()
        if not recipient or not text:
            raise ConnectorError("Choose who to reply to and write the message.")
        if len(text) > 1000:
            raise ConnectorError("A message can be up to 1000 characters.")
        now = datetime.now(timezone.utc)
        last = None
        for row in ctx.recent(inbound_name, 300):
            if str((row.get("entity") or {}).get("sender_id")) == recipient:
                when = _when(row.get("occurred_at"))
                if when and (last is None or when > last):
                    last = when
        if last is None or now - last > MESSAGE_WINDOW:
            raise ConnectorError("You can only reply within 24 hours of the person's last message, and Raptor has no message from them in that time.")
        if ctx.count_today(sent_name) >= DAILY_REPLY_CAP:
            raise ConnectorError("Daily reply limit reached. Try again tomorrow.")
        page_id = (connection.get("config") or {}).get("page_id")
        out = graph("POST", f"{page_id}/messages", self._token(secret), None, {"recipient": {"id": recipient}, "messaging_type": "RESPONSE", "message": {"text": text}})
        ctx.record(Signal("event", sent_name, text_value=text[:300], entity={"recipient_id": recipient, "message_id": out.get("message_id", "")}, dedupe_key=f"{sent_name}:{out.get('message_id') or now.isoformat()}"))
        return {"ok": True, "message_id": out.get("message_id", "")}


class MetaPage(_MetaBase):
    provider = "meta_page"
    channel = "facebook"
    title = "Facebook Page"
    description = "Your Page's followers and posts, and the messages and comments people send you on Facebook."
    category = "channel"
    can_reply = True
    fields = []
    help = [
        "Press “Connect with Facebook” and sign in with the Facebook account that manages your Page.",
        "In Facebook's own window choose the Pages to share, and allow everything Raptor asks for. It needs these to read messages and comments and to receive leads.",
        "Raptor then connects the Page, its Lead Ads, and the Instagram account linked to it, all at once.",
        "Replies are sent only when you press Send, and only within 24 hours of the person's last message (Facebook's rule).",
    ]
    actions = [Action("send_message", "Reply to a Messenger message", "Sends a reply to a person who messaged your Page in the last 24 hours.",
                      [Field("recipient_id", "Recipient", "", ""), Field("text", "Message", "", "", multiline=True)]),
               Action("reply_comment", "Reply to a comment", "Replies to a comment on one of your Page's posts.",
                      [Field("comment_id", "Comment", "", ""), Field("text", "Reply", "", "", multiline=True)])]

    def post_connect(self, connection: dict, secret: Optional[str]) -> None:
        """Asks Meta to send this Page's messages, comments and leads to Raptor. Done once per Page (here), which also covers its Lead Ads
        and Instagram connections."""
        c = _creds(secret)
        subscribe_page(c.get("page_id") or connection["config"].get("page_id"), c.get("page_token", ""))

    def sync(self, connection: dict, secret: Optional[str]) -> list:
        token, page_id = self._token(secret), connection["external_id"]
        now = datetime.now(timezone.utc)
        day = now.strftime("%Y-%m-%d")
        info = graph("GET", page_id, token, {"fields": "name,followers_count,fan_count"})
        out = []
        for name, key in (("page_followers", "followers_count"), ("page_likes", "fan_count")):
            if isinstance(info.get(key), (int, float)):
                out.append(Signal("metric", name, float(info[key]), entity={"page_id": page_id}, occurred_at=now, dedupe_key=f"{name}:{day}"))
        posts = graph("GET", f"{page_id}/posts", token, {"fields": "id,message,created_time,permalink_url,shares,reactions.summary(total_count).limit(0),comments.summary(total_count).limit(0)", "limit": 10})
        for post in posts.get("data") or []:
            entity = {"post_id": post.get("id"), "title": (post.get("message") or "")[:90], "url": post.get("permalink_url", "")}
            pairs = (("post_reactions", ((post.get("reactions") or {}).get("summary") or {}).get("total_count")),
                     ("post_comments", ((post.get("comments") or {}).get("summary") or {}).get("total_count")),
                     ("post_shares", (post.get("shares") or {}).get("count", 0)))
            for name, value in pairs:
                if isinstance(value, (int, float)):
                    out.append(Signal("metric", name, float(value), entity=entity, occurred_at=now, dedupe_key=f"{name}:{post.get('id')}:{day}"))
        return out

    def ingest_meta(self, connection: dict, secret: Optional[str], obj: str, entry: dict) -> tuple:
        if obj != "page":
            return [], {}
        page_id, signals, token = connection["external_id"], [], _creds(secret).get("page_token", "")
        for event in entry.get("messaging") or []:
            message = event.get("message") or {}
            sender = (event.get("sender") or {}).get("id")
            if not message.get("mid") or message.get("is_echo") or not sender or str(sender) == str(page_id):
                continue
            text = (message.get("text") or "").strip() or ("[attachment]" if message.get("attachments") else "")
            if not text:
                continue
            signals.append(Signal("mention", "facebook_message", text_value=text[:1500], occurred_at=_when(event.get("timestamp")),
                                  entity={"sender_id": str(sender), "from": _name_of(token, str(sender)) or f"Messenger user …{str(sender)[-4:]}", "mid": message["mid"]},
                                  dedupe_key=f"fbm:{message['mid']}"))
        for change in entry.get("changes") or []:
            v = change.get("value") or {}
            if change.get("field") != "feed" or v.get("item") != "comment" or v.get("verb") != "add":
                continue
            author = v.get("from") or {}
            if not v.get("comment_id") or str(author.get("id")) == str(page_id) or not (v.get("message") or "").strip():
                continue
            signals.append(Signal("mention", "facebook_comment", text_value=v["message"][:1500], occurred_at=_when(v.get("created_time")),
                                  entity={"comment_id": v["comment_id"], "post_id": v.get("post_id", ""), "author": author.get("name") or "Someone", "author_id": str(author.get("id", ""))},
                                  dedupe_key=f"fbc:{v['comment_id']}"))
        return signals, {}

    def action(self, connection: dict, secret: Optional[str], name: str, params: dict, ctx: Context) -> dict:
        if name == "send_message":
            return self._send(connection, secret, params, ctx, "facebook_message", "facebook_reply_sent")
        if name == "reply_comment":
            comment_id, text = str(params.get("comment_id") or "").strip(), (params.get("text") or "").strip()
            if not comment_id or not text:
                raise ConnectorError("Choose the comment and write the reply.")
            if ctx.count_today("facebook_reply_sent") >= DAILY_REPLY_CAP:
                raise ConnectorError("Daily reply limit reached. Try again tomorrow.")
            out = graph("POST", f"{comment_id}/comments", self._token(secret), None, {"message": text[:8000]})
            ctx.record(Signal("event", "facebook_reply_sent", text_value=text[:300], entity={"comment_id": comment_id}, dedupe_key=f"fbr:{out.get('id') or comment_id + text[:20]}"))
            return {"ok": True, "id": out.get("id", "")}
        raise ConnectorError("This connection does not do that.")


class MetaLeads(_MetaBase):
    provider = "meta_leads"
    channel = "leads"
    title = "Lead Ads"
    description = "Every person who fills in one of your Facebook or Instagram lead forms arrives in Raptor within seconds."
    category = "channel"
    fields = []
    help = [
        "Connect with Facebook once (on this tab, the Facebook tab or the Instagram tab). Lead Ads are connected for every Page you share.",
        "Your lead forms must belong to a Page you shared, and the person who connects needs to be able to manage ads for that Page.",
        "New leads arrive here the moment they submit the form, and you can add each one to your CRM with one press.",
        "Raptor also reads the leads already waiting in your forms, up to 100 of the newest.",
    ]

    def sync(self, connection: dict, secret: Optional[str]) -> list:
        token, page_id = self._token(secret), connection["external_id"]
        forms = graph("GET", f"{page_id}/leadgen_forms", token, {"fields": "id,name", "limit": 20}).get("data") or []
        out = []
        for form in forms:
            if len(out) >= 100:
                break
            leads = graph("GET", f"{form['id']}/leads", token, {"fields": LEAD_FIELDS, "limit": 25}).get("data") or []
            for lead in leads:
                lead.setdefault("form_id", form["id"])
                out.append(lead_signal(lead, page_id))
        return out[:100]

    def ingest_meta(self, connection: dict, secret: Optional[str], obj: str, entry: dict) -> tuple:
        if obj != "page":
            return [], {}
        token, signals = self._token(secret), []
        for change in entry.get("changes") or []:
            v = change.get("value") or {}
            if change.get("field") != "leadgen" or not v.get("leadgen_id"):
                continue
            lead = graph("GET", str(v["leadgen_id"]), token, {"fields": LEAD_FIELDS})      # a failure here is raised so Meta delivers it again
            lead.setdefault("form_id", v.get("form_id", ""))
            signals.append(lead_signal(lead, connection["external_id"]))
        return signals, {}


class MetaInstagram(_MetaBase):
    provider = "meta_instagram"
    channel = "instagram"
    title = "Instagram"
    description = "Your Instagram followers and posts, and the direct messages and comments people send you."
    category = "channel"
    can_reply = True
    fields = []
    help = [
        "Your Instagram account must be a Professional (Business or Creator) account linked to a Facebook Page.",
        "Press “Connect with Facebook” and share that Page. Raptor finds the linked Instagram account by itself.",
        "In Instagram's settings, allow access to messages for connected tools (Settings, Messages and story replies, Connected tools).",
        "Replies are sent only when you press Send, and only within 24 hours of the person's last message (Instagram's rule).",
    ]
    actions = [Action("send_message", "Reply to a direct message", "Sends a reply to a person who messaged you in the last 24 hours.",
                      [Field("recipient_id", "Recipient", "", ""), Field("text", "Message", "", "", multiline=True)]),
               Action("reply_comment", "Reply to a comment", "Replies to a comment on one of your posts.",
                      [Field("comment_id", "Comment", "", ""), Field("text", "Reply", "", "", multiline=True)])]

    def sync(self, connection: dict, secret: Optional[str]) -> list:
        token, ig_id = self._token(secret), connection["external_id"]
        now = datetime.now(timezone.utc)
        day = now.strftime("%Y-%m-%d")
        info = graph("GET", ig_id, token, {"fields": "username,followers_count,follows_count,media_count"})
        out = []
        for name, key in (("ig_followers", "followers_count"), ("ig_following", "follows_count"), ("ig_posts", "media_count")):
            if isinstance(info.get(key), (int, float)):
                out.append(Signal("metric", name, float(info[key]), entity={"ig_id": ig_id}, occurred_at=now, dedupe_key=f"{name}:{day}"))
        media = graph("GET", f"{ig_id}/media", token, {"fields": "id,caption,like_count,comments_count,timestamp,permalink,media_type", "limit": 10})
        for item in media.get("data") or []:
            entity = {"media_id": item.get("id"), "title": (item.get("caption") or "")[:90], "url": item.get("permalink", ""), "type": item.get("media_type", "")}
            for name, key in (("ig_post_likes", "like_count"), ("ig_post_comments", "comments_count")):
                if isinstance(item.get(key), (int, float)):
                    out.append(Signal("metric", name, float(item[key]), entity=entity, occurred_at=now, dedupe_key=f"{name}:{item.get('id')}:{day}"))
        return out

    def ingest_meta(self, connection: dict, secret: Optional[str], obj: str, entry: dict) -> tuple:
        if obj != "instagram":
            return [], {}
        ig_id, token, signals = connection["external_id"], _creds(secret).get("page_token", ""), []
        for event in entry.get("messaging") or []:
            message = event.get("message") or {}
            sender = (event.get("sender") or {}).get("id")
            if not message.get("mid") or message.get("is_echo") or not sender or str(sender) == str(ig_id):
                continue
            text = (message.get("text") or "").strip() or ("[attachment]" if message.get("attachments") else "")
            if not text:
                continue
            signals.append(Signal("mention", "instagram_message", text_value=text[:1500], occurred_at=_when(event.get("timestamp")),
                                  entity={"sender_id": str(sender), "from": _name_of(token, str(sender), "name,username") or f"Instagram user …{str(sender)[-4:]}", "mid": message["mid"]},
                                  dedupe_key=f"igm:{message['mid']}"))
        for change in entry.get("changes") or []:
            v = change.get("value") or {}
            if change.get("field") != "comments" or not v.get("id") or not (v.get("text") or "").strip():
                continue
            author = v.get("from") or {}
            if str(author.get("id")) == str(ig_id):
                continue
            signals.append(Signal("mention", "instagram_comment", text_value=v["text"][:1500], occurred_at=datetime.now(timezone.utc),
                                  entity={"comment_id": v["id"], "media_id": (v.get("media") or {}).get("id", ""), "author": author.get("username") or "Someone", "author_id": str(author.get("id", ""))},
                                  dedupe_key=f"igc:{v['id']}"))
        return signals, {}

    def action(self, connection: dict, secret: Optional[str], name: str, params: dict, ctx: Context) -> dict:
        if name == "send_message":
            return self._send(connection, secret, params, ctx, "instagram_message", "instagram_reply_sent")
        if name == "reply_comment":
            comment_id, text = str(params.get("comment_id") or "").strip(), (params.get("text") or "").strip()
            if not comment_id or not text:
                raise ConnectorError("Choose the comment and write the reply.")
            if ctx.count_today("instagram_reply_sent") >= DAILY_REPLY_CAP:
                raise ConnectorError("Daily reply limit reached. Try again tomorrow.")
            out = graph("POST", f"{comment_id}/replies", self._token(secret), None, {"message": text[:2200]})
            ctx.record(Signal("event", "instagram_reply_sent", text_value=text[:300], entity={"comment_id": comment_id}, dedupe_key=f"igr:{out.get('id') or comment_id + text[:20]}"))
            return {"ok": True, "id": out.get("id", "")}
        raise ConnectorError("This connection does not do that.")


register(MetaPage())
register(MetaLeads())
register(MetaInstagram())
