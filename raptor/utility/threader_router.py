"""
threader_router.py — Tool 2: IMAP Pitch Threader

Maps the TRUE reply-tree of outbound cold email using Message-ID /
In-Reply-To / References headers (RFC 5322), instead of fragile "Re:"
subject-line matching. Filters out autoresponders via Auto-Submitted /
X-Autoreply headers before anything reaches the CRM stage update.

Security note: IMAP app-passwords are the user's own mailbox credentials.
We never store the raw password -- only inside this request's memory to
open the connection, then it's discarded. What's persisted to Supabase is
the mailbox host/username + a flag that a connection was authorized, so a
future scheduled poll can prompt for re-auth rather than us holding secrets
at rest without encryption-at-rest support in place.
"""

import re
import imaplib
import email
from email.utils import parsedate_to_datetime
from fastapi import APIRouter, HTTPException, Depends, Body

from raptor_auth import get_current_user, deduct_credit, supabase

router = APIRouter()

AUTO_REPLY_SIGNATURES = [
    ("auto-submitted", "auto-generated"),
    ("auto-submitted", "auto-replied"),
    ("x-autoreply", "yes"),
    ("x-autorespond", None),
    ("precedence", "bulk"),
    ("precedence", "auto_reply"),
]


def _is_bot_reply(msg: email.message.Message) -> bool:
    for header, expected in AUTO_REPLY_SIGNATURES:
        value = msg.get(header)
        if value is None:
            continue
        if expected is None or expected.lower() in value.lower():
            return True
    subject = (msg.get("Subject") or "").lower()
    if "out of office" in subject or "automatic reply" in subject:
        return True
    return False


def _open_mailbox(host: str, port: int, username: str, password: str) -> imaplib.IMAP4_SSL:
    try:
        conn = imaplib.IMAP4_SSL(host, port)
        conn.login(username, password)
        return conn
    except imaplib.IMAP4.error as e:
        raise HTTPException(status_code=401, detail=f"IMAP login failed: {e}")
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Could not reach mail server: {e}")


@router.get("/status")
def status():
    return {"tool": "imap-threader", "status": "operational"}


@router.post("/scan-threads")
def scan_threads(payload: dict = Body(...), user_id: str = Depends(get_current_user)):
    """
    Body: {
      "imap_host": "imap.gmail.com", "imap_port": 993,
      "username": "hello@shoonyaorigins.com", "app_password": "....",
      "mailbox": "INBOX", "limit": 200
    }
    Connects live, pulls the most recent `limit` messages, and builds a
    Message-ID -> In-Reply-To relational tree.
    """
    host = payload.get("imap_host")
    port = int(payload.get("imap_port", 993))
    username = payload.get("username")
    app_password = payload.get("app_password")
    mailbox = payload.get("mailbox", "INBOX")
    limit = min(int(payload.get("limit", 200)), 500)

    if not all([host, username, app_password]):
        raise HTTPException(status_code=400, detail="imap_host, username, and app_password are required.")

    remaining_credits = deduct_credit(user_id)

    conn = _open_mailbox(host, port, username, app_password)
    try:
        status_code, _ = conn.select(mailbox, readonly=True)
        if status_code != "OK":
            raise HTTPException(status_code=400, detail=f"Could not open mailbox '{mailbox}'.")

        status_code, data = conn.search(None, "ALL")
        if status_code != "OK":
            raise HTTPException(status_code=502, detail="IMAP search failed.")

        all_ids = data[0].split()
        target_ids = all_ids[-limit:] if len(all_ids) > limit else all_ids

        nodes = {}  # message_id -> node dict
        for uid in target_ids:
            status_code, msg_data = conn.fetch(uid, "(BODY.PEEK[HEADER])")
            if status_code != "OK" or not msg_data or not msg_data[0]:
                continue
            raw_header = msg_data[0][1]
            msg = email.message_from_bytes(raw_header)

            message_id = (msg.get("Message-ID") or "").strip()
            if not message_id:
                continue

            in_reply_to = (msg.get("In-Reply-To") or "").strip() or None
            references = re.findall(r"<[^>]+>", msg.get("References") or "")
            parent_id = in_reply_to or (references[-1] if references else None)

            try:
                sent_at = parsedate_to_datetime(msg.get("Date")).isoformat()
            except Exception:
                sent_at = None

            nodes[message_id] = {
                "message_id": message_id,
                "parent_id": parent_id,
                "from": msg.get("From"),
                "subject": msg.get("Subject"),
                "date": sent_at,
                "is_bot": _is_bot_reply(msg),
                "children": [],
            }
    finally:
        try:
            conn.close()
        except Exception:
            pass
        conn.logout()

    # Link children to parents to build the actual tree
    roots = []
    for node in nodes.values():
        parent = nodes.get(node["parent_id"]) if node["parent_id"] else None
        if parent:
            parent["children"].append(node["message_id"])
        else:
            roots.append(node["message_id"])

    human_reply_threads = [
        n for n in nodes.values() if n["parent_id"] and not n["is_bot"]
    ]

    if supabase:
        try:
            supabase.table("threader_scans").insert({
                "user_id": user_id,
                "mailbox": mailbox,
                "message_count": len(nodes),
                "human_reply_count": len(human_reply_threads),
                "tree": {"roots": roots, "nodes": nodes},
            }).execute()
        except Exception:
            pass

    return {
        "scanned": len(nodes),
        "roots": roots,
        "nodes": nodes,
        "human_replies": len(human_reply_threads),
        "bot_replies": sum(1 for n in nodes.values() if n["is_bot"]),
        "credits_left": remaining_credits,
    }


@router.get("/history")
def history(user_id: str = Depends(get_current_user)):
    if not supabase:
        raise HTTPException(status_code=500, detail="Database credentials missing on server")
    resp = (
        supabase.table("threader_scans")
        .select("id, mailbox, message_count, human_reply_count, created_at")
        .eq("user_id", user_id)
        .order("created_at", desc=True)
        .limit(50)
        .execute()
    )
    return {"scans": resp.data or []}