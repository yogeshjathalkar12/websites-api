"""
insights_router.py — Tool 11: Campaign Optimization Engine

Turns the data other tools already generate into specific, defensible
recommendations. "Defensible" is the operative word: every finding below
requires a minimum sample size before it's stated as a finding at all,
and every number returned traces back to an actual join, not a guess.

What this can and can't currently say:
  - Variant-level reply rates: REAL, as of the message_id linkage added
    to mailer_router.py + threader_router.py's reply-attribution step.
    Before that linkage existed, this number was not measurable — see
    schema_insights_addition.sql's note.
  - Best send-hour: REAL, computed from outreach_queue.sent_at cross-
    referenced with email_events (only counts sends that later got a
    logged reply).
  - Deal/pipeline velocity: SPECULATIVE until you confirm your actual
    deals/CRM table's real column names — see _get_deal_insights below,
    which fails soft (returns nothing) rather than guessing at a schema
    this file was never shown.
"""

from collections import defaultdict
from datetime import datetime, timedelta, timezone
from fastapi import APIRouter, Depends, HTTPException

from raptor_auth import get_current_user, supabase

router = APIRouter()

# Below this many sends, a variant's reply rate is noise, not a finding —
# a 1/3 "33%" is not information. This threshold is a judgment call, not
# a statistical guarantee; treat recommendations as directional even
# above it, and widen it if data volume grows and false positives creep in.
MIN_SENDS_FOR_VARIANT_VERDICT = 20
MIN_SENDS_FOR_HOUR_VERDICT = 15
STALLED_DEAL_DAYS = 14


@router.get("/status")
def status():
    return {"tool": "insights-engine", "status": "operational"}


def _variant_performance(user_id: str) -> list:
    """
    Joins outreach_queue (what was sent, and when) against email_events
    (what got a reply) to compute a real reply rate per campaign. Groups
    by campaign_id rather than raw variant_hash, since a single-recipient
    variant_hash has n=1 by construction and is never statistically
    meaningful on its own.
    """
    sent_resp = (
        supabase.table("outreach_queue")
        .select("id, campaign_id, sent")
        .eq("user_id", user_id)
        .eq("sent", True)
        .execute()
    )
    sent_rows = sent_resp.data or []
    if not sent_rows:
        return []

    events_resp = (
        supabase.table("email_events")
        .select("outreach_queue_id")
        .eq("user_id", user_id)
        .eq("event_type", "replied")
        .execute()
    )
    replied_ids = {e["outreach_queue_id"] for e in (events_resp.data or [])}

    by_campaign = defaultdict(lambda: {"sent": 0, "replied": 0})
    for row in sent_rows:
        cid = row.get("campaign_id") or "(uncategorized)"
        by_campaign[cid]["sent"] += 1
        if row["id"] in replied_ids:
            by_campaign[cid]["replied"] += 1

    results = []
    for cid, counts in by_campaign.items():
        results.append({
            "campaign_id": cid,
            "sent": counts["sent"],
            "replied": counts["replied"],
            "reply_rate_pct": round(100 * counts["replied"] / counts["sent"], 1),
            "statistically_meaningful": counts["sent"] >= MIN_SENDS_FOR_VARIANT_VERDICT,
        })
    results.sort(key=lambda r: r["reply_rate_pct"], reverse=True)
    return results


def _timing_performance(user_id: str) -> list:
    """
    Buckets sent_at by hour-of-day (UTC) and computes reply rate per
    bucket. Same sample-size gating as variant performance — an hour
    with 3 sends and 1 reply is not "33% better," it's 3 data points.
    """
    sent_resp = (
        supabase.table("outreach_queue")
        .select("id, sent_at")
        .eq("user_id", user_id)
        .eq("sent", True)
        .not_.is_("sent_at", "null")
        .execute()
    )
    sent_rows = sent_resp.data or []
    if not sent_rows:
        return []

    events_resp = (
        supabase.table("email_events")
        .select("outreach_queue_id")
        .eq("user_id", user_id)
        .eq("event_type", "replied")
        .execute()
    )
    replied_ids = {e["outreach_queue_id"] for e in (events_resp.data or [])}

    by_hour = defaultdict(lambda: {"sent": 0, "replied": 0})
    for row in sent_rows:
        try:
            hour = datetime.fromisoformat(row["sent_at"].replace("Z", "+00:00")).hour
        except Exception:
            continue
        by_hour[hour]["sent"] += 1
        if row["id"] in replied_ids:
            by_hour[hour]["replied"] += 1

    results = []
    for hour, counts in sorted(by_hour.items()):
        results.append({
            "hour_utc": hour,
            "sent": counts["sent"],
            "replied": counts["replied"],
            "reply_rate_pct": round(100 * counts["replied"] / counts["sent"], 1) if counts["sent"] else 0,
            "statistically_meaningful": counts["sent"] >= MIN_SENDS_FOR_HOUR_VERDICT,
        })
    return results


def _deliverability_health(user_id: str) -> dict:
    """Bounce rate — always meaningful even at low volume, since a single
    hard bounce is a real, individually-verified signal (not a correlation)."""
    sent_resp = (
        supabase.table("outreach_queue")
        .select("id", count="exact")
        .eq("user_id", user_id)
        .eq("sent", True)
        .execute()
    )
    total_sent = sent_resp.count or 0

    bounced_resp = (
        supabase.table("email_events")
        .select("id", count="exact")
        .eq("user_id", user_id)
        .eq("event_type", "bounced")
        .execute()
    )
    total_bounced = bounced_resp.count or 0

    return {
        "total_sent": total_sent,
        "total_bounced": total_bounced,
        "bounce_rate_pct": round(100 * total_bounced / total_sent, 1) if total_sent else 0,
    }


def _get_deal_insights(user_id: str) -> list:
    """
    Best-effort only. This backend has never been shown your actual
    deals/CRM table schema (schema.sql explicitly says raptor_users and
    the core CRM tables live in the original deployment, not here) —
    automations_router.py's docstrings reference stage names like
    'contact_no_reply' and 'deal_stalled', which implies a deals table
    exists, but not its exact columns. Rather than guess at column names
    and risk a confidently-wrong recommendation, this fails soft: if the
    query errors (wrong table/column name), it returns an empty list and
    the /recommendations response says so explicitly instead of hiding it.

    TO ACTIVATE: replace the select() below with your real deals table's
    actual column names once you confirm them.
    """
    try:
        cutoff = (datetime.now(timezone.utc) - timedelta(days=STALLED_DEAL_DAYS)).isoformat()
        resp = (
            supabase.table("deals")
            .select("id, title, stage, value, updated_at")
            .eq("owner_id", user_id)
            .in_("stage", ["lead", "meeting", "negotiation"])
            .lt("updated_at", cutoff)
            .execute()
        )
        return resp.data or []
    except Exception:
        return None  # None = "couldn't check", distinct from [] = "checked, found nothing"


@router.get("/recommendations")
def get_recommendations(user_id: str = Depends(get_current_user)):
    if not supabase:
        raise HTTPException(status_code=500, detail="Database credentials missing on server")

    variant_perf = _variant_performance(user_id)
    timing_perf = _timing_performance(user_id)
    deliverability = _deliverability_health(user_id)
    stalled_deals = _get_deal_insights(user_id)

    recommendations = []

    # --- Variant/campaign performance ---
    meaningful_variants = [v for v in variant_perf if v["statistically_meaningful"]]
    if len(meaningful_variants) >= 2:
        best = meaningful_variants[0]
        worst = meaningful_variants[-1]
        if best["reply_rate_pct"] - worst["reply_rate_pct"] >= 5:
            recommendations.append({
                "type": "campaign_performance",
                "severity": "medium",
                "title": f"Campaign '{best['campaign_id']}' outperforms '{worst['campaign_id']}'",
                "detail": f"{best['reply_rate_pct']}% reply rate ({best['replied']}/{best['sent']}) "
                          f"vs {worst['reply_rate_pct']}% ({worst['replied']}/{worst['sent']}).",
                "action": f"Consider pausing or revising '{worst['campaign_id']}' and reallocating volume to '{best['campaign_id']}'.",
            })
    elif variant_perf and not meaningful_variants:
        recommendations.append({
            "type": "insufficient_data",
            "severity": "info",
            "title": "Not enough sends yet for a reliable campaign comparison",
            "detail": f"Every campaign is under the {MIN_SENDS_FOR_VARIANT_VERDICT}-send threshold this engine "
                      f"requires before calling a difference real rather than noise.",
            "action": "Keep sending — recommendations will appear once a campaign crosses the threshold.",
        })

    # --- Timing ---
    meaningful_hours = [h for h in timing_perf if h["statistically_meaningful"]]
    if meaningful_hours:
        best_hour = max(meaningful_hours, key=lambda h: h["reply_rate_pct"])
        recommendations.append({
            "type": "timing_optimization",
            "severity": "low",
            "title": f"{best_hour['hour_utc']:02d}:00 UTC shows the strongest reply rate so far",
            "detail": f"{best_hour['reply_rate_pct']}% ({best_hour['replied']}/{best_hour['sent']} sends).",
            "action": "Weight new Chronos-scheduled sends toward this window where the recipient's local time allows it.",
        })

    # --- Deliverability ---
    if deliverability["total_sent"] >= 20 and deliverability["bounce_rate_pct"] >= 5:
        recommendations.append({
            "type": "deliverability_warning",
            "severity": "high",
            "title": f"Bounce rate is {deliverability['bounce_rate_pct']}%",
            "detail": f"{deliverability['total_bounced']} of {deliverability['total_sent']} sends bounced.",
            "action": "A rate this high risks your sender reputation — verify list quality before the next send, "
                       "e.g. with raptor_router.py's /verify-email.",
        })

    # --- Deals ---
    if stalled_deals is None:
        recommendations.append({
            "type": "deal_check_unavailable",
            "severity": "info",
            "title": "Deal-stage analysis is not wired up",
            "detail": "This engine expects a 'deals' table with owner_id/stage/updated_at columns and couldn't "
                      "find one matching that shape.",
            "action": "Confirm your CRM/deals table's real column names and update _get_deal_insights() in insights_router.py.",
        })
    elif stalled_deals:
        total_value = sum(d.get("value") or 0 for d in stalled_deals)
        recommendations.append({
            "type": "deal_warning",
            "severity": "high",
            "title": f"{len(stalled_deals)} deal(s) stalled {STALLED_DEAL_DAYS}+ days",
            "detail": f"Combined value: {total_value:,.0f}.",
            "action": "Trigger a follow-up automation or move these to a Cold stage before they decay further.",
        })

    return {
        "campaign_performance": variant_perf,
        "timing_performance": timing_perf,
        "deliverability": deliverability,
        "recommendations": recommendations,
    }