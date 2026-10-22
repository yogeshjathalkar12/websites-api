"""raptor/audit/router.py: the Company Audit API, mounted at /api/raptor/audit.

  GET  /presets        the kinds of company the report can lead with
  POST /start          {company, website, city?, preset?, keywords?, competitors?, note?}  ->  {job_id}      (signed-in Raptor user)
  GET  /{job_id}       progress, the sections finished so far, and the finished report                       (only the person who started it)

Signed in with the same Supabase sign-in as every other Raptor tool; each person is limited per day and to one audit running at a time
(engine.py), so the shared servers and the search quota cannot be drained.
"""
from __future__ import annotations

from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from ..utility.raptor_auth import get_current_user
from . import engine
from .common import normalize_site

router = APIRouter()


class AuditRequest(BaseModel):
    company: str
    website: str
    city: Optional[str] = None
    preset: Optional[str] = None
    keywords: List[str] = []
    competitors: List[str] = []
    note: Optional[str] = None


def _clean(text: Optional[str], limit: int) -> str:
    return " ".join((text or "").split())[:limit]


@router.get("/presets")
def presets():
    return [{"id": k, "title": v[0]} for k, v in engine.PRESETS.items()]


@router.post("/start")
def start(req: AuditRequest, user_id: str = Depends(get_current_user)):
    company = _clean(req.company, 120)
    if not company:
        raise HTTPException(status_code=400, detail="Enter the company's name.")
    site = normalize_site(req.website)
    if not site:
        raise HTTPException(status_code=400, detail="That does not look like a website address. Use something like acme.com.")
    competitors = []
    for raw in (req.competitors or [])[:3]:
        if (raw or "").strip():
            other = normalize_site(raw)
            if not other:
                raise HTTPException(status_code=400, detail="'%s' does not look like a website address." % _clean(raw, 60))
            if other["registrable"] != site["registrable"] and other["host"] not in [c["host"] for c in competitors]:
                competitors.append(other)
    keywords = []
    for raw in (req.keywords or [])[:5]:
        k = _clean(raw, 80)
        if k and k.lower() not in [x.lower() for x in keywords]:
            keywords.append(k)
    inputs = {"company": company, "site": site, "city": _clean(req.city, 80) or None, "preset": req.preset if req.preset in engine.PRESETS else "general",
              "keywords": keywords, "competitors": competitors, "note": _clean(req.note, 300) or None}
    try:
        job_id = engine.start(user_id, inputs)
    except engine.Refused as e:
        raise HTTPException(status_code=e.status, detail=e.message)
    return {"job_id": job_id}


@router.get("/{job_id}")
def status(job_id: str, user_id: str = Depends(get_current_user)):
    job = engine.get(user_id, job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="That audit was not found. It may have expired: run it again.")
    return job
