"""
router.py — AI Playground: roleplay a real CRM lead, or general sales
coaching, both as a multi-turn chat.

Deliberately reuses raptor.ai_integration's key_vault and providers rather
than building a third key-management system — this is BYOK text chat, the
exact same capability the Content Suite already validates and stores keys
for. A user who's already added an OpenAI/Anthropic/Google key there can
use it here immediately, no re-entry, no new secret.

SIMPLIFICATION worth knowing: call_text() (from ai_integration.providers)
is single-turn — one prompt in, one completion out, no native multi-turn
chat state. So "conversation" here means the whole system prompt + prior
turns gets reconstructed as one text block and resent on every message.
That's real token cost that grows with conversation length, and it's not
how a production chat feature should ultimately work — a native
chat-completions call per provider (each already supports multi-message
arrays) would be the natural next step if this proves useful. Good enough
for a v1; not a place to over-build before anyone's used it once.
"""
from fastapi import APIRouter, HTTPException, Depends, Body

from raptor.utility.raptor_auth import get_current_user, supabase
from raptor.ai_integration import key_vault
from raptor.ai_integration.providers import call_text, ProviderError, PROVIDER_CAPABILITIES

router = APIRouter()

MAX_HISTORY_MESSAGES = 20  # bounds prompt growth — long sessions truncate to the most recent turns


def _build_roleplay_prompt(deal: dict, extra_context: str) -> str:
    contact_name = (deal.get('contacts') or {}).get('name') or 'the prospect'
    company_name = (deal.get('companies') or {}).get('name') or 'their company'
    prompt = (
        f"You are {contact_name}, a prospect at {company_name}. "
        f"You are currently in the '{deal.get('stage', 'lead')}' stage of a sales conversation "
        f"about a potential deal worth ${deal.get('value', 0)}. "
        f"Stay in character as this prospect throughout the conversation — realistic objections, "
        f"realistic tone for someone in this position, don't break character to give sales advice "
        f"or acknowledge you're an AI."
    )
    if extra_context:
        prompt += f" Additional context on this prospect: {extra_context}"
    return prompt


def _build_coaching_prompt(topic: str) -> str:
    base = "You are an experienced, encouraging sales coach helping someone practice and improve their skills through conversation."
    if topic:
        base += f" Focus this session specifically on: {topic}."
    return base


@router.get("/status")
def status():
    return {"tool": "ai-playground", "status": "operational"}


@router.post("/sessions")
def create_session(payload: dict = Body(...), user_id: str = Depends(get_current_user)):
    """
    Body: {
      "mode": "lead_roleplay" | "coaching",
      "provider": "openai" | "google" | "anthropic",
      "deal_id": "..." (required for lead_roleplay),
      "extra_context": "..." (optional, lead_roleplay),
      "topic": "..." (optional, coaching)
    }
    """
    mode = payload.get('mode')
    provider = payload.get('provider')
    if mode not in ('lead_roleplay', 'coaching'):
        raise HTTPException(status_code=400, detail="mode must be 'lead_roleplay' or 'coaching'.")
    if provider not in PROVIDER_CAPABILITIES:
        raise HTTPException(status_code=400, detail=f"Unsupported provider '{provider}'.")
    if not PROVIDER_CAPABILITIES[provider]['text']:
        raise HTTPException(status_code=400, detail=f"'{provider}' does not support text generation.")

    deal_id = None
    if mode == 'lead_roleplay':
        deal_id = payload.get('deal_id')
        if not deal_id:
            raise HTTPException(status_code=400, detail="deal_id is required for lead_roleplay mode.")
        deal = supabase.table('deals').select('*, companies(name), contacts(name)').eq('id', deal_id).single().execute().data
        if not deal:
            raise HTTPException(status_code=404, detail="Deal not found.")
        system_prompt = _build_roleplay_prompt(deal, payload.get('extra_context', ''))
        contact_name = (deal.get('contacts') or {}).get('name', 'Lead')
        company_name = (deal.get('companies') or {}).get('name', deal.get('title', 'Deal'))
        title = f"Roleplay — {contact_name} @ {company_name}"
    else:
        system_prompt = _build_coaching_prompt(payload.get('topic', ''))
        title = payload.get('topic') or 'Sales Coaching Session'

    row = {
        'user_id': user_id,
        'mode': mode,
        'deal_id': deal_id,
        'provider': provider,
        'title': title,
        'system_prompt': system_prompt,
    }
    resp = supabase.table('playground_sessions').insert(row).execute()
    if not resp.data:
        raise HTTPException(status_code=500, detail="Could not create session.")
    return resp.data[0]


@router.get("/sessions")
def list_sessions(user_id: str = Depends(get_current_user)):
    resp = (
        supabase.table('playground_sessions')
        .select('id, mode, title, provider, created_at')
        .eq('user_id', user_id)
        .order('created_at', desc=True)
        .limit(50)
        .execute()
    )
    return {"sessions": resp.data or []}


@router.get("/sessions/{session_id}/messages")
def get_messages(session_id: str, user_id: str = Depends(get_current_user)):
    session = supabase.table('playground_sessions').select('id').eq('id', session_id).eq('user_id', user_id).single().execute().data
    if not session:
        raise HTTPException(status_code=404, detail="Session not found.")
    resp = supabase.table('playground_messages').select('role, content, created_at').eq('session_id', session_id).order('created_at').execute()
    return {"messages": resp.data or []}


@router.post("/sessions/{session_id}/messages")
def send_message(session_id: str, payload: dict = Body(...), user_id: str = Depends(get_current_user)):
    """Body: {"message": "..."}"""
    user_message = (payload.get('message') or '').strip()
    if not user_message:
        raise HTTPException(status_code=400, detail="message is required.")

    session = supabase.table('playground_sessions').select('*').eq('id', session_id).eq('user_id', user_id).single().execute().data
    if not session:
        raise HTTPException(status_code=404, detail="Session not found.")

    try:
        api_key = key_vault.get_decrypted_key(user_id, session['provider'])
    except HTTPException:
        raise

    history = (
        supabase.table('playground_messages')
        .select('role, content')
        .eq('session_id', session_id)
        .order('created_at')
        .limit(MAX_HISTORY_MESSAGES)
        .execute()
        .data
    )

    supabase.table('playground_messages').insert({'session_id': session_id, 'role': 'user', 'content': user_message}).execute()

    conversation_text = session['system_prompt'] + "\n\n"
    for m in history:
        speaker = 'You' if m['role'] == 'user' else 'Them'
        conversation_text += f"{speaker}: {m['content']}\n"
    conversation_text += f"You: {user_message}\nThem:"

    model = PROVIDER_CAPABILITIES[session['provider']]['text']
    try:
        reply = call_text(session['provider'], api_key, model, conversation_text, max_tokens=400)
    except ProviderError as e:
        raise HTTPException(status_code=502, detail=str(e))

    reply = reply.strip()
    supabase.table('playground_messages').insert({'session_id': session_id, 'role': 'assistant', 'content': reply}).execute()
    return {"reply": reply}