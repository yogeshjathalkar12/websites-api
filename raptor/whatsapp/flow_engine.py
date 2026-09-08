"""
flow_engine.py — walks a whatsapp_flows.definition graph one step at a
time in response to an inbound message.

The graph is a direct save of a React Flow canvas: nodes = [{id, data:
{kind, ...}}], edges = [{source, target, sourceHandle}]. sourceHandle is
None for a node with a single unconditional exit (message/question/
ai_reply/start), and equals a button id / list row id / condition case
value for a branching node (buttons/list/condition).

EXECUTION MODEL: most node kinds fire immediately and move straight to the
next node in the same webhook call — only buttons/list/question actually
pause and wait for the contact's next message, at which point we save a
whatsapp_flow_sessions row pointing at that node. Everything else
(message, ai_reply, condition) has no reason to make the contact wait, so
it just keeps walking the graph until it hits something that does need
their input, or a terminal node (handoff/end).

This mirrors how a real chatbot builder (Landbot, ManyChat, etc.) executes
underneath the visual canvas — the graph is just data, this is the
interpreter for it.
"""
import os
from datetime import datetime, timezone

import httpx

ANTHROPIC_API_URL = "https://api.anthropic.com/v1/messages"


def get_flow_start_node_id(definition: dict) -> str | None:
    """Public entry point for router.py — finds the 'start' node and
    returns whatever it points to (the flow's real first step), rather
    than making the caller reach into _next_node_id/_find_node directly."""
    start_id = next((n['id'] for n in definition.get('nodes', []) if n['data'].get('kind') == 'start'), None)
    if not start_id:
        return None
    return _next_node_id(definition, start_id, None)


def find_flow_for_keyword(supabase, account_id: str, match_key: str):
    """Returns the first active flow whose entry_keyword matches, or None.
    Checked BEFORE plain whatsapp_triggers — a flow takes priority if both
    would match the same inbound message."""
    flows = supabase.table('whatsapp_flows').select('*').eq('account_id', account_id).eq('is_active', True).execute().data or []
    for flow in flows:
        keyword = flow['entry_keyword'].strip().lower()
        matched = match_key == keyword if flow.get('match_type') == 'exact' else keyword in match_key
        if matched:
            return flow
    return None


def get_active_session(supabase, account_id: str, phone: str):
    rows = (
        supabase.table('whatsapp_flow_sessions')
        .select('*')
        .eq('account_id', account_id)
        .eq('contact_phone', phone)
        .eq('status', 'active')
        .limit(1)
        .execute()
        .data
    )
    return rows[0] if rows else None


def _find_node(definition: dict, node_id: str):
    for node in definition.get('nodes', []):
        if node['id'] == node_id:
            return node
    return None


def _next_node_id(definition: dict, source_id: str, source_handle: str | None):
    """source_handle=None matches an edge with no sourceHandle set (a
    single-exit node) OR one saved as 'default' (React Flow sometimes sets
    a literal 'default' id when a node has just one unnamed handle)."""
    for edge in definition.get('edges', []):
        if edge['source'] != source_id:
            continue
        handle = edge.get('sourceHandle')
        if source_handle is None:
            if handle is None or handle == 'default':
                return edge['target']
        elif handle == source_handle:
            return edge['target']
    return None


def _call_ai_reply(supabase, owner_id: str, account_id: str, node_data: dict, trigger_message: str) -> str | None:
    """Looks up the account's AI settings + the owner's existing Anthropic
    key from the AI Content Suite (ai_content_keys — bring-your-own-key,
    same as every other AI feature in this app), and generates one reply.
    Returns None if unavailable so the caller can fall back gracefully."""
    settings = supabase.table('whatsapp_ai_settings').select('*').eq('account_id', account_id).maybe_single().execute().data
    if not settings or not settings.get('is_enabled', True):
        return None

    key_row = (
        supabase.table('ai_content_keys')
        .select('encrypted_api_key')
        .eq('owner_id', owner_id)
        .eq('provider', 'anthropic')
        .execute()
        .data
    )
    if not key_row:
        return None

    try:
        # Reuses the AI Content Suite's own key vault/secret — a separate
        # module from raptor/whatsapp/key_vault.py, matching the isolation
        # pattern already established between the email/whatsapp/content tools.
        from raptor.ai_integration import key_vault as ai_key_vault
        api_key = ai_key_vault.decrypt_key(key_row[0]['encrypted_api_key'])
    except Exception as err:
        print(f"Could not decrypt AI Content Suite key for AI Reply node: {err}")
        return None

    system_prompt = node_data.get('system_prompt') or settings['system_prompt']
    try:
        resp = httpx.post(
            ANTHROPIC_API_URL,
            headers={'x-api-key': api_key, 'anthropic-version': '2023-06-01', 'content-type': 'application/json'},
            json={
                'model': settings.get('model', 'claude-sonnet-4-6'),
                'max_tokens': 300,
                'system': system_prompt,
                'messages': [{'role': 'user', 'content': trigger_message or '(no message)'}],
            },
            timeout=30,
        )
        resp.raise_for_status()
        data = resp.json()
        return ''.join(b['text'] for b in data.get('content', []) if b.get('type') == 'text').strip() or None
    except Exception as err:
        print(f"AI Reply call failed: {err}")
        return None


def run_flow(supabase, provider, account: dict, phone: str, flow: dict, start_node_id: str,
             context: dict, crm_contact_id: str | None, conversation_id: str,
             trigger_message: str, touch_conversation_fn, log_interaction_fn) -> None:
    """Walks the graph starting at start_node_id until it hits a node that
    needs the contact's input (buttons/list/question) or a terminal node
    (handoff/end). Saves/updates/deletes the whatsapp_flow_sessions row
    accordingly. Every send is logged into whatsapp_events + interactions
    exactly like a trigger reply would be."""
    definition = flow['definition']
    node_id = start_node_id
    account_id = account['id']

    while node_id:
        node = _find_node(definition, node_id)
        if not node:
            _end_session(supabase, account_id, phone)
            return
        kind = node['data'].get('kind')
        data = node['data']

        if kind == 'start':
            node_id = _next_node_id(definition, node_id, None)
            continue

        if kind == 'message':
            text = data.get('text', '')
            _send_and_log(supabase, provider, account_id, phone, text, crm_contact_id, conversation_id, touch_conversation_fn, log_interaction_fn)
            node_id = _next_node_id(definition, node_id, None)
            continue

        if kind == 'ai_reply':
            reply = _call_ai_reply(supabase, account['owner_id'], account_id, data, trigger_message)
            text = reply or data.get('fallback_text') or "Let me get someone to help you with that."
            _send_and_log(supabase, provider, account_id, phone, text, crm_contact_id, conversation_id, touch_conversation_fn, log_interaction_fn)
            node_id = _next_node_id(definition, node_id, None)
            continue

        if kind == 'condition':
            var_name = data.get('variable_name', '')
            value = str(context.get(var_name, '')).strip().lower()
            matched_handle = 'default'
            for case in data.get('cases', []):
                case_value = str(case.get('value', '')).strip().lower()
                if case_value and case_value in value:
                    matched_handle = case_value
                    break
            node_id = _next_node_id(definition, node_id, matched_handle)
            continue

        if kind == 'buttons':
            provider.send_interactive_buttons(phone, data.get('body', ''), data.get('buttons', []))
            _record_outbound(supabase, account_id, phone, data.get('body', ''), crm_contact_id, conversation_id, touch_conversation_fn, log_interaction_fn)
            _save_session(supabase, account_id, phone, flow['id'], node_id, context)
            return

        if kind == 'list':
            provider.send_interactive_list(phone, data.get('body', ''), data.get('button_label', 'View options'), data.get('rows', []))
            _record_outbound(supabase, account_id, phone, data.get('body', ''), crm_contact_id, conversation_id, touch_conversation_fn, log_interaction_fn)
            _save_session(supabase, account_id, phone, flow['id'], node_id, context)
            return

        if kind == 'question':
            text = data.get('text', '')
            _send_and_log(supabase, provider, account_id, phone, text, crm_contact_id, conversation_id, touch_conversation_fn, log_interaction_fn)
            _save_session(supabase, account_id, phone, flow['id'], node_id, context)
            return

        if kind == 'handoff':
            touch_conversation_fn(account_id, phone, 'inbound', data.get('note') or '[Flow handed off to agent]', crm_contact_id)
            supabase.table('whatsapp_conversations').update({'status': 'waiting'}).eq('account_id', account_id).eq('contact_phone', phone).execute()
            supabase.table('whatsapp_flow_sessions').update({'status': 'handed_off', 'updated_at': datetime.now(timezone.utc).isoformat()}).eq('account_id', account_id).eq('contact_phone', phone).execute()
            return

        if kind == 'end':
            _end_session(supabase, account_id, phone)
            return

        # Unknown node kind — stop safely rather than loop forever.
        _end_session(supabase, account_id, phone)
        return


def advance_flow_session(supabase, provider, account: dict, phone: str, session: dict,
                          match_key: str, text_body: str, crm_contact_id: str | None,
                          conversation_id: str, touch_conversation_fn, log_interaction_fn) -> None:
    """Called when an inbound message arrives and there's already an
    active session — interprets the message as the answer to whichever
    node the session is paused at, then resumes run_flow from there."""
    flow = supabase.table('whatsapp_flows').select('*').eq('id', session['flow_id']).single().execute().data
    if not flow:
        _end_session(supabase, account['id'], phone)
        return

    definition = flow['definition']
    node = _find_node(definition, session['current_node_id'])
    context = session.get('context') or {}

    if not node:
        _end_session(supabase, account['id'], phone)
        return

    kind = node['data'].get('kind')

    if kind == 'question':
        var_name = node['data'].get('variable_name')
        if var_name:
            context[var_name] = text_body
        next_id = _next_node_id(definition, node['id'], None)
    elif kind in ('buttons', 'list'):
        next_id = _next_node_id(definition, node['id'], match_key)
        if next_id is None:
            # Tapped/typed something that doesn't match any branch — resend
            # the same prompt rather than silently dropping the contact.
            if kind == 'buttons':
                provider.send_interactive_buttons(phone, node['data'].get('body', ''), node['data'].get('buttons', []))
            else:
                provider.send_interactive_list(phone, node['data'].get('body', ''), node['data'].get('button_label', 'View options'), node['data'].get('rows', []))
            return
    else:
        next_id = _next_node_id(definition, node['id'], None)

    if next_id is None:
        _end_session(supabase, account['id'], phone)
        return

    run_flow(supabase, provider, account, phone, flow, next_id, context, crm_contact_id, conversation_id, text_body, touch_conversation_fn, log_interaction_fn)


# ---------------------------------------------------------------------------
# internal helpers
# ---------------------------------------------------------------------------

def _send_and_log(supabase, provider, account_id, phone, text, crm_contact_id, conversation_id, touch_conversation_fn, log_interaction_fn):
    provider.send_text(phone, text)
    _record_outbound(supabase, account_id, phone, text, crm_contact_id, conversation_id, touch_conversation_fn, log_interaction_fn)


def _record_outbound(supabase, account_id, phone, preview, crm_contact_id, conversation_id, touch_conversation_fn, log_interaction_fn):
    touch_conversation_fn(account_id, phone, 'outbound', preview, crm_contact_id)
    supabase.table('whatsapp_events').insert({
        'account_id': account_id, 'contact_phone': phone, 'direction': 'outbound',
        'event_type': 'sent', 'body_text': preview, 'conversation_id': conversation_id,
    }).execute()
    log_interaction_fn(crm_contact_id, 'outbound', preview)


def _save_session(supabase, account_id, phone, flow_id, node_id, context):
    supabase.table('whatsapp_flow_sessions').upsert({
        'account_id': account_id, 'contact_phone': phone, 'flow_id': flow_id,
        'current_node_id': node_id, 'context': context, 'status': 'active',
        'updated_at': datetime.now(timezone.utc).isoformat(),
    }, on_conflict='account_id,contact_phone').execute()


def _end_session(supabase, account_id, phone):
    supabase.table('whatsapp_flow_sessions').update({
        'status': 'completed', 'updated_at': datetime.now(timezone.utc).isoformat(),
    }).eq('account_id', account_id).eq('contact_phone', phone).eq('status', 'active').execute()