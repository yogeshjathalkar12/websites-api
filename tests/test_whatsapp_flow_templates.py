"""tests/test_whatsapp_flow_templates.py - the starter flows in the app's template library, run through the REAL flow engine.

tests/fixtures/wa_flow_templates.json holds the flow definitions exactly as the app builds them from its library
(raptor-app/src/lib/waTemplates.ts: buildFlowDefinition). Every path through every flow is walked, answering each question with text
and each button / list option with its ID, the way WhatsApp delivers a tap. A flow passes when every path ends cleanly (finished or
handed to a person) and every step of the flow is reached by at least one path.

If the library changes, regenerate the fixture (see tests/fixtures/README.md)."""
import json
import os
import re

import pytest

os.environ.setdefault('ANTHROPIC_API_KEY', 'test')

from raptor.whatsapp import flow_engine  # noqa: E402

FLOWS = json.load(open(os.path.join(os.path.dirname(__file__), 'fixtures', 'wa_flow_templates.json'), encoding='utf-8'))
ACCOUNT = {'id': 'acct-1', 'owner_id': 'org-1'}
PHONE = '919800000000'
MAX_STEPS = 30


class Query:
    def __init__(self, db, table):
        self.db, self.t, self.filters, self.op, self.payload, self.single_row, self.conflict = db, table, [], 'select', None, False, None

    def select(self, *a, **k): self.op = 'select'; return self
    def insert(self, p): self.op, self.payload = 'insert', p; return self
    def update(self, p): self.op, self.payload = 'update', p; return self
    def upsert(self, p, on_conflict=None): self.op, self.payload, self.conflict = 'upsert', p, on_conflict; return self
    def eq(self, c, v): self.filters.append((c, v)); return self
    def limit(self, n): return self
    def single(self): self.single_row = True; return self

    def _match(self, row): return all(row.get(c) == v for c, v in self.filters)

    def execute(self):
        rows = self.db.tables.setdefault(self.t, [])
        if self.op == 'insert':
            rows.append(dict(self.payload)); return type('R', (), {'data': [self.payload]})()
        if self.op == 'upsert':
            keys = (self.conflict or '').split(',')
            for r in rows:
                if all(r.get(k) == self.payload.get(k) for k in keys):
                    r.update(self.payload); break
            else:
                rows.append(dict(self.payload))
            return type('R', (), {'data': [self.payload]})()
        hits = [r for r in rows if self._match(r)]
        if self.op == 'update':
            for r in hits: r.update(self.payload)
            return type('R', (), {'data': hits})()
        data = hits[0] if (self.single_row and hits) else (None if self.single_row else hits)
        return type('R', (), {'data': data})()


class FakeDB:
    def __init__(self, flow):
        self.tables = {'whatsapp_flows': [{**flow, 'id': flow['id'], 'is_active': True, 'account_id': 'acct-1'}], 'whatsapp_flow_sessions': []}

    def table(self, name): return Query(self, name)


class Provider:
    def __init__(self): self.sent = []
    def send_text(self, to, text): self.sent.append(('text', text))
    def send_interactive_buttons(self, to, body, buttons): self.sent.append(('buttons', body, buttons))
    def send_interactive_list(self, to, body, label, rows): self.sent.append(('list', body, rows))


@pytest.fixture(autouse=True)
def no_ai(monkeypatch):
    monkeypatch.setattr(flow_engine, '_call_ai_reply', lambda *a, **k: None)      # the AI step falls back to its own text


def _node(definition, node_id):
    return next(n for n in definition['nodes'] if n['id'] == node_id)


def _noop(*a, **k): return None


def _walk(flow):
    """Explores every choice at every pause. Returns (visited node ids, number of paths, endings)."""
    definition = flow['definition']
    visited, endings, paths = set(), set(), 0
    stack = [[]]
    while stack:
        choices = stack.pop()
        db, provider = FakeDB(flow), Provider()
        start = flow_engine.get_flow_start_node_id(definition)
        assert start, 'the flow has a first step'
        flow_engine.run_flow(db, provider, ACCOUNT, PHONE, db.tables['whatsapp_flows'][0], start, {}, None, 'conv', 'start',
                             touch_conversation_fn=_noop, log_interaction_fn=_noop)
        for step in range(MAX_STEPS):
            session = flow_engine.get_active_session(db, ACCOUNT['id'], PHONE)
            if not session:
                break
            node = _node(definition, session['current_node_id'])
            visited.add(node['id'])
            data = node['data']
            if data['kind'] == 'question':
                options = ['some answer']
            else:
                options = list(data['branches'])
            if step < len(choices):
                pick = choices[step]
            else:
                pick = options[0]
                for other in options[1:]:
                    stack.append(choices[:step] + [other])
                choices = choices + [pick]
            flow_engine.advance_flow_session(db, provider, ACCOUNT, PHONE, session, pick, pick, None, 'conv',
                                             touch_conversation_fn=_noop, log_interaction_fn=_noop)
        else:
            pytest.fail(f"{flow['id']}: a path did not end within {MAX_STEPS} steps ({choices})")
        paths += 1
        statuses = [r.get('status') for r in db.tables['whatsapp_flow_sessions']]
        endings.add(statuses[-1] if statuses else 'completed')
        assert provider.sent, f"{flow['id']}: the flow said something"
        # every send is a real, non-empty message
        for item in provider.sent:
            assert item[1].strip(), f"{flow['id']}: empty message sent"
    return visited, paths, endings


@pytest.mark.parametrize('flow', FLOWS, ids=[f['id'] for f in FLOWS])
def test_every_path_through_the_flow_ends_cleanly_and_every_step_is_used(flow):
    visited, paths, endings = _walk(flow)
    definition = flow['definition']
    pausing = {n['id'] for n in definition['nodes'] if n['data']['kind'] in ('question', 'buttons', 'list')}
    assert pausing <= visited, f"steps never reached by any path: {sorted(pausing - visited)}"
    assert endings <= {'completed', 'handed_off'}
    assert paths >= 1


@pytest.mark.parametrize('flow', FLOWS, ids=[f['id'] for f in FLOWS])
def test_the_flow_starts_on_its_own_keyword_and_the_engine_finds_it(flow):
    db = FakeDB(flow)
    keyword = flow['entry_keyword']
    assert flow_engine.find_flow_for_keyword(db, ACCOUNT['id'], keyword)['id'] == flow['id']
    assert flow_engine.find_flow_for_keyword(db, ACCOUNT['id'], 'zzz unrelated zzz') is None


def test_the_buttons_in_every_flow_fit_whatsapps_limits_and_the_ids_match_what_a_tap_delivers():
    for flow in FLOWS:
        for n in flow['definition']['nodes']:
            d = n['data']
            if d['kind'] == 'buttons':
                assert 1 <= len(d['buttons']) <= 3
                for b in d['buttons']:
                    assert len(b['title']) <= 20 and b['id'] == re.sub(r'^_+|_+$', '', re.sub(r'[^a-z0-9]+', '_', b['title'].strip().lower()))[:40]
            if d['kind'] == 'list':
                assert 1 <= len(d['rows']) <= 10 and len(d['button_label']) <= 20
                assert all(len(r['title']) <= 24 for r in d['rows'])


def test_a_tap_that_matches_nothing_asks_again_instead_of_losing_the_person():
    flow = next(f for f in FLOWS if f['id'] == 'flow-book-demo')
    db, provider = FakeDB(flow), Provider()
    definition = flow['definition']
    flow_engine.run_flow(db, provider, ACCOUNT, PHONE, db.tables['whatsapp_flows'][0], flow_engine.get_flow_start_node_id(definition), {}, None, 'c', 'demo',
                         touch_conversation_fn=_noop, log_interaction_fn=_noop)
    for answer in ('Priya', 'Acme'):                    # name, company -> now waiting on the time-of-day buttons
        session = flow_engine.get_active_session(db, ACCOUNT['id'], PHONE)
        flow_engine.advance_flow_session(db, provider, ACCOUNT, PHONE, session, answer.lower(), answer, None, 'c', touch_conversation_fn=_noop, log_interaction_fn=_noop)
    before = len(provider.sent)
    session = flow_engine.get_active_session(db, ACCOUNT['id'], PHONE)
    assert session['current_node_id'] == 'ask_when'
    flow_engine.advance_flow_session(db, provider, ACCOUNT, PHONE, session, 'not_a_button', 'whatever', None, 'c', touch_conversation_fn=_noop, log_interaction_fn=_noop)
    assert len(provider.sent) == before + 1 and provider.sent[-1][0] == 'buttons'
    assert flow_engine.get_active_session(db, ACCOUNT['id'], PHONE)['current_node_id'] == 'ask_when'
