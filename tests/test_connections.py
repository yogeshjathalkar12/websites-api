"""tests/test_connections.py - the connections foundation: the vault, the YouTube connector and the router rules.
No network, no database: an in-memory stand-in for Supabase and a fake YouTube."""
import os
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.fernet import Fernet
from fastapi import HTTPException

os.environ.setdefault('EMAIL_KEY_ENCRYPTION_SECRET', Fernet.generate_key().decode())

from raptor.connections import registry, router as conn_router, vault, youtube  # noqa: E402
from raptor.utility import raptor_auth  # noqa: E402

CHANNEL_ID = 'UC' + 'a' * 22


# ───────────────────────── an in-memory Supabase ─────────────────────────

class Query:
    def __init__(self, db, table):
        self.db, self.t = db, table
        self.op, self.payload, self.filters, self._limit, self._order = 'select', None, [], None, None
        self.upsert_keys, self.ignore = None, False

    def select(self, *a, **k): self.op = 'select'; return self
    def insert(self, payload): self.op, self.payload = 'insert', payload; return self
    def update(self, payload): self.op, self.payload = 'update', payload; return self
    def delete(self): self.op = 'delete'; return self
    def upsert(self, payload, on_conflict=None, ignore_duplicates=False):
        self.op, self.payload, self.upsert_keys, self.ignore = 'upsert', payload, on_conflict, ignore_duplicates
        return self
    def eq(self, col, val): self.filters.append((col, val)); return self
    def limit(self, n): self._limit = n; return self
    def order(self, col, desc=False): self._order = (col, desc); return self

    def _match(self, row):
        return all(row.get(c) == v for c, v in self.filters)

    def execute(self):
        rows = self.db.tables.setdefault(self.t, [])
        if self.op == 'insert':
            items = self.payload if isinstance(self.payload, list) else [self.payload]
            out = []
            for it in items:
                row = {'id': f'{self.t}-{len(rows) + 1}', **it}
                rows.append(row); out.append(row)
            return type('R', (), {'data': out})()
        if self.op == 'upsert':
            keys = self.upsert_keys.split(',')
            out = []
            for it in self.payload:
                if any(all(r.get(k) == it.get(k) for k in keys) for r in rows):
                    if self.ignore:
                        continue
                rows.append({'id': f'{self.t}-{len(rows) + 1}', **it}); out.append(it)
            return type('R', (), {'data': out})()
        hits = [r for r in rows if self._match(r)]
        if self.op == 'update':
            for r in hits: r.update(self.payload)
            return type('R', (), {'data': hits})()
        if self.op == 'delete':
            for r in hits: rows.remove(r)
            # cascade, like the database does
            if self.t == 'connections':
                ids = {r['id'] for r in hits}
                for dep in ('connection_secrets', 'signals'):
                    self.db.tables[dep] = [r for r in self.db.tables.get(dep, []) if r.get('connection_id') not in ids]
            return type('R', (), {'data': hits})()
        if self._order:
            col, desc = self._order
            hits = sorted(hits, key=lambda r: (r.get(col) is None, r.get(col) or ''), reverse=desc)
        if self._limit:
            hits = hits[:self._limit]
        return type('R', (), {'data': [dict(r) for r in hits]})()


class FakeDB:
    def __init__(self, tables=None):
        self.tables = tables or {}

    def table(self, name):
        return Query(self, name)


class FakeResponse:
    def __init__(self, status=200, body=None):
        self.status_code, self._body = status, body or {}

    def json(self):
        return self._body


def fake_youtube(calls, quota=False):
    def get(url, params=None, timeout=None):
        calls.append((url, dict(params or {})))
        if quota:
            return FakeResponse(403, {'error': {'errors': [{'reason': 'quotaExceeded'}]}})
        path = url.rsplit('/', 1)[-1]
        if path == 'channels' and params.get('part') == 'snippet,statistics,contentDetails':
            if params.get('forHandle') == '@nobody':
                return FakeResponse(200, {'items': []})
            return FakeResponse(200, {'items': [{'id': CHANNEL_ID, 'snippet': {'title': 'Acme TV', 'customUrl': '@acme'},
                                                 'contentDetails': {'relatedPlaylists': {'uploads': 'UU123'}}}]})
        if path == 'channels':
            return FakeResponse(200, {'items': [{'statistics': {'subscriberCount': '1200', 'viewCount': '98000', 'videoCount': '40'},
                                                 'contentDetails': {'relatedPlaylists': {'uploads': 'UU123'}}}]})
        if path == 'playlistItems':
            return FakeResponse(200, {'items': [{'contentDetails': {'videoId': 'v1'}}, {'contentDetails': {'videoId': 'v2'}}]})
        if path == 'videos':
            return FakeResponse(200, {'items': [
                {'id': 'v1', 'snippet': {'title': 'First'}, 'statistics': {'viewCount': '500', 'likeCount': '20', 'commentCount': '3'}},
                {'id': 'v2', 'snippet': {'title': 'Second'}, 'statistics': {'viewCount': '90'}},
            ]})
        raise AssertionError('unexpected call ' + url)
    return get


@pytest.fixture
def world(monkeypatch):
    db = FakeDB({
        'org_members': [
            {'user_id': 'owner', 'org_id': 'org-1', 'status': 'active', 'is_owner': True, 'permissions': {}},
            {'user_id': 'member', 'org_id': 'org-1', 'status': 'active', 'is_owner': False, 'permissions': {}},
            {'user_id': 'manager', 'org_id': 'org-1', 'status': 'active', 'is_owner': False, 'permissions': {'manage_automations': True}},
            {'user_id': 'gone', 'org_id': 'org-1', 'status': 'removed', 'is_owner': False, 'permissions': {'manage_automations': True}},
            {'user_id': 'other', 'org_id': 'org-2', 'status': 'active', 'is_owner': True, 'permissions': {}},
        ],
        'raptor_users': [{'user_id': 'org-1', 'plan': 'Pro'}, {'user_id': 'org-2', 'plan': 'Free'}],
    })
    monkeypatch.setattr(raptor_auth, '_service_client', db)
    monkeypatch.setattr(raptor_auth, 'supabase', db)
    monkeypatch.setenv('YOUTUBE_API_KEY', 'test-key')
    calls = []
    monkeypatch.setattr(youtube.httpx, 'get', fake_youtube(calls))
    db.calls = calls
    return db


def _connect(user='owner', link='https://www.youtube.com/@acme'):
    return conn_router.connect(conn_router.ConnectBody(provider='youtube_public', inputs={'channel': link}), user_id=user)


# ───────────────────────── the vault ─────────────────────────

def test_a_secret_is_stored_encrypted_and_comes_back():
    token = vault.encrypt_secret('my-service-account')
    assert 'my-service-account' not in token
    assert vault.decrypt_secret(token) == 'my-service-account'


def test_a_secret_that_cannot_be_decrypted_says_to_reconnect(monkeypatch):
    token = vault.encrypt_secret('x')
    monkeypatch.setenv('CONNECTIONS_KEY_ENCRYPTION_SECRET', Fernet.generate_key().decode())
    with pytest.raises(HTTPException) as err:
        vault.decrypt_secret(token)
    assert err.value.status_code == 500 and 'Reconnect' in err.value.detail


def test_without_any_key_the_vault_fails_cleanly(monkeypatch):
    monkeypatch.delenv('EMAIL_KEY_ENCRYPTION_SECRET', raising=False)
    monkeypatch.delenv('CONNECTIONS_KEY_ENCRYPTION_SECRET', raising=False)
    with pytest.raises(HTTPException) as err:
        vault.encrypt_secret('x')
    assert err.value.status_code == 500


# ───────────────────────── understanding a pasted channel link ─────────────────────────

@pytest.mark.parametrize('text,expected', [
    ('https://www.youtube.com/@acme', ('handle', '@acme')),
    ('youtube.com/@acme/videos', ('handle', '@acme')),
    ('https://m.youtube.com/@acme?si=abc', ('handle', '@acme')),
    ('@acme', ('handle', '@acme')),
    (CHANNEL_ID, ('id', CHANNEL_ID)),
    (f'https://www.youtube.com/channel/{CHANNEL_ID}', ('id', CHANNEL_ID)),
])
def test_channel_links_are_understood(text, expected):
    assert youtube.parse_channel_reference(text) == expected


@pytest.mark.parametrize('text', ['', '   ', 'https://example.com/@acme', 'https://www.youtube.com/watch?v=abc',
                                  'https://www.youtube.com/c/OldName', 'https://youtube.com/@a/../x y'])
def test_things_that_are_not_a_channel_are_refused(text):
    with pytest.raises(registry.ConnectorError):
        youtube.parse_channel_reference(text)


# ───────────────────────── connecting ─────────────────────────

def test_connecting_a_channel_stores_it_for_the_organization_and_fetches_first_data(world):
    result = _connect()['connection']
    assert result['provider'] == 'youtube_public' and result['label'] == 'Acme TV' and result['status'] == 'connected'
    assert result['external_id'] == CHANNEL_ID and result['last_sync_at']
    row = world.tables['connections'][0]
    assert row['owner_id'] == 'org-1' and row['created_by'] == 'owner'            # the organization, not the person
    names = sorted({s['name'] for s in world.tables['signals']})
    assert names == ['subscribers', 'video_comments', 'video_likes', 'video_views', 'videos', 'views']
    assert all(s['owner_id'] == 'org-1' and s['connection_id'] == row['id'] for s in world.tables['signals'])
    assert 'secret' not in str(result).lower()


def test_syncing_twice_on_one_day_does_not_store_the_same_numbers_twice(world):
    created = _connect()['connection']
    count = len(world.tables['signals'])
    world.tables['connections'][0]['last_sync_at'] = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
    conn_router.sync_now(created['id'], user_id='owner')
    assert len(world.tables['signals']) == count


def test_a_connection_cannot_be_synced_again_within_the_wait(world):
    created = _connect()['connection']
    with pytest.raises(HTTPException) as err:
        conn_router.sync_now(created['id'], user_id='owner')
    assert err.value.status_code == 429


def test_the_same_channel_cannot_be_connected_twice(world):
    _connect()
    with pytest.raises(HTTPException) as err:
        _connect(link=f'https://www.youtube.com/channel/{CHANNEL_ID}')
    assert err.value.status_code == 409


def test_only_people_allowed_to_manage_connections_can_connect(world):
    for user in ('member', 'gone'):
        with pytest.raises(HTTPException) as err:
            _connect(user=user)
        assert err.value.status_code == 403
    assert _connect(user='manager')['connection']['status'] == 'connected'      # the permission is enough, not ownership


def test_connecting_needs_the_pro_plan(world):
    with pytest.raises(HTTPException) as err:
        _connect(user='other')
    assert err.value.status_code == 403 and 'Pro' in err.value.detail
    assert world.tables.get('connections', []) == []


def test_a_connector_that_is_not_switched_on_says_so(world, monkeypatch):
    monkeypatch.delenv('YOUTUBE_API_KEY')
    with pytest.raises(HTTPException) as err:
        _connect()
    assert err.value.status_code == 503 and 'not switched on' in err.value.detail


def test_a_missing_channel_is_a_clear_message_and_nothing_is_saved(world):
    with pytest.raises(HTTPException) as err:
        _connect(link='@nobody')
    assert err.value.status_code == 422 and 'No YouTube channel' in err.value.detail
    assert world.tables.get('connections', []) == []


def test_required_fields_are_checked(world):
    with pytest.raises(HTTPException) as err:
        conn_router.connect(conn_router.ConnectBody(provider='youtube_public', inputs={}), user_id='owner')
    assert err.value.status_code == 400


def test_an_unknown_provider_is_404(world):
    with pytest.raises(HTTPException) as err:
        conn_router.connect(conn_router.ConnectBody(provider='nope', inputs={}), user_id='owner')
    assert err.value.status_code == 404


# ───────────────────────── errors while syncing ─────────────────────────

def test_a_used_up_quota_is_recorded_on_the_connection_in_plain_words(world, monkeypatch):
    created = _connect()['connection']
    world.tables['connections'][0]['last_sync_at'] = (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat()
    monkeypatch.setattr(youtube.httpx, 'get', fake_youtube([], quota=True))
    with pytest.raises(HTTPException) as err:
        conn_router.sync_now(created['id'], user_id='owner')
    assert err.value.status_code == 422 and 'daily limit' in err.value.detail
    row = world.tables['connections'][0]
    assert row['status'] == 'error' and 'daily limit' in row['last_error']


def test_a_paused_connection_is_not_synced_and_resuming_clears_the_error(world):
    created = _connect()['connection']
    conn_router.patch(created['id'], conn_router.PatchBody(paused=True), user_id='owner')
    assert world.tables['connections'][0]['status'] == 'paused'
    with pytest.raises(HTTPException) as err:
        conn_router.sync_now(created['id'], user_id='owner')
    assert err.value.status_code == 409
    world.tables['connections'][0]['last_error'] = 'old'
    conn_router.patch(created['id'], conn_router.PatchBody(paused=False), user_id='owner')
    assert world.tables['connections'][0]['status'] == 'connected' and world.tables['connections'][0]['last_error'] is None


# ───────────────────────── looking at and removing ─────────────────────────

def test_everyone_in_the_organization_sees_the_connections_but_others_see_none(world):
    _connect()
    assert len(conn_router.list_connections(user_id='member')['connections']) == 1
    assert conn_router.list_connections(user_id='other')['connections'] == []


def test_another_organization_cannot_read_change_or_remove_a_connection(world):
    created = _connect()['connection']
    for call in (lambda: conn_router.signals(created['id'], limit=10, user_id='other'),
                 lambda: conn_router.patch(created['id'], conn_router.PatchBody(label='x'), user_id='other'),
                 lambda: conn_router.disconnect(created['id'], user_id='other'),
                 lambda: conn_router.sync_now(created['id'], user_id='other')):
        with pytest.raises(HTTPException) as err:
            call()
        assert err.value.status_code in (403, 404)
    assert len(world.tables['connections']) == 1 and world.tables['connections'][0]['label'] == 'Acme TV'


def test_a_member_without_the_permission_cannot_remove_a_connection(world):
    created = _connect()['connection']
    with pytest.raises(HTTPException) as err:
        conn_router.disconnect(created['id'], user_id='member')
    assert err.value.status_code == 403 and len(world.tables['connections']) == 1


def test_disconnecting_removes_the_connection_its_secret_and_its_signals(world):
    created = _connect()['connection']
    world.tables.setdefault('connection_secrets', []).append({'connection_id': created['id'], 'encrypted_secret': 'x'})
    conn_router.disconnect(created['id'], user_id='owner')
    assert world.tables['connections'] == [] and world.tables['connection_secrets'] == [] and world.tables['signals'] == []


def test_the_signals_of_a_connection_can_be_read(world):
    created = _connect()['connection']
    rows = conn_router.signals(created['id'], limit=100, user_id='member')['signals']
    assert {r['name'] for r in rows} >= {'subscribers', 'views'}


def test_the_provider_list_says_what_is_switched_on(world, monkeypatch):
    listed = {p['provider']: p for p in conn_router.providers(user_id='member')['providers']}
    assert listed['youtube_public']['available'] is True and listed['youtube_public']['fields'][0]['name'] == 'channel'
    monkeypatch.delenv('YOUTUBE_API_KEY')
    assert {p['provider']: p for p in conn_router.providers(user_id='member')['providers']}['youtube_public']['available'] is False


# ───────────────────────── the scheduled run ─────────────────────────

def test_the_scheduled_run_needs_the_cron_secret(monkeypatch):
    monkeypatch.setenv('AUTOMATION_CRON_SECRET', 'right')
    for bad in (None, 'wrong'):
        with pytest.raises(HTTPException) as err:
            conn_router._require_cron_secret(bad)
        assert err.value.status_code == 401
    monkeypatch.delenv('AUTOMATION_CRON_SECRET')
    with pytest.raises(HTTPException):
        conn_router._require_cron_secret('anything')


def test_the_scheduled_run_syncs_only_connections_that_are_due(world):
    _connect()
    row = world.tables['connections'][0]
    assert conn_router.tick() == {'synced': 0, 'failed': 0}                      # refreshed just now
    row['last_sync_at'] = (datetime.now(timezone.utc) - timedelta(hours=7)).isoformat()
    assert conn_router.tick() == {'synced': 1, 'failed': 0}


def test_one_failing_connection_does_not_stop_the_scheduled_run(world, monkeypatch):
    _connect()
    world.tables['connections'][0]['last_sync_at'] = (datetime.now(timezone.utc) - timedelta(hours=7)).isoformat()
    monkeypatch.setattr(youtube.httpx, 'get', fake_youtube([], quota=True))
    assert conn_router.tick() == {'synced': 0, 'failed': 1}
