"""tests/test_connections.py - the connections foundation: the vault, the YouTube connector and the router rules.
No network, no database: an in-memory stand-in for Supabase and a fake YouTube."""
import os
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.fernet import Fernet
from fastapi import HTTPException

os.environ.setdefault('EMAIL_KEY_ENCRYPTION_SECRET', Fernet.generate_key().decode())

from raptor.connections import google_oauth, registry, router as conn_router, vault, youtube, youtube_account  # noqa: E402
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
    def get(url, params=None, headers=None, timeout=None):
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
        if path == 'commentThreads':
            if params.get('videoId') == 'v2':
                return FakeResponse(403, {'error': {'errors': [{'reason': 'commentsDisabled'}]}})
            return FakeResponse(200, {'items': [
                {'id': 'c1', 'snippet': {'totalReplyCount': 1, 'topLevelComment': {'id': 'c1', 'snippet': {
                    'videoId': 'v1', 'textDisplay': 'Great &amp; useful<br>video', 'authorDisplayName': 'Priya', 'likeCount': 4,
                    'authorChannelUrl': 'http://www.youtube.com/channel/UCpriya', 'authorChannelId': {'value': 'UCpriya'},
                    'publishedAt': '2026-10-17T10:00:00Z'}}}},
                {'id': 'c2', 'snippet': {'totalReplyCount': 0, 'topLevelComment': {'id': 'c2', 'snippet': {
                    'videoId': 'v1', 'textDisplay': 'our own comment', 'authorDisplayName': 'Acme TV',
                    'authorChannelId': {'value': CHANNEL_ID}, 'publishedAt': '2026-10-17T11:00:00Z'}}}},
            ]})
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
    assert names == ['comment', 'subscribers', 'video_comments', 'video_likes', 'video_views', 'videos', 'views']
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


# ───────────────────────── public comments ─────────────────────────

def test_public_comments_are_read_as_plain_text_without_the_channels_own(world):
    _connect()
    comments = [s for s in world.tables['signals'] if s['name'] == 'comment']
    assert len(comments) == 1                                     # the channel's own comment is not a lead
    c = comments[0]
    assert c['kind'] == 'mention' and c['text_value'] == 'Great & useful\nvideo'
    assert c['entity']['author'] == 'Priya' and c['entity']['comment_id'] == 'c1' and c['entity']['title'] == 'First'
    assert c['occurred_at'].startswith('2026-10-17') and c['dedupe_key'] == 'comment:c1'


def test_a_video_with_comments_turned_off_is_skipped_quietly(world):
    _connect()                                                    # v2 has comments disabled in the fake
    assert world.tables['connections'][0]['status'] == 'connected'


# ───────────────────────── sign in with Google ─────────────────────────

ACCOUNT_SCOPES = ' '.join(youtube_account.SCOPES)


@pytest.fixture
def google(world, monkeypatch):
    """A Google that approves sign-ins, with a recorder of what was sent to it."""
    monkeypatch.setenv('GOOGLE_OAUTH_CLIENT_ID', 'client-id')
    monkeypatch.setenv('GOOGLE_OAUTH_CLIENT_SECRET', 'client-secret')
    monkeypatch.setenv('WEB_APP_URL', 'https://app.test/ventures/raptor/app/')
    sent = {'posts': [], 'revoked': [], 'granted_scope': ACCOUNT_SCOPES, 'refresh': 'refresh-123', 'reply_status': 200,
            'analytics_status': 200, 'token_error': None}

    def post(url, data=None, json=None, params=None, headers=None, timeout=None):
        sent['posts'].append((url, data, json, params, headers))
        if url == google_oauth.TOKEN_URL:
            if sent['token_error']:
                return FakeResponse(400, {'error': sent['token_error']})
            if data['grant_type'] == 'authorization_code':
                body = {'access_token': 'access-1', 'scope': sent['granted_scope']}
                if sent['refresh']:
                    body['refresh_token'] = sent['refresh']
                return FakeResponse(200, body)
            return FakeResponse(200, {'access_token': 'access-2'})
        if url == google_oauth.REVOKE_URL:
            sent['revoked'].append(data['token'])
            return FakeResponse(200, {})
        if url.endswith('/youtube/v3/comments'):
            return FakeResponse(sent['reply_status'], {'id': 'reply-9'})
        raise AssertionError('unexpected POST ' + url)

    inner = youtube.httpx.get

    def get(url, params=None, headers=None, timeout=None):
        if 'youtubeanalytics' in url:
            if sent['analytics_status'] != 200:
                return FakeResponse(sent['analytics_status'], {'error': {'errors': [{'reason': 'accessNotConfigured'}]}})
            return FakeResponse(200, {'columnHeaders': [{'name': 'views'}, {'name': 'estimatedMinutesWatched'}, {'name': 'subscribersGained'}],
                                      'rows': [[1500, 4200, 30]]})
        if headers and params.get('mine') == 'true':
            sent.setdefault('mine_calls', []).append(headers['Authorization'])
            return FakeResponse(200, {'items': [{'id': CHANNEL_ID, 'snippet': {'title': 'Acme TV', 'customUrl': '@acme'},
                                                 'statistics': {'subscriberCount': '1200', 'viewCount': '98000', 'videoCount': '40'},
                                                 'contentDetails': {'relatedPlaylists': {'uploads': 'UU123'}}}]})
        if headers and 'allThreadsRelatedToChannelId' in (params or {}):
            sent.setdefault('thread_calls', []).append(headers['Authorization'])
            return FakeResponse(200, {'items': [
                {'id': 'c9', 'snippet': {'videoId': 'v1', 'totalReplyCount': 0, 'topLevelComment': {'id': 'c9', 'snippet': {
                    'videoId': 'v1', 'textOriginal': 'Can you share pricing?', 'authorDisplayName': 'Ravi',
                    'authorChannelId': {'value': 'UCravi'}, 'publishedAt': '2026-10-18T08:00:00Z'}}}}]})
        return inner(url, params=params, headers=headers, timeout=timeout)

    monkeypatch.setattr(google_oauth.httpx, 'post', post)
    monkeypatch.setattr(youtube_account.httpx, 'post', post)
    monkeypatch.setattr(youtube_account.httpx, 'get', get)
    monkeypatch.setattr(youtube.httpx, 'get', get)
    return sent


def _sign_in(user='owner', granted=None):
    started = conn_router.oauth_start(conn_router.OAuthStartBody(provider='youtube_account'), user_id=user)
    state = started['url'].split('state=')[1].split('&')[0]
    from urllib.parse import unquote
    return conn_router.oauth_google_callback(code='auth-code', state=unquote(state))


def test_starting_a_sign_in_builds_the_google_address_with_a_signed_state(world, google):
    started = conn_router.oauth_start(conn_router.OAuthStartBody(provider='youtube_account'), user_id='owner')
    url = started['url']
    assert url.startswith(google_oauth.AUTH_URL) and 'client_id=client-id' in url and 'access_type=offline' in url
    assert 'youtube.force-ssl' in url and 'yt-analytics.readonly' in url
    assert 'client-secret' not in url
    assert 'redirect_uri=' in url and 'oauth%2Fgoogle%2Fcallback' in url


def test_only_a_manager_on_pro_can_start_a_sign_in(world, google):
    for user, status in (('member', 403), ('other', 403)):
        with pytest.raises(HTTPException) as err:
            conn_router.oauth_start(conn_router.OAuthStartBody(provider='youtube_account'), user_id=user)
        assert err.value.status_code == status


def test_a_sign_in_that_is_not_switched_on_says_so(world, monkeypatch):
    monkeypatch.delenv('GOOGLE_OAUTH_CLIENT_ID', raising=False)
    with pytest.raises(HTTPException) as err:
        conn_router.oauth_start(conn_router.OAuthStartBody(provider='youtube_account'), user_id='owner')
    assert err.value.status_code == 503


def test_sign_in_connectors_cannot_be_connected_with_a_form_and_form_ones_cannot_sign_in(world, google):
    with pytest.raises(HTTPException) as err:
        conn_router.connect(conn_router.ConnectBody(provider='youtube_account', inputs={}), user_id='owner')
    assert err.value.status_code == 400
    with pytest.raises(HTTPException) as err:
        conn_router.oauth_start(conn_router.OAuthStartBody(provider='youtube_public'), user_id='owner')
    assert err.value.status_code == 400


def test_approving_creates_the_connection_stores_the_token_encrypted_and_returns_to_the_app(world, google):
    response = _sign_in()
    assert response.status_code == 302 and response.headers['location'] == 'https://app.test/ventures/raptor/app/#/connections?connected=youtube_account'
    conn = world.tables['connections'][0]
    assert conn['provider'] == 'youtube_account' and conn['owner_id'] == 'org-1' and conn['created_by'] == 'owner' and conn['status'] == 'connected'
    stored = world.tables['connection_secrets'][0]['encrypted_secret']
    assert 'refresh-123' not in stored and 'refresh-123' in vault.decrypt_secret(stored)         # encrypted, not plain
    assert 'refresh-123' not in str(world.tables['connections']) and 'refresh-123' not in str(world.tables['signals'])
    names = {s['name'] for s in world.tables['signals']}
    assert {'subscribers', 'comment', 'views_28d', 'watch_minutes_28d', 'subs_gained_28d'} <= names
    comment = [s for s in world.tables['signals'] if s['name'] == 'comment'][0]
    assert comment['text_value'] == 'Can you share pricing?' and comment['entity']['comment_id'] == 'c9'
    assert google['mine_calls'] and set(google['mine_calls']) <= {'Bearer access-1', 'Bearer access-2'}   # acted as the person


def test_refusing_connects_nothing_and_says_why(world, google):
    response = conn_router.oauth_google_callback(code='', state='x', error='access_denied')
    assert 'oauth_error=' in response.headers['location'] and 'did+not+allow' in response.headers['location']
    assert world.tables.get('connections', []) == []


def test_a_forged_or_old_state_is_refused(world, google):
    response = conn_router.oauth_google_callback(code='c', state='not-a-real-state')
    assert 'oauth_error=' in response.headers['location'] and 'expired' in response.headers['location']
    assert world.tables.get('connections', []) == []
    token = vault.sign_state({'o': 'org-1', 'u': 'owner', 'p': 'youtube_account'})
    import time
    time.sleep(1.1)
    with pytest.raises(HTTPException):
        vault.read_state(token, max_age=0)


def test_a_person_who_lost_permission_before_approving_connects_nothing(world, google):
    started = conn_router.oauth_start(conn_router.OAuthStartBody(provider='youtube_account'), user_id='manager')
    from urllib.parse import unquote
    state = unquote(started['url'].split('state=')[1].split('&')[0])
    world.tables['org_members'][2]['permissions'] = {}
    response = conn_router.oauth_google_callback(code='c', state=state)
    assert 'oauth_error=' in response.headers['location'] and world.tables.get('connections', []) == []


def test_without_long_term_access_or_all_permissions_nothing_is_connected(world, google):
    google['refresh'] = None
    assert 'long-term' in _sign_in().headers['location'] or 'long-term' in _sign_in().headers['location'].replace('+', ' ')
    google['refresh'], google['granted_scope'] = 'r', 'https://www.googleapis.com/auth/yt-analytics.readonly'
    assert 'both' in _sign_in().headers['location'].replace('+', ' ')
    assert world.tables.get('connections', []) == []


def test_signing_in_again_updates_the_same_connection_instead_of_adding_one(world, google):
    _sign_in()
    google['refresh'] = 'refresh-NEW'
    _sign_in()
    assert len(world.tables['connections']) == 1 and len(world.tables['connection_secrets']) == 1
    assert 'refresh-NEW' in vault.decrypt_secret(world.tables['connection_secrets'][0]['encrypted_secret'])


def test_an_expired_google_approval_is_shown_as_needing_a_sign_in(world, google):
    _sign_in()
    world.tables['connections'][0]['last_sync_at'] = (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat()
    google['token_error'] = 'invalid_grant'
    with pytest.raises(HTTPException) as err:
        conn_router.sync_now(world.tables['connections'][0]['id'], user_id='owner')
    assert err.value.status_code == 422 and 'Sign in with Google again' in err.value.detail
    assert world.tables['connections'][0]['status'] == 'error'


def test_a_missing_analytics_service_is_explained(world, google):
    google['analytics_status'] = 403
    response = _sign_in()
    assert world.tables['connections'][0]['status'] == 'error'
    assert 'Analytics' in world.tables['connections'][0]['last_error']
    assert response.status_code == 302


# ───────────────────────── replying ─────────────────────────

def _signed_in_connection(world):
    _sign_in()
    return world.tables['connections'][0]['id']


def test_a_reply_is_posted_as_the_channel_and_recorded(world, google):
    cid = _signed_in_connection(world)
    result = conn_router.reply(cid, conn_router.ReplyBody(parent_id='c9', text='  Yes, pricing is on our site.  '), user_id='owner')
    assert result == {'ok': True, 'reply_id': 'reply-9'}
    url, data, body, params, headers = google['posts'][-1]
    assert url.endswith('/youtube/v3/comments') and body == {'snippet': {'parentId': 'c9', 'textOriginal': 'Yes, pricing is on our site.'}}
    assert headers['Authorization'] == 'Bearer access-2'
    event = [s for s in world.tables['signals'] if s['name'] == 'reply_sent'][0]
    assert event['kind'] == 'event' and event['entity']['parent_id'] == 'c9' and event['entity']['sent_by'] == 'owner'


def test_only_managers_can_reply_and_others_see_a_clear_refusal(world, google):
    cid = _signed_in_connection(world)
    with pytest.raises(HTTPException) as err:
        conn_router.reply(cid, conn_router.ReplyBody(parent_id='c9', text='hi'), user_id='member')
    assert err.value.status_code == 403
    assert not [p for p in google['posts'] if p[0].endswith('/comments')]
    assert conn_router.reply(cid, conn_router.ReplyBody(parent_id='c9', text='hi'), user_id='manager')['ok']


def test_an_empty_too_long_or_targetless_reply_is_refused_before_anything_is_sent(world, google):
    cid = _signed_in_connection(world)
    for body in (conn_router.ReplyBody(parent_id='c9', text='   '),
                 conn_router.ReplyBody(parent_id='c9', text='x' * (conn_router.MAX_REPLY_LENGTH + 1)),
                 conn_router.ReplyBody(parent_id=' ', text='hi')):
        with pytest.raises(HTTPException) as err:
            conn_router.reply(cid, body, user_id='owner')
        assert err.value.status_code == 400
    assert not [p for p in google['posts'] if p[0].endswith('/comments')]


def test_a_connection_without_reply_support_or_needing_attention_cannot_reply(world, google):
    created = _connect()['connection']
    with pytest.raises(HTTPException) as err:
        conn_router.reply(created['id'], conn_router.ReplyBody(parent_id='c1', text='hi'), user_id='owner')
    assert err.value.status_code == 400
    _sign_in()
    cid = world.tables['connections'][-1]['id']
    world.tables['connections'][-1]['status'] = 'error'
    with pytest.raises(HTTPException) as err:
        conn_router.reply(cid, conn_router.ReplyBody(parent_id='c9', text='hi'), user_id='owner')
    assert err.value.status_code in (404, 409)


def test_youtube_refusing_a_reply_is_reported_and_nothing_is_recorded(world, google):
    cid = _signed_in_connection(world)
    google['reply_status'] = 403
    with pytest.raises(HTTPException) as err:
        conn_router.reply(cid, conn_router.ReplyBody(parent_id='c9', text='hi'), user_id='owner')
    assert err.value.status_code == 422 and 'would not accept' in err.value.detail
    assert not [s for s in world.tables['signals'] if s['name'] == 'reply_sent']


def test_there_is_a_daily_limit_on_replies(world, google, monkeypatch):
    cid = _signed_in_connection(world)
    monkeypatch.setattr(conn_router, 'MAX_REPLIES_PER_DAY', 2)
    for n in range(2):
        google['posts'].clear()
        conn_router.reply(cid, conn_router.ReplyBody(parent_id=f'c{n}', text='hi'), user_id='owner')
        world.tables['signals'][-1]['dedupe_key'] = f'unique-{n}'
    with pytest.raises(HTTPException) as err:
        conn_router.reply(cid, conn_router.ReplyBody(parent_id='c5', text='hi'), user_id='owner')
    assert err.value.status_code == 429


def test_another_organization_cannot_reply_through_my_connection(world, google):
    cid = _signed_in_connection(world)
    with pytest.raises(HTTPException) as err:
        conn_router.reply(cid, conn_router.ReplyBody(parent_id='c9', text='hi'), user_id='other')
    assert err.value.status_code in (403, 404)


def test_disconnecting_a_signed_in_connection_withdraws_the_approval_at_google(world, google):
    cid = _signed_in_connection(world)
    conn_router.disconnect(cid, user_id='owner')
    assert google['revoked'] == ['refresh-123'] and world.tables['connections'] == [] and world.tables['connection_secrets'] == []


def test_the_provider_list_describes_sign_in_and_reply_support(world, google):
    listed = {p['provider']: p for p in conn_router.providers(user_id='member')['providers']}
    assert listed['youtube_account']['auth'] == 'oauth' and listed['youtube_account']['can_reply'] is True and listed['youtube_account']['available'] is True
    assert listed['youtube_public']['auth'] == 'none' and listed['youtube_public']['can_reply'] is False
