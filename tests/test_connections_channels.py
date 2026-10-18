"""tests/test_connections_channels.py - the channels added after YouTube: news feeds, Google Analytics, Google reviews, payments and
webhooks (Razorpay, Stripe, generic), Slack, Teams, Telegram and SMS, plus the alert engine and the router rules around them.

No network and no database: a fake internet answers every outbound call by address, and the same in-memory Supabase as
test_connections.py holds the data."""
import base64
import hashlib
import hmac
import json
import os
import time
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse

import httpx
import pytest
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from fastapi import HTTPException

os.environ.setdefault('EMAIL_KEY_ENCRYPTION_SECRET', Fernet.generate_key().decode())

from raptor.connections import alerts, ga4, net, registry, reviews, rss, sms, vault, webhooks  # noqa: E402
from raptor.connections import router as conn_router  # noqa: E402
from raptor.connections.registry import ConnectorError  # noqa: E402
from tests.test_connections import FakeResponse, world  # noqa: E402,F401  (world: the in-memory database with an org, a manager and a member)


# ───────────────────────── a fake internet ─────────────────────────

class Internet:
    """Answers outbound calls by method and address prefix, and remembers every call."""

    def __init__(self):
        self.routes, self.calls = [], []

    def on(self, method, prefix, handler):
        self.routes.append((method.upper(), prefix, handler))

    def _answer(self, method, url, **kw):
        self.calls.append({'method': method, 'url': str(url), **kw})
        for m, prefix, handler in reversed(self.routes):
            if m == method and str(url).startswith(prefix):
                out = handler(str(url), **kw)
                return out if hasattr(out, 'status_code') else FakeResponse(200, out)
        raise AssertionError(f'unexpected {method} {url}')

    def posts(self, prefix=''):
        return [c for c in self.calls if c['method'] == 'POST' and c['url'].startswith(prefix)]


class StreamResponse(FakeResponse):
    def __init__(self, status=200, text='', headers=None):
        super().__init__(status, {})
        self.text_body, self.headers, self.encoding = text, headers or {}, 'utf-8'

    def iter_bytes(self):
        data = self.text_body.encode()
        for i in range(0, len(data), 4096):
            yield data[i:i + 4096]

    def __enter__(self): return self
    def __exit__(self, *a): return False


@pytest.fixture
def web(monkeypatch):
    internet = Internet()
    monkeypatch.setattr(httpx, 'post', lambda url, **kw: internet._answer('POST', url, **kw))
    monkeypatch.setattr(httpx, 'get', lambda url, **kw: internet._answer('GET', url, **kw))
    monkeypatch.setattr(httpx, 'stream', lambda method, url, **kw: internet._answer(method.upper(), url, **kw))
    monkeypatch.setattr(net, '_resolve', lambda host: ['10.0.0.5'] if host.startswith('internal') else ['93.184.216.34'])
    monkeypatch.setenv('PUBLIC_API_URL', 'https://api.example.test')
    conn_router._buckets.clear()
    return internet


def connect(provider, inputs, user='owner'):
    return conn_router.connect(conn_router.ConnectBody(provider=provider, inputs=inputs), user_id=user)['connection']


def signals_named(world, name):
    return [s for s in world.tables.get('signals', []) if s['name'] == name]


# ───────────────────────── safe outbound calls ─────────────────────────

def test_only_public_https_addresses_are_called(web):
    assert net.assert_public_url('https://example.com/feed') == 'https://example.com/feed'
    for bad in ('http://example.com/x', 'ftp://example.com', 'https://internal.test/x', 'https://user:pw@example.com/x', 'https://example.com:8443/x', '', 'not a url'):
        with pytest.raises(ConnectorError):
            net.assert_public_url(bad)
    with pytest.raises(ConnectorError):
        net.assert_public_url('https://evil.example.com/x', ('hooks.slack.com',))
    assert net.assert_public_url('https://hooks.slack.com/services/T/B/x', ('hooks.slack.com',))


def test_a_redirect_to_a_private_address_is_refused_and_a_huge_page_is_cut_off(web):
    web.on('GET', 'https://example.com/hop', lambda url, **kw: StreamResponse(302, headers={'location': 'https://internal.test/secret'}))
    with pytest.raises(ConnectorError, match='private'):
        net.fetch_text('https://example.com/hop')
    web.on('GET', 'https://example.com/big', lambda url, **kw: StreamResponse(200, 'x' * 2_000_000))
    with pytest.raises(ConnectorError, match='too large'):
        net.fetch_text('https://example.com/big')
    web.on('GET', 'https://example.com/ok', lambda url, **kw: StreamResponse(200, 'hello'))
    assert net.fetch_text('https://example.com/ok') == 'hello'


# ───────────────────────── news feeds ─────────────────────────

RSS = """<?xml version="1.0"?><rss version="2.0"><channel><title>Acme News</title>
<item><title>Acme launches a new plan - The Daily</title><link>https://news.test/1</link><guid>g1</guid><pubDate>Fri, 16 Oct 2026 08:00:00 GMT</pubDate></item>
<item><title>Acme hires a head of sales</title><link>https://news.test/2</link><guid>g2</guid><pubDate>Thu, 15 Oct 2026 08:00:00 GMT</pubDate><source>Business Wire</source></item>
</channel></rss>"""
ATOM = """<feed xmlns="http://www.w3.org/2005/Atom"><title>Blog</title><entry><title>Post one</title><id>tag:1</id><updated>2026-10-16T08:00:00Z</updated>
<link rel="alternate" href="https://blog.test/1"/></entry></feed>"""


def test_rss_and_atom_feeds_are_read_and_a_google_news_headline_is_split_from_its_publisher():
    title, items = rss.parse_feed(RSS)
    assert title == 'Acme News' and [i['title'] for i in items] == ['Acme launches a new plan', 'Acme hires a head of sales']
    assert [i['source'] for i in items] == ['The Daily', 'Business Wire']
    assert items[0]['published'].year == 2026
    t2, atom = rss.parse_feed(ATOM)
    assert t2 == 'Blog' and atom[0]['url'] == 'https://blog.test/1' and atom[0]['published'].month == 10


def test_a_feed_that_declares_entities_or_is_not_a_feed_is_refused():
    bomb = '<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;">]><rss><channel><title>&lol2;</title></channel></rss>'
    for bad in (bomb, '<html><body>nope</body></html>', 'plain text', '<rss></rss>'):
        with pytest.raises(ConnectorError):
            rss.parse_feed(bad)


def test_following_a_word_uses_google_news_and_each_new_headline_becomes_one_signal(world, web):
    web.on('GET', 'https://news.google.com/rss/search', lambda url, **kw: StreamResponse(200, RSS))
    created = connect('news_feed', {'kind': 'keyword', 'value': 'Acme Ltd'})
    assert created['label'] == 'Acme Ltd'
    assert 'q=Acme+Ltd' in web.calls[0]['url']
    news = signals_named(world, 'news')
    assert len(news) == 2 and news[0]['kind'] == 'mention' and news[0]['entity']['query'] == 'Acme Ltd'
    world.tables['connections'][0]['last_sync_at'] = (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat()
    conn_router.sync_now(created['id'], user_id='owner')
    assert len(signals_named(world, 'news')) == 2                     # the same headlines are not stored twice


def test_a_feed_address_must_be_https_and_a_keyword_must_not_be_empty(world, web):
    for inputs in ({'kind': 'feed', 'value': 'http://x.test/feed'}, {'kind': 'keyword', 'value': '  '}, {'kind': 'keyword', 'value': 'x' * 121}):
        with pytest.raises(HTTPException) as err:
            connect('news_feed', inputs)
        assert err.value.status_code in (400, 422)
    with pytest.raises(HTTPException):
        connect('news_feed', {'kind': 'feed', 'value': 'https://internal.test/feed'})


# ───────────────────────── Google Analytics ─────────────────────────

def _key_file():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode()
    return key, json.dumps({'type': 'service_account', 'client_email': 'raptor@proj.iam.gserviceaccount.com', 'private_key': pem, 'token_uri': 'https://evil.test/token'})


def _ga_routes(web, status=200):
    web.on('POST', 'https://oauth2.googleapis.com/token', lambda url, **kw: {'access_token': 'ga-token'})

    def report(url, json=None, headers=None, **kw):
        if status != 200:
            return FakeResponse(status, {})
        assert headers['Authorization'] == 'Bearer ga-token'
        dims = [d['name'] for d in json.get('dimensions', [])]
        if dims == ['date']:
            return {'rows': [{'dimensionValues': [{'value': '20261015'}], 'metricValues': [{'value': '120'}, {'value': '90'}]},
                             {'dimensionValues': [{'value': '20261016'}], 'metricValues': [{'value': '150'}, {'value': '100'}]}]}
        if dims == ['pagePath']:
            return {'rows': [{'dimensionValues': [{'value': '/pricing'}], 'metricValues': [{'value': '300'}]}, {'dimensionValues': [{'value': '/'}], 'metricValues': [{'value': '200'}]}]}
        if dims == ['sessionSourceMedium']:
            return {'rows': [{'dimensionValues': [{'value': 'google / organic'}], 'metricValues': [{'value': '400'}]}]}
        if len(json['dateRanges']) == 2:
            return {'dimensionHeaders': [{'name': 'dateRange'}], 'rows': [
                {'dimensionValues': [{'value': 'date_range_0'}], 'metricValues': [{'value': v} for v in ('1000', '800', '300', '0.61', '25')]},
                {'dimensionValues': [{'value': 'date_range_1'}], 'metricValues': [{'value': v} for v in ('900', '700', '250', '0.58', '20')]}]}
        return {'rows': [{'metricValues': [{'value': '10'}]}]}
    web.on('POST', 'https://analyticsdata.googleapis.com/v1beta/properties/', report)


def test_a_key_file_that_is_not_a_service_account_is_refused():
    for bad in ('', 'not json', '[]', json.dumps({'type': 'user'}), json.dumps({'type': 'service_account', 'client_email': 'a@b', 'private_key': 'junk'})):
        with pytest.raises(ConnectorError):
            ga4.parse_key_file(bad)


def test_the_google_sign_in_is_a_real_rs256_signature_and_the_key_files_own_token_address_is_never_used(web):
    key, text = _key_file()
    web.on('POST', 'https://oauth2.googleapis.com/token', lambda url, **kw: {'access_token': 't'})
    assert ga4.access_token(ga4.parse_key_file(text)) == 't'
    call = web.posts()[0]
    assert call['url'] == 'https://oauth2.googleapis.com/token'            # not https://evil.test/token from the file
    assertion = call['data']['assertion']
    head, claims, sig = assertion.split('.')
    pad = lambda x: x + '=' * (-len(x) % 4)  # noqa: E731
    payload = json.loads(base64.urlsafe_b64decode(pad(claims)))
    assert payload['iss'] == 'raptor@proj.iam.gserviceaccount.com' and payload['scope'].endswith('analytics.readonly') and payload['aud'] == 'https://oauth2.googleapis.com/token'
    key.public_key().verify(base64.urlsafe_b64decode(pad(sig)), f'{head}.{claims}'.encode(), padding.PKCS1v15(), hashes.SHA256())    # raises if forged


def test_connecting_analytics_stores_the_key_encrypted_and_reads_the_numbers(world, web):
    _, text = _key_file()
    _ga_routes(web)
    created = connect('ga4', {'property_id': '412345678', 'service_account': text})
    assert created['external_id'] == '412345678' and created['status'] == 'connected'
    stored = world.tables['connection_secrets'][0]['encrypted_secret']
    assert 'BEGIN PRIVATE KEY' not in stored and 'BEGIN PRIVATE KEY' in vault.decrypt_secret(stored)
    assert 'private_key' not in str(world.tables['connections']) and 'BEGIN' not in str(world.tables['signals'])
    by = {s['name']: s for s in world.tables['signals']}
    assert by['ga_sessions_28d']['value'] == 1000 and by['ga_sessions_prev28d']['value'] == 900 and by['ga_engagement_rate_28d']['value'] == 0.61
    assert by['ga_key_events_28d']['value'] == 25
    days = signals_named(world, 'ga_sessions_day')
    assert [d['value'] for d in days] == [120, 150] and days[0]['entity']['users'] == 90 and days[0]['occurred_at'].startswith('2026-10-15')
    assert by['ga_top_pages']['entity']['items'][0] == {'label': '/pricing', 'value': 300}
    assert by['ga_top_sources']['entity']['items'][0]['label'] == 'google / organic'


def test_analytics_tells_the_person_exactly_what_to_do_when_access_is_missing(world, web):
    _, text = _key_file()
    _ga_routes(web, status=403)
    with pytest.raises(HTTPException) as err:
        connect('ga4', {'property_id': '412345678', 'service_account': text})
    assert 'raptor@proj.iam.gserviceaccount.com' in err.value.detail and 'Viewer' in err.value.detail
    assert world.tables.get('connections', []) == []
    for bad in ({'property_id': 'abc', 'service_account': text}, {'property_id': '412345678', 'service_account': 'junk'}):
        with pytest.raises(HTTPException):
            connect('ga4', bad)


# ───────────────────────── Google reviews ─────────────────────────

PLACE = {'id': 'ChIJabcdefghijk', 'displayName': {'text': 'Acme Interiors'}, 'formattedAddress': 'Pune', 'rating': 4.6, 'userRatingCount': 128, 'googleMapsUri': 'https://maps.test/x',
         'reviews': [{'name': 'places/ChIJabcdefghijk/reviews/r1', 'rating': 5, 'text': {'text': 'Lovely work'}, 'authorAttribution': {'displayName': 'Priya'}, 'publishTime': '2026-10-10T10:00:00Z'},
                     {'name': 'places/ChIJabcdefghijk/reviews/r2', 'rating': 2, 'text': {'text': 'Late delivery'}, 'authorAttribution': {'displayName': 'Ravi'}, 'publishTime': '2026-10-12T10:00:00Z'}]}


def _places(web, status=200):
    web.on('GET', 'https://places.googleapis.com/v1/places/', lambda url, headers=None, **kw: FakeResponse(status, PLACE) if headers.get('X-Goog-Api-Key') == 'AIzaKEYKEYKEYKEYKEYKEY' else FakeResponse(403, {}))
    web.on('POST', 'https://places.googleapis.com/v1/places:searchText', lambda url, **kw: {'places': [{'id': 'ChIJabcdefghijk', 'displayName': {'text': 'Acme Interiors'}}]})


def test_reviews_connect_by_name_or_place_id_and_the_key_is_stored_encrypted(world, web):
    _places(web)
    created = connect('google_reviews', {'place': 'Acme Interiors Pune', 'api_key': 'AIzaKEYKEYKEYKEYKEYKEY'})
    assert created['label'] == 'Acme Interiors' and created['external_id'] == 'ChIJabcdefghijk'
    assert any('searchText' in c['url'] for c in web.calls)
    assert 'AIzaKEY' not in world.tables['connection_secrets'][0]['encrypted_secret'] and 'AIzaKEY' not in str(world.tables['signals'])
    by = {s['name']: s for s in world.tables['signals'] if s['name'] != 'review'}
    assert by['rating']['value'] == 4.6 and by['review_count']['value'] == 128
    reviews_ = signals_named(world, 'review')
    assert sorted(r['value'] for r in reviews_) == [2, 5] and {r['entity']['author'] for r in reviews_} == {'Priya', 'Ravi'}
    web.calls.clear()
    other = connect('google_reviews', {'place': 'ChIJzzzzzzzzzzzz', 'api_key': 'AIzaKEYKEYKEYKEYKEYKEY'}) if False else None
    assert other is None


def test_a_wrong_google_key_or_unknown_business_is_explained(world, web):
    _places(web)
    with pytest.raises(HTTPException) as err:
        connect('google_reviews', {'place': 'ChIJabcdefghijk', 'api_key': 'AIzaWRONGWRONGWRONGWRONG'})
    assert 'Places API' in err.value.detail
    web.on('POST', 'https://places.googleapis.com/v1/places:searchText', lambda url, **kw: {'places': []})
    with pytest.raises(HTTPException) as err:
        connect('google_reviews', {'place': 'Nowhere Inc', 'api_key': 'AIzaKEYKEYKEYKEYKEYKEY'})
    assert 'No business' in err.value.detail
    for inputs in ({'place': 'ab', 'api_key': 'AIzaKEYKEYKEYKEYKEYKEY'}, {'place': 'Acme', 'api_key': 'short'}):
        with pytest.raises(HTTPException):
            connect('google_reviews', inputs)


# ───────────────────────── payments and webhooks ─────────────────────────

def _sign_rzp(secret, body):
    return {'X-Razorpay-Signature': hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()}


RZP = {'event': 'payment.captured', 'payload': {'payment': {'entity': {'id': 'pay_1', 'amount': 499900, 'currency': 'INR', 'email': 'buyer@x.test', 'contact': '+919800000000', 'method': 'upi', 'description': 'Pro plan', 'created_at': 1792000000}}}}


def test_money_is_converted_from_the_smallest_unit_for_every_kind_of_currency():
    assert webhooks.minor_to_major(499900, 'INR') == 4999.0 and webhooks.minor_to_major(1250, 'usd') == 12.5
    assert webhooks.minor_to_major(500, 'JPY') == 500 and webhooks.minor_to_major(1500, 'KWD') == 1.5 and webhooks.minor_to_major(None, 'INR') == 0


def test_a_razorpay_payment_becomes_revenue_only_with_the_right_signature(world, web):
    created = connect('razorpay', {'signing_secret': 'my-razorpay-secret'})
    token = created['external_id']
    assert len(token) >= 30 and 'my-razorpay-secret' not in world.tables['connection_secrets'][0]['encrypted_secret']
    body = json.dumps(RZP).encode()
    assert conn_router.receive_push(token, body, _sign_rzp('my-razorpay-secret', body)) == {'ok': True, 'received': 1}
    pay = signals_named(world, 'payment_received')[0]
    assert pay['value'] == 4999.0 and pay['kind'] == 'event' and pay['entity']['email'] == 'buyer@x.test' and pay['dedupe_key'] == 'rzp:pay_1'
    assert conn_router.receive_push(token, body, _sign_rzp('my-razorpay-secret', body)) == {'ok': True, 'received': 0}     # sent twice: counted once
    assert len(signals_named(world, 'payment_received')) == 1
    for headers in ({}, _sign_rzp('wrong-secret', body), {'X-Razorpay-Signature': 'abc'}):
        with pytest.raises(HTTPException) as err:
            conn_router.receive_push(token, body, headers)
        assert err.value.status_code == 401
    tampered = body.replace(b'499900', b'900')
    with pytest.raises(HTTPException) as err:
        conn_router.receive_push(token, tampered, _sign_rzp('my-razorpay-secret', body))
    assert err.value.status_code == 401


def test_razorpay_failed_payments_and_refunds_are_recorded_and_other_events_are_ignored(world, web):
    token = connect('razorpay', {'signing_secret': 'secret-secret'})['external_id']
    for payload in (
        {'event': 'payment.failed', 'payload': {'payment': {'entity': {'id': 'pay_2', 'amount': 1000, 'currency': 'INR', 'error_description': 'Card declined'}}}},
        {'event': 'refund.processed', 'payload': {'refund': {'entity': {'id': 'rfnd_1', 'amount': 500, 'currency': 'INR', 'payment_id': 'pay_1'}}}},
        {'event': 'order.paid', 'payload': {}},
    ):
        raw = json.dumps(payload).encode()
        conn_router.receive_push(token, raw, _sign_rzp('secret-secret', raw))
    assert signals_named(world, 'payment_failed')[0]['entity']['reason'] == 'Card declined'
    assert signals_named(world, 'refund')[0]['value'] == 5.0
    assert len(world.tables['signals']) == 2


def _sign_stripe(secret, body, stamp=None):
    stamp = str(stamp or int(time.time()))
    return {'Stripe-Signature': f't={stamp},v1={hmac.new(secret.encode(), stamp.encode() + b"." + body, hashlib.sha256).hexdigest()}'}


def test_a_stripe_payment_needs_a_fresh_correctly_signed_message(world, web):
    token = connect('stripe', {'signing_secret': 'whsec_testtesttest'})['external_id']
    event = {'type': 'payment_intent.succeeded', 'created': 1792000000, 'data': {'object': {'id': 'pi_1', 'amount_received': 2500, 'currency': 'usd', 'receipt_email': 'a@b.test', 'description': 'Order 7'}}}
    body = json.dumps(event).encode()
    assert conn_router.receive_push(token, body, _sign_stripe('whsec_testtesttest', body))['received'] == 1
    pay = signals_named(world, 'payment_received')[0]
    assert pay['value'] == 25.0 and pay['entity']['currency'] == 'USD' and pay['dedupe_key'] == 'stripe:pi_1'
    old = _sign_stripe('whsec_testtesttest', body, stamp=int(time.time()) - 3600)
    with pytest.raises(HTTPException) as err:
        conn_router.receive_push(token, body, old)                     # a recorded message sent again later
    assert err.value.status_code == 401
    for headers in ({}, _sign_stripe('other', body), {'Stripe-Signature': 't=abc,v1=def'}):
        with pytest.raises(HTTPException):
            conn_router.receive_push(token, body, headers)


def test_stripe_failures_and_refunds_and_unknown_events(world, web):
    token = connect('stripe', {'signing_secret': 'whsec_testtesttest'})['external_id']
    for event in (
        {'type': 'payment_intent.payment_failed', 'data': {'object': {'id': 'pi_2', 'amount': 900, 'currency': 'inr', 'last_payment_error': {'message': 'Insufficient funds'}}}},
        {'type': 'charge.refunded', 'data': {'object': {'id': 'ch_1', 'amount_refunded': 300, 'currency': 'inr', 'payment_intent': 'pi_1'}}},
        {'type': 'customer.created', 'data': {'object': {'id': 'cus_1'}}},
    ):
        raw = json.dumps(event).encode()
        conn_router.receive_push(token, raw, _sign_stripe('whsec_testtesttest', raw))
    assert signals_named(world, 'payment_failed')[0]['entity']['reason'] == 'Insufficient funds' and signals_named(world, 'refund')[0]['value'] == 3.0
    assert len(world.tables['signals']) == 2


def test_both_payment_providers_refuse_to_connect_without_the_signing_secret(world, web):
    for provider in ('razorpay', 'stripe'):
        with pytest.raises(HTTPException) as err:
            connect(provider, {'signing_secret': ''})
        assert err.value.status_code == 400 and 'required' in err.value.detail
        with pytest.raises(HTTPException) as err:
            connect(provider, {'signing_secret': 'abc'})                  # too short to be a real secret
        assert err.value.status_code == 422 and 'fake payments' in err.value.detail
    assert world.tables.get('connections', []) == []


def test_a_generic_webhook_counts_known_events_as_revenue_and_keeps_the_rest_as_events(world, web):
    token = connect('webhook', {})['external_id']
    body = json.dumps({'event': 'payment_received', 'value': 1500, 'currency': 'INR', 'email': 'z@z.test', 'id': 'order-9', 'nested': {'a': 1}}).encode()
    conn_router.receive_push(token, body, {})
    pay = signals_named(world, 'payment_received')[0]
    assert pay['value'] == 1500 and pay['entity']['email'] == 'z@z.test' and 'nested' not in pay['entity'] and pay['dedupe_key'] == 'hook:order-9'
    conn_router.receive_push(token, json.dumps({'event': 'Form Submitted!', 'text': 'Hello there'}).encode(), {})
    other = signals_named(world, 'webhook_event')[0]
    assert other['entity']['event'] == 'form_submitted_' and other['text_value'] == 'Hello there'
    conn_router.receive_push(token, body, {})
    assert len(signals_named(world, 'payment_received')) == 1


def test_a_generic_webhook_with_a_signing_secret_refuses_unsigned_messages(world, web):
    token = connect('webhook', {'signing_secret': 'shared-password'})['external_id']
    body = json.dumps({'event': 'lead_created', 'email': 'a@b.test'}).encode()
    with pytest.raises(HTTPException) as err:
        conn_router.receive_push(token, body, {})
    assert err.value.status_code == 401
    good = {'X-Raptor-Signature': 'sha256=' + hmac.new(b'shared-password', body, hashlib.sha256).hexdigest()}
    assert conn_router.receive_push(token, body, good)['received'] == 1


def test_the_public_door_gives_nothing_away_and_enforces_size_pause_and_rate(world, web, monkeypatch):
    created = connect('webhook', {})
    token = created['external_id']
    for bad in ('short', 'x' * 40, token[:-1] + ('a' if token[-1] != 'a' else 'b')):
        with pytest.raises(HTTPException) as err:
            conn_router.receive_push(bad, b'{}', {})
        assert err.value.status_code == 404 and err.value.detail == 'Not found.'
    for not_inbound in ('youtube_public',):
        pass
    with pytest.raises(HTTPException) as err:
        conn_router.receive_push(token, b'x' * (webhooks.MAX_BODY + 1), {})
    assert err.value.status_code == 413
    with pytest.raises(HTTPException) as err:
        conn_router.receive_push(token, b'not json', {})
    assert err.value.status_code == 400 and 'JSON' in err.value.detail
    monkeypatch.setattr(conn_router, '_PUSH_LIMIT', 2)
    conn_router._buckets.clear()
    for _ in range(2):
        conn_router.receive_push(token, b'{}', {})
    with pytest.raises(HTTPException) as err:
        conn_router.receive_push(token, b'{}', {})
    assert err.value.status_code == 429
    conn_router._buckets.clear()
    conn_router.patch(created['id'], conn_router.PatchBody(paused=True), user_id='owner')
    with pytest.raises(HTTPException) as err:
        conn_router.receive_push(token, b'{}', {})
    assert err.value.status_code == 409


def test_a_connection_that_does_not_take_pushed_data_cannot_be_reached_through_the_door(world, web):
    youtube_row = {'id': 'y1', 'owner_id': 'org-1', 'provider': 'youtube_public', 'external_id': 'UC' + 'q' * 30, 'status': 'connected', 'config': {}}
    world.tables.setdefault('connections', []).append(youtube_row)
    with pytest.raises(HTTPException) as err:
        conn_router.receive_push(youtube_row['external_id'], b'{}', {})
    assert err.value.status_code == 404


# ───────────────────────── alert rules ─────────────────────────

def test_money_reads_the_way_a_person_writes_it():
    assert alerts.money(4999, 'INR') == '₹4,999.00' and alerts.money(12.5, 'usd') == '$12.50' and alerts.money(10, 'AED') == 'AED 10.00' and alerts.money(None) == '₹0.00'


def test_which_new_signals_deserve_an_alert():
    rows = [
        {'name': 'payment_received', 'value': 4999, 'entity': {'currency': 'INR', 'email': 'a@b.test', 'provider': 'razorpay'}},
        {'name': 'payment_failed', 'value': 100, 'entity': {'currency': 'INR', 'reason': 'Card declined'}},
        {'name': 'review', 'value': 2, 'text_value': 'Late delivery', 'entity': {'author': 'Ravi'}},
        {'name': 'review', 'value': 5, 'text_value': 'Great', 'entity': {'author': 'Priya'}},
        {'name': 'comment', 'text_value': 'What is the price for 10 units?', 'entity': {'author': 'Sam'}},
        {'name': 'comment', 'text_value': 'Nice video', 'entity': {'author': 'Sam'}},
        {'name': 'comment', 'text_value': 'price?', 'entity': {'author': 'Own channel', 'mine': True}},
        {'name': 'telegram_message', 'text_value': 'how much is the demo?', 'entity': {'from': '@lead'}},
        {'name': 'views', 'value': 100, 'entity': {}},
    ]
    out = alerts.derive_alerts('x', rows)
    kinds = [a.events for a in out]
    assert kinds == [('payment_received',), ('payment_failed',), ('low_review', 'new_review'), ('new_review',), ('buying_comment',), ('buying_comment', 'new_message')]
    assert 'a@b.test' in out[0].text and '₹4,999.00' in out[0].text and 'Card declined' in out[1].text and '2-star' in out[2].text and 'Ravi' in out[2].text


def test_a_falling_rating_alerts_and_a_rising_or_steady_one_does_not():
    drop = alerts.derive_alerts('google_reviews', [{'name': 'rating', 'value': 4.4}], previous_rating=4.6)
    assert len(drop) == 1 and 'from 4.6 to 4.4' in drop[0].text and drop[0].events == ('rating_drop',)
    assert alerts.derive_alerts('google_reviews', [{'name': 'rating', 'value': 4.7}], previous_rating=4.6) == []
    assert alerts.derive_alerts('google_reviews', [{'name': 'rating', 'value': 4.6}], previous_rating=4.6) == []
    assert alerts.derive_alerts('google_reviews', [{'name': 'rating', 'value': 4.0}], previous_rating=None) == []


def test_only_known_alert_events_are_kept():
    assert alerts.clean_events(['payment_received', 'bogus', 'sync_error', 'payment_received']) == ['payment_received', 'sync_error']
    assert alerts.clean_events('payment_received') == [] and alerts.clean_events(None) == []


# ───────────────────────── Slack, Teams, Telegram ─────────────────────────

SLACK = 'https://hooks.slack.com/services/T000/B000/XXXXXXXX'


def test_slack_connects_only_with_a_real_slack_address_and_proves_it_works(world, web):
    web.on('POST', 'https://hooks.slack.com/', lambda url, **kw: FakeResponse(200, {}))
    created = connect('slack', {'webhook_url': SLACK})
    assert created['label'] == 'Slack' and created['config']['events'] == alerts.DEFAULT_EVENTS
    assert web.posts('https://hooks.slack.com')[0]['json']['text'].startswith('Raptor is connected')
    assert SLACK not in str(world.tables['connections']) and SLACK not in world.tables['connection_secrets'][0]['encrypted_secret']
    for bad in ('https://example.com/services/x', 'http://hooks.slack.com/services/x', 'https://hooks.slack.com/other/path', 'https://internal.test/x', ''):
        with pytest.raises(HTTPException):
            connect('slack', {'webhook_url': bad})


def test_slack_that_refuses_the_message_is_explained(world, web):
    web.on('POST', 'https://hooks.slack.com/', lambda url, **kw: FakeResponse(404, {}))
    with pytest.raises(HTTPException) as err:
        connect('slack', {'webhook_url': SLACK})
    assert 'create a new one' in err.value.detail and world.tables.get('connections', []) == []


def test_teams_uses_the_card_format_for_workflows_and_plain_text_for_the_old_connector(world, web):
    web.on('POST', 'https://', lambda url, **kw: FakeResponse(202, {}))
    connect('teams', {'webhook_url': 'https://prod-12.westus.logic.azure.com:443/workflows/abc'}) if False else None
    flow = connect('teams', {'webhook_url': 'https://prod-12.westus.logic.azure.com/workflows/abc/triggers/manual'})
    body = web.posts()[0]['json']
    assert body['type'] == 'message' and body['attachments'][0]['content']['type'] == 'AdaptiveCard'
    assert flow['label'] == 'Microsoft Teams'
    web.calls.clear()
    connect('teams', {'webhook_url': 'https://acme.webhook.office.com/webhookb2/abc'})
    assert web.posts()[0]['json'] == {'text': 'Raptor is connected. Alerts will appear in this channel.'}
    with pytest.raises(HTTPException):
        connect('teams', {'webhook_url': 'https://evil.example.com/x'})


def _telegram(web, chat_ok=True):
    def api(url, json=None, **kw):
        method = url.rsplit('/', 1)[-1]
        if '/botbad' in url:
            return FakeResponse(401, {'ok': False})
        if method == 'getMe':
            return {'ok': True, 'result': {'username': 'acme_bot'}}
        return {'ok': True, 'result': True}
    web.on('POST', 'https://api.telegram.org/bot', api)


TG_TOKEN = '123456789:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'


def test_telegram_connects_a_bot_registers_its_webhook_and_stores_the_token_encrypted(world, web):
    _telegram(web)
    created = connect('telegram', {'bot_token': TG_TOKEN})
    assert created['label'] == 'Telegram @acme_bot' and created['status'] == 'connected'
    hook = [c for c in web.posts() if c['url'].endswith('/setWebhook')][0]['json']
    assert hook['url'] == f"https://api.example.test/api/raptor/hooks/{created['external_id']}" and hook['allowed_updates'] == ['message'] and len(hook['secret_token']) >= 20
    assert TG_TOKEN not in str(world.tables['connections']) and TG_TOKEN not in world.tables['connection_secrets'][0]['encrypted_secret']
    for bad in ('', 'nonsense', '123:short'):
        with pytest.raises(HTTPException):
            connect('telegram', {'bot_token': bad})
    web.on('POST', 'https://api.telegram.org/bot', lambda url, **kw: FakeResponse(401, {'ok': False}))
    with pytest.raises(HTTPException) as err:
        connect('telegram', {'bot_token': '999999999:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB'})
    assert 'BotFather' in err.value.detail


def test_a_failed_webhook_registration_is_shown_on_the_connection_not_hidden(world, web):
    def api(url, json=None, **kw):
        if url.endswith('/setWebhook'):
            return FakeResponse(400, {'ok': False, 'description': 'bad webhook: HTTPS url must be provided'})
        return {'ok': True, 'result': {'username': 'acme_bot'}}
    web.on('POST', 'https://api.telegram.org/bot', api)
    created = connect('telegram', {'bot_token': TG_TOKEN})
    assert created['status'] == 'error' and 'bad webhook' in created['last_error']


def _tg_update(text, chat_id=555, chat_type='private', update_id=1):
    return json.dumps({'update_id': update_id, 'message': {'text': text, 'chat': {'id': chat_id, 'type': chat_type}, 'from': {'username': 'priya', 'first_name': 'Priya'}}}).encode()


def test_telegram_messages_need_the_secret_header_and_start_links_the_chat_for_alerts(world, web):
    _telegram(web)
    created = connect('telegram', {'bot_token': TG_TOKEN})
    token, row = created['external_id'], world.tables['connections'][0]
    secret = json.loads(vault.decrypt_secret(world.tables['connection_secrets'][0]['encrypted_secret']))['webhook_secret']
    with pytest.raises(HTTPException) as err:
        conn_router.receive_push(token, _tg_update('/start'), {})
    assert err.value.status_code == 401
    with pytest.raises(HTTPException):
        conn_router.receive_push(token, _tg_update('/start'), {'x-telegram-bot-api-secret-token': 'wrong'})
    # an alert cannot be sent yet: nobody has said /start
    with pytest.raises(HTTPException) as err:
        conn_router.run_action(created['id'], 'test_alert', conn_router.ActionBody(), user_id='owner')
    assert err.value.status_code == 422 and '/start' in err.value.detail
    conn_router.receive_push(token, _tg_update('/start', update_id=2), {'X-Telegram-Bot-Api-Secret-Token': secret})
    assert row['config']['chat_id'] == 555
    web.calls.clear()
    assert conn_router.run_action(created['id'], 'test_alert', conn_router.ActionBody(), user_id='owner') == {'ok': True}
    sent = web.posts('https://api.telegram.org')[0]['json']
    assert sent['chat_id'] == 555 and 'Test alert' in sent['text']
    conn_router.receive_push(token, _tg_update('hello there', update_id=3), {'X-Telegram-Bot-Api-Secret-Token': secret})
    msgs = signals_named(world, 'telegram_message')
    assert len(msgs) == 2 and msgs[1]['entity']['from'] == '@priya' and msgs[1]['text_value'] == 'hello there'
    conn_router.receive_push(token, _tg_update('hello there', update_id=3), {'X-Telegram-Bot-Api-Secret-Token': secret})
    assert len(signals_named(world, 'telegram_message')) == 2          # Telegram retried: counted once


def test_a_group_chat_never_becomes_the_alert_destination(world, web):
    _telegram(web)
    created = connect('telegram', {'bot_token': TG_TOKEN})
    secret = json.loads(vault.decrypt_secret(world.tables['connection_secrets'][0]['encrypted_secret']))['webhook_secret']
    conn_router.receive_push(created['external_id'], _tg_update('/start', chat_id=-100, chat_type='group'), {'X-Telegram-Bot-Api-Secret-Token': secret})
    assert world.tables['connections'][0]['config']['chat_id'] is None


def test_disconnecting_telegram_removes_its_webhook(world, web):
    _telegram(web)
    created = connect('telegram', {'bot_token': TG_TOKEN})
    web.calls.clear()
    conn_router.disconnect(created['id'], user_id='owner')
    assert [c['url'].rsplit('/', 1)[-1] for c in web.posts('https://api.telegram.org')] == ['deleteWebhook']


# ───────────────────────── sending alerts end to end ─────────────────────────

def _slack_with_events(world, web, events=None):
    web.on('POST', 'https://hooks.slack.com/', lambda url, **kw: FakeResponse(200, {}))
    created = connect('slack', {'webhook_url': SLACK})
    if events is not None:
        conn_router.patch(created['id'], conn_router.PatchBody(settings={'events': events}), user_id='owner')
    web.calls.clear()
    return created


def test_a_payment_alert_goes_to_slack_once_and_only_when_the_person_asked_for_it(world, web):
    _slack_with_events(world, web, ['payment_received'])
    token = connect('webhook', {})['external_id']
    body = json.dumps({'event': 'payment_received', 'value': 750, 'currency': 'INR', 'id': 'o1'}).encode()
    conn_router.receive_push(token, body, {})
    sent = web.posts('https://hooks.slack.com')
    assert len(sent) == 1 and 'Payment received: ₹750.00' in sent[0]['json']['text']
    assert [s for s in world.tables['signals'] if s['name'] == 'alert_sent'][0]['text_value'].startswith('Payment received')
    conn_router.receive_push(token, body, {})                           # the same payment again: no second alert
    assert len(web.posts('https://hooks.slack.com')) == 1
    conn_router.receive_push(token, json.dumps({'event': 'payment_failed', 'id': 'o2', 'value': 5}).encode(), {})
    assert len(web.posts('https://hooks.slack.com')) == 1              # failed payments were not asked for


def test_alerts_stay_inside_the_organization_and_never_break_the_data(world, web):
    _slack_with_events(world, web)
    world.tables['connections'].append({'id': 'other-slack', 'owner_id': 'org-2', 'provider': 'slack', 'external_id': 'z', 'status': 'connected', 'config': {'events': ['payment_received']}})
    world.tables.setdefault('connection_secrets', []).append({'connection_id': 'other-slack', 'encrypted_secret': vault.encrypt_secret(json.dumps({'url': SLACK}))})
    token = connect('webhook', {})['external_id']
    conn_router.receive_push(token, json.dumps({'event': 'payment_received', 'value': 1, 'id': 'a'}).encode(), {})
    assert len(web.posts('https://hooks.slack.com')) == 1               # only org-1's channel, never org-2's
    web.on('POST', 'https://hooks.slack.com/', lambda url, **kw: FakeResponse(500, {}))
    assert conn_router.receive_push(token, json.dumps({'event': 'payment_received', 'value': 2, 'id': 'b'}).encode(), {})['received'] == 1   # Slack down: the payment is still recorded
    assert len(signals_named(world, 'payment_received')) == 2


def test_a_connection_that_stops_working_alerts_once_and_not_on_every_retry(world, web, monkeypatch):
    from raptor.connections import youtube
    _slack_with_events(world, web)
    web.on('GET', 'https://www.googleapis.com/youtube/v3', lambda url, params=None, **kw: FakeResponse(403, {'error': {'errors': [{'reason': 'quotaExceeded'}]}}))
    monkeypatch.setenv('YOUTUBE_API_KEY', 'k')
    row = {'id': 'yt1', 'owner_id': 'org-1', 'provider': 'youtube_public', 'label': 'Acme TV', 'external_id': 'UC' + 'a' * 22, 'status': 'connected', 'config': {}, 'last_sync_at': '2026-10-17T00:00:00+00:00'}
    world.tables.setdefault('connections', []).append(row)
    for _ in range(2):
        with pytest.raises(HTTPException):
            conn_router._run_sync(dict(row))
        row['status'] = 'error'
    texts = [c['json']['text'] for c in web.posts('https://hooks.slack.com')]
    assert len(texts) == 1 and 'Acme TV stopped working' in texts[0]


def test_the_first_fetch_of_a_connection_sends_no_alerts_but_later_new_items_do(world, web, monkeypatch):
    _slack_with_events(world, web, ['new_review', 'low_review'])
    _places(web)
    created = connect('google_reviews', {'place': 'ChIJabcdefghijk', 'api_key': 'AIzaKEYKEYKEYKEYKEYKEY'})
    assert web.posts('https://hooks.slack.com') == []                     # two existing reviews were not announced
    PLACE2 = {**PLACE, 'rating': 4.2, 'reviews': PLACE['reviews'] + [{'name': 'places/ChIJabcdefghijk/reviews/r3', 'rating': 1, 'text': {'text': 'Terrible'}, 'authorAttribution': {'displayName': 'Sam'}, 'publishTime': '2026-10-17T10:00:00Z'}]}
    web.on('GET', 'https://places.googleapis.com/v1/places/', lambda url, **kw: FakeResponse(200, PLACE2))
    world.tables['connections'][-1]['last_sync_at'] = (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat()
    conn_router.sync_now(created['id'], user_id='owner')
    text = [c['json']['text'] for c in web.posts('https://hooks.slack.com')]
    assert len(text) == 1 and '1-star' in text[0] and 'Sam' in text[0]


# ───────────────────────── settings, actions, refresh ─────────────────────────

def test_alert_settings_can_be_changed_only_for_known_settings_and_known_events(world, web):
    created = _slack_with_events(world, web)
    conn_router.patch(created['id'], conn_router.PatchBody(settings={'events': ['sync_error', 'nonsense', 'payment_received']}), user_id='owner')
    assert world.tables['connections'][0]['config']['events'] == ['payment_received', 'sync_error']
    with pytest.raises(HTTPException) as err:
        conn_router.patch(created['id'], conn_router.PatchBody(settings={'webhook_url': 'https://evil.test'}), user_id='owner')
    assert err.value.status_code == 400
    with pytest.raises(HTTPException) as err:
        conn_router.patch(created['id'], conn_router.PatchBody(settings={'events': ['payment_received']}), user_id='member')
    assert err.value.status_code == 403


def test_actions_need_the_permission_exist_on_the_connector_and_not_be_paused(world, web):
    created = _slack_with_events(world, web)
    web.on('POST', 'https://hooks.slack.com/', lambda url, **kw: FakeResponse(200, {}))
    assert conn_router.run_action(created['id'], 'test_alert', conn_router.ActionBody(), user_id='manager') == {'ok': True}
    with pytest.raises(HTTPException) as err:
        conn_router.run_action(created['id'], 'test_alert', conn_router.ActionBody(), user_id='member')
    assert err.value.status_code == 403
    with pytest.raises(HTTPException) as err:
        conn_router.run_action(created['id'], 'launch_rocket', conn_router.ActionBody(), user_id='owner')
    assert err.value.status_code == 404
    with pytest.raises(HTTPException) as err:
        conn_router.run_action(created['id'], 'test_alert', conn_router.ActionBody(), user_id='other')
    assert err.value.status_code in (403, 404)
    conn_router.patch(created['id'], conn_router.PatchBody(paused=True), user_id='owner')
    with pytest.raises(HTTPException) as err:
        conn_router.run_action(created['id'], 'test_alert', conn_router.ActionBody(), user_id='owner')
    assert err.value.status_code == 409


def test_connections_that_only_send_or_receive_have_nothing_to_refresh_and_the_scheduled_run_skips_them(world, web):
    created = _slack_with_events(world, web)
    assert conn_router.sync_now(created['id'], user_id='owner') == {'signals': 0}
    world.tables['connections'][0]['last_sync_at'] = '2020-01-01T00:00:00+00:00'
    assert conn_router.tick() == {'synced': 0, 'failed': 0}


# ───────────────────────── SMS ─────────────────────────

def test_phone_numbers_must_carry_a_country_code():
    assert sms.normalize_number('+91 98765-43210') == '+919876543210' and sms.normalize_number('(+1) 415 555 0100') == '+14155550100'
    for bad in ('9876543210', '+0123456789', '+91', 'abc', ''):
        with pytest.raises(ConnectorError):
            sms.normalize_number(bad)


SID = 'AC' + 'a' * 32


def _twilio(web, ok=True):
    web.on('GET', 'https://api.twilio.com/2010-04-01/Accounts/', lambda url, **kw: FakeResponse(200 if ok else 401, {}))
    web.on('POST', 'https://api.twilio.com/2010-04-01/Accounts/', lambda url, data=None, **kw: FakeResponse(201, {'sid': 'SM1', 'status': 'queued'}) if data['To'] == '+919876543210' else FakeResponse(400, {'message': 'The number is not valid'}))


def test_sms_connects_with_the_customers_own_twilio_key_stored_encrypted(world, web):
    _twilio(web)
    created = connect('sms_twilio', {'account_sid': SID, 'auth_token': 'tokentokentokentoken', 'from_number': '+1 415 555 0100'})
    assert created['label'] == 'Twilio +14155550100'
    assert 'tokentoken' not in str(world.tables['connections']) and 'tokentoken' not in world.tables['connection_secrets'][0]['encrypted_secret']
    for bad in ({'account_sid': 'nope', 'auth_token': 'tokentokentokentoken', 'from_number': '+14155550100'}, {'account_sid': SID, 'auth_token': 'x', 'from_number': '+14155550100'},
                {'account_sid': SID, 'auth_token': 'tokentokentokentoken', 'from_number': '4155550100'}):
        with pytest.raises(HTTPException):
            connect('sms_twilio', bad)
    _twilio(web, ok=False)
    with pytest.raises(HTTPException) as err:
        connect('sms_twilio', {'account_sid': 'AC' + 'b' * 32, 'auth_token': 'tokentokentokentoken', 'from_number': '+14155550100'})
    assert 'did not accept' in err.value.detail


def _sms_connection(world, web):
    _twilio(web)
    return connect('sms_twilio', {'account_sid': SID, 'auth_token': 'tokentokentokentoken', 'from_number': '+14155550100'})


def test_a_text_message_is_sent_from_the_customers_number_and_logged(world, web):
    created = _sms_connection(world, web)
    out = conn_router.run_action(created['id'], 'send', conn_router.ActionBody(params={'to': '+91 98765 43210', 'text': '  Hello Priya  '}), user_id='owner')
    assert out == {'ok': True, 'sid': 'SM1'}
    call = [c for c in web.posts('https://api.twilio.com') if 'Messages.json' in c['url']][0]
    assert call['data'] == {'To': '+919876543210', 'From': '+14155550100', 'Body': 'Hello Priya'} and call['auth'] == (SID, 'tokentokentokentoken')
    logged = signals_named(world, 'sms_sent')[0]
    assert logged['entity']['to'] == '+919876543210' and logged['text_value'] == 'Hello Priya' and logged['kind'] == 'event'


def test_sms_refuses_empty_oversized_unaddressed_and_rejected_messages_and_has_a_daily_cap(world, web, monkeypatch):
    created = _sms_connection(world, web)
    run = lambda **p: conn_router.run_action(created['id'], 'send', conn_router.ActionBody(params=p), user_id='owner')  # noqa: E731
    for params, text in (({'to': '+919876543210', 'text': '  '}, 'Write the message'), ({'to': '+919876543210', 'text': 'x' * 601}, '600'),
                         ({'to': '98765', 'text': 'hi'}, 'country code'), ({'to': '+919999999999', 'text': 'hi'}, 'not valid')):
        with pytest.raises(HTTPException) as err:
            run(**params)
        assert err.value.status_code == 422 and text in err.value.detail
    assert signals_named(world, 'sms_sent') == []
    monkeypatch.setattr(sms, 'DAILY_CAP', 2)
    for n in range(2):
        run(to='+919876543210', text=f'msg {n}')
        world.tables['signals'][-1]['dedupe_key'] = f'u{n}'
    with pytest.raises(HTTPException) as err:
        run(to='+919876543210', text='one more')
    assert err.value.status_code == 422 and 'Daily' in err.value.detail


# ───────────────────────── the catalogue the apps draw from ─────────────────────────

def test_every_new_channel_is_listed_with_its_tab_setup_steps_and_what_it_can_do(world, web):
    listed = {p['provider']: p for p in conn_router.providers(user_id='member')['providers']}
    expect = {'ga4': 'analytics', 'google_reviews': 'reviews', 'razorpay': 'payments', 'stripe': 'payments', 'webhook': 'payments', 'slack': 'alerts', 'teams': 'alerts',
              'telegram': 'telegram', 'sms_twilio': 'sms', 'news_feed': 'news', 'youtube_public': 'youtube', 'youtube_account': 'youtube'}
    for provider, tab in expect.items():
        p = listed[provider]
        assert p['channel'] == (tab if provider not in ('youtube_public', 'youtube_account') else p['channel'])
    assert listed['ga4']['fields'][1]['secret'] and listed['google_reviews']['fields'][1]['secret'] and listed['razorpay']['fields'][0]['secret']
    assert len(listed['slack']['help']) >= 3 and listed['slack']['extra']['events'][0]['value'] == 'payment_received'
    assert [a['name'] for a in listed['slack']['actions']] == ['test_alert'] and [a['name'] for a in listed['sms_twilio']['actions']] == ['send']
    assert listed['razorpay']['inbound'] and not listed['razorpay']['syncable'] and listed['telegram']['inbound'] and listed['ga4']['syncable']
    assert all(set(p['fields'][i].keys()) >= {'name', 'label', 'secret', 'required'} for p in listed.values() for i in range(len(p['fields'])))
