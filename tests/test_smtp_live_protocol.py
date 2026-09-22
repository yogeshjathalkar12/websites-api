"""
tests/test_smtp_live_protocol.py — SmtpProvider against a REAL SMTP server.

The unit tests in test_email_providers.py use a fake smtplib. This one
runs an actual server on localhost that speaks the SMTP protocol (EHLO,
STARTTLS or implicit TLS, AUTH, MAIL/RCPT/DATA) with a real TLS
handshake, so mistakes in how we drive smtplib show up here.

Only two things are bypassed: the "public addresses only" host check
(localhost is deliberately refused in production), and certificate trust
(the server uses a throw-away self-signed certificate, which is trusted
explicitly for these tests — certificate verification stays ON).
"""
import base64
import datetime
import email
import email.policy
import os
import socketserver
import ssl
import tempfile
import threading

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from raptor.email import providers  # noqa: E402


def _self_signed_cert():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'localhost')])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=5)).not_valid_after(now + datetime.timedelta(days=1))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName('localhost')]), critical=False)
            .sign(key, hashes.SHA256()))
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
                                serialization.NoEncryption())
    return cert_pem, key_pem


class SmtpServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, tls_context, implicit_tls, user, password):
        super().__init__(('127.0.0.1', 0), _Handler)
        self.tls_context, self.implicit_tls = tls_context, implicit_tls
        self.user, self.password = user, password
        self.messages, self.commands = [], []
        self.thread = threading.Thread(target=self.serve_forever, daemon=True)
        self.thread.start()

    @property
    def port(self):
        return self.server_address[1]

    def stop(self):
        self.shutdown()
        self.server_close()


class _Handler(socketserver.StreamRequestHandler):
    def _say(self, text):
        self.wfile.write(text.encode() + b'\r\n')

    def _rewrap(self):
        self.request = self.server.tls_context.wrap_socket(self.request, server_side=True)
        self.rfile = self.request.makefile('rb')
        self.wfile = self.request.makefile('wb', buffering=0)

    def handle(self):
        srv = self.server
        secure = False
        try:
            if srv.implicit_tls:
                self._rewrap()
                secure = True
            self._say('220 test ESMTP ready')
            mail_from, rcpts = None, []
            while True:
                line = self.rfile.readline()
                if not line:
                    return
                cmd = line.decode().rstrip('\r\n')
                verb = cmd.split(' ', 1)[0].upper()
                srv.commands.append(verb)
                if verb == 'EHLO':
                    self._say('250-localhost')
                    if secure:
                        self._say('250 AUTH PLAIN')
                    else:
                        self._say('250 STARTTLS')
                elif verb == 'STARTTLS':
                    self._say('220 go ahead')
                    self._rewrap()
                    secure = True
                elif verb == 'AUTH':
                    if not secure:
                        self._say('530 must issue STARTTLS first')
                        continue
                    _, mech, b64 = cmd.split(' ', 2)
                    _, user, pw = base64.b64decode(b64).split(b'\0')
                    if (user.decode(), pw.decode()) == (srv.user, srv.password):
                        self._say('235 2.7.0 authenticated')
                    else:
                        self._say('535 5.7.8 bad credentials')
                elif verb == 'MAIL':
                    mail_from = cmd.split(':', 1)[1].strip().strip('<>')
                    self._say('250 ok')
                elif verb == 'RCPT':
                    rcpts.append(cmd.split(':', 1)[1].strip().strip('<>'))
                    self._say('250 ok')
                elif verb == 'DATA':
                    self._say('354 end with <CRLF>.<CRLF>')
                    body = []
                    while True:
                        l = self.rfile.readline()
                        if l in (b'.\r\n', b''):
                            break
                        body.append(l[1:] if l.startswith(b'..') else l)
                    srv.messages.append({'from': mail_from, 'to': list(rcpts), 'raw': b''.join(body)})
                    self._say('250 queued')
                elif verb == 'QUIT':
                    self._say('221 bye')
                    return
                else:
                    self._say('250 ok')
        except (ssl.SSLError, ConnectionError, OSError):
            return


@pytest.fixture(scope='module')
def certs():
    cert_pem, key_pem = _self_signed_cert()
    with tempfile.TemporaryDirectory() as d:
        cert_path, key_path = os.path.join(d, 'c.pem'), os.path.join(d, 'k.pem')
        open(cert_path, 'wb').write(cert_pem)
        open(key_path, 'wb').write(key_pem)
        server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server_ctx.load_cert_chain(cert_path, key_path)
        yield server_ctx, cert_pem


def _start(certs, implicit_tls):
    server_ctx, _ = certs
    return SmtpServer(server_ctx, implicit_tls, 'me@example.com', 'right-password')


def _provider(server, security, password='right-password'):
    return providers.SmtpProvider({'host': 'localhost', 'port': server.port, 'username': 'me@example.com',
                                   'security': security, 'password': password})


@pytest.fixture
def trust_test_cert(monkeypatch, certs):
    """Trust the test certificate; verification (chain + hostname) stays on."""
    _, cert_pem = certs
    real = ssl.create_default_context

    def ctx(*a, **k):
        c = real(*a, **k)
        c.load_verify_locations(cadata=cert_pem.decode())
        return c
    monkeypatch.setattr(providers.ssl, 'create_default_context', ctx)
    monkeypatch.setattr(providers, '_assert_public_host', lambda host: None)


@pytest.mark.parametrize('security,implicit', [('starttls', False), ('ssl', True)])
def test_message_is_delivered_over_tls(certs, trust_test_cert, security, implicit):
    server = _start(certs, implicit)
    try:
        html = '<p>Hello Priya</p><p><a href="https://x.test/book">Book a call</a></p>'
        msg_id = _provider(server, security).send('me@example.com', 'Ravi K', 'priya@buyer.test', 'Quick question', html)
    finally:
        server.stop()

    assert len(server.messages) == 1
    got = server.messages[0]
    assert got['from'] == 'me@example.com' and got['to'] == ['priya@buyer.test']
    parsed = email.message_from_bytes(got['raw'], policy=email.policy.default)
    assert parsed['Subject'] == 'Quick question' and parsed['To'] == 'priya@buyer.test'
    assert 'Ravi K' in parsed['From'] and parsed['Message-ID'] == msg_id
    assert [p.get_content_type() for p in parsed.walk() if not p.is_multipart()] == ['text/plain', 'text/html']
    assert 'Book a call (https://x.test/book)' in parsed.get_body(preferencelist=('plain',)).get_content()
    if security == 'starttls':
        assert server.commands.index('STARTTLS') < server.commands.index('AUTH')  # never logs in unencrypted


def test_wrong_password_is_reported_helpfully(certs, trust_test_cert):
    server = _start(certs, False)
    try:
        with pytest.raises(RuntimeError, match='app password'):
            _provider(server, 'starttls', password='wrong').check_connection()
    finally:
        server.stop()
    assert server.messages == []


def test_an_untrusted_certificate_is_refused(certs, monkeypatch):
    """With the test certificate NOT trusted, the connection must fail —
    proving certificate checking is really on."""
    monkeypatch.setattr(providers, '_assert_public_host', lambda host: None)
    server = _start(certs, False)
    try:
        with pytest.raises(RuntimeError, match='Secure connection'):
            _provider(server, 'starttls').check_connection()
    finally:
        server.stop()
    assert server.messages == [] and 'AUTH' not in server.commands


def test_check_connection_logs_in_without_sending(certs, trust_test_cert):
    server = _start(certs, False)
    try:
        _provider(server, 'starttls').check_connection()
    finally:
        server.stop()
    assert 'AUTH' in server.commands and 'DATA' not in server.commands and server.messages == []
