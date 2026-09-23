"""
One interface, swappable providers. Add a new provider by implementing
send() — the sender loop doesn't care which one it's talking to.

One provider today:
  * smtp — the customer's own mailbox or relay (Google Workspace,
    Microsoft 365, Zoho, ...). Every send goes out from a mailbox the
    customer owns, at a human pace.

send() returns the provider's message id. It raises ProviderRateLimited
when the provider or mailbox says "you've hit your limit, try later" —
the campaign loop leaves the recipient pending for that case instead of
marking them failed for good. Any other exception means a real failure.
"""
import ipaddress
import os
import re
import smtplib
import socket
import ssl
from abc import ABC, abstractmethod
from email.message import EmailMessage
from email.utils import formataddr, formatdate, make_msgid
from html import unescape

SUPPORTED_PROVIDERS = ('smtp',)

# 25/465/587 are the standard SMTP ports; 2525 is the common alternative
# offered by relays (Brevo, Mailgun, SendGrid, ...) precisely because
# some hosts block the standard three. Anything else is refused so this
# can't be aimed at arbitrary services.
ALLOWED_SMTP_PORTS = (25, 465, 587, 2525)
SMTP_SECURITY_MODES = ('starttls', 'ssl')
SMTP_TIMEOUT_SECONDS = 20


class ProviderRateLimited(Exception):
    """The provider (or the mailbox behind it) refused because a sending
    limit was reached. Temporary, and not the recipient's fault."""


class ProviderUnavailable(ProviderRateLimited):
    """The provider could not be reached at all (timeout, refused, dropped
    connection). Handled like a rate limit: the campaign pauses and tries
    again later, rather than marking every recipient failed."""


def smtp_enabled() -> bool:
    """Sending through a customer's own mailbox is OFF unless the server
    opts in with EMAIL_SMTP_ENABLED=true. Many hosts (Render's free tier
    among them) block the outgoing mail ports, and a blocked port ties up
    a worker until the connection times out. Turn this on only where
    outgoing SMTP works."""
    return os.environ.get('EMAIL_SMTP_ENABLED', '').strip().lower() in ('1', 'true', 'yes', 'on')


class EmailProvider(ABC):
    @abstractmethod
    def send(self, from_email: str, from_name: str, to: str, subject: str, html: str) -> str:
        """Returns the provider's message ID."""
        ...


# ---------------------------------------------------------------------------
# SMTP
# ---------------------------------------------------------------------------

def _assert_public_host(host: str) -> None:
    """Refuse to connect to anything that isn't on the public internet.
    The server opens this connection on the customer's behalf, so an
    unchecked host would let anyone probe internal addresses (localhost,
    cloud metadata, private networks) through us."""
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        raise ValueError(f"We couldn't find a mail server called '{host}'. Check the host name.")
    for info in infos:
        ip = ipaddress.ip_address(info[4][0].split('%')[0])
        if getattr(ip, 'ipv4_mapped', None):
            ip = ip.ipv4_mapped
        if not ip.is_global:
            raise ValueError("That mail server address isn't allowed. Use your provider's public SMTP host name.")


def validate_smtp_config(config: dict) -> dict:
    """Checks and normalises the non-secret SMTP settings. The password is
    NOT part of this (it's encrypted separately and never stored here).
    Raises ValueError with a message that is safe to show to the user."""
    if not isinstance(config, dict):
        raise ValueError("SMTP settings are missing.")

    host = str(config.get('host', '')).strip().lower()
    if not host or len(host) > 253 or not re.fullmatch(r'[a-z0-9]([a-z0-9.\-]*[a-z0-9])?', host) or '.' not in host:
        raise ValueError("Enter your mail server's host name, like smtp.gmail.com.")

    security = str(config.get('security', 'starttls')).strip().lower()
    if security not in SMTP_SECURITY_MODES:
        raise ValueError("Choose a connection type: STARTTLS (usually port 587) or SSL/TLS (usually port 465).")

    default_port = 465 if security == 'ssl' else 587
    try:
        port = int(config.get('port') or default_port)
    except (TypeError, ValueError):
        raise ValueError("The port must be a number.")
    if port not in ALLOWED_SMTP_PORTS:
        raise ValueError(f"Port {port} isn't supported. Use one of: {', '.join(str(p) for p in ALLOWED_SMTP_PORTS)}.")

    username = str(config.get('username', '')).strip()
    if not username or len(username) > 320:
        raise ValueError("Enter the username for your mail account (often your full email address).")

    _assert_public_host(host)
    return {'host': host, 'port': port, 'username': username, 'security': security}


_LIMIT_HINTS = re.compile(
    r"quota|too many|throttl|rate.?limit|sending limit|limit(ed)? exceeded|"
    r"exceeded (the )?(daily|sending|rate|user|message|recipient)",
    re.IGNORECASE,
)
_LIMIT_CODES = (421, 452, 454)


def _looks_rate_limited(code: int, message: str) -> bool:
    return code in _LIMIT_CODES or bool(_LIMIT_HINTS.search(message or ''))


def _connect_hint(host: str, port: int) -> str:
    hint = f"Could not reach {host}:{port}."
    if port in (25, 465, 587):
        hint += (" If this service runs on a hosting plan that blocks outgoing mail ports,"
                 " use port 2525 (if your provider offers it) or a plan that allows SMTP.")
    return hint


def _html_to_text(html: str) -> str:
    """A plain-text alternative part. Mail with only an HTML part scores
    worse with spam filters than mail that also carries plain text."""
    text = re.sub(r'(?is)<(script|style).*?</\1>', '', html)
    text = re.sub(r'(?is)<a\s[^>]*href=["\']([^"\']+)["\'][^>]*>(.*?)</a>', r'\2 (\1)', text)
    text = re.sub(r'(?i)<br\s*/?>|</p>|</div>|</h[1-6]>|</li>', '\n', text)
    text = re.sub(r'<[^>]+>', '', text)
    text = unescape(text)
    text = re.sub(r'[ \t]+', ' ', text)
    return re.sub(r'\n\s*\n\s*\n+', '\n\n', text).strip()


class SmtpProvider(EmailProvider):
    def __init__(self, config: dict):
        """config: host, port, username, security ('starttls' | 'ssl') and
        password (already decrypted, held only in memory)."""
        missing = [k for k in ('host', 'port', 'username', 'security', 'password') if not config.get(k)]
        if missing:
            raise ValueError(f"SMTP account is missing: {', '.join(missing)}.")
        self.config = config

    def _connect(self):
        host, port = self.config['host'], int(self.config['port'])
        _assert_public_host(host)  # again at send time, not only at save time
        context = ssl.create_default_context()  # verifies the server certificate
        try:
            if self.config['security'] == 'ssl':
                server = smtplib.SMTP_SSL(host, port, timeout=SMTP_TIMEOUT_SECONDS, context=context)
            else:
                server = smtplib.SMTP(host, port, timeout=SMTP_TIMEOUT_SECONDS)
                server.ehlo()
                server.starttls(context=context)
                server.ehlo()
            server.login(self.config['username'], self.config['password'])
            return server
        except smtplib.SMTPAuthenticationError:
            raise RuntimeError("The mail server rejected the username or password. "
                               "Gmail and Microsoft accounts usually need an app password, not your normal password.")
        except ssl.SSLError as err:
            raise RuntimeError(f"Secure connection to {host}:{port} failed ({err.reason or err}). "
                               "Check the connection type matches the port.")
        except (OSError, smtplib.SMTPConnectError, smtplib.SMTPServerDisconnected) as err:
            raise ProviderUnavailable(f"{_connect_hint(host, port)} ({err})")

    def check_connection(self) -> None:
        """Logs in and disconnects without sending anything."""
        server = self._connect()
        try:
            server.quit()
        except smtplib.SMTPException:
            pass

    def send(self, from_email: str, from_name: str, to: str, subject: str, html: str) -> str:
        msg = EmailMessage()
        msg['Subject'] = subject
        msg['From'] = formataddr((from_name, from_email))
        msg['To'] = to
        msg['Date'] = formatdate(localtime=False)
        msg['Message-ID'] = make_msgid(domain=from_email.split('@')[-1])
        msg.set_content(_html_to_text(html))
        msg.add_alternative(html, subtype='html')

        server = self._connect()
        try:
            server.send_message(msg, from_addr=from_email, to_addrs=[to])
        except smtplib.SMTPResponseException as err:
            detail = err.smtp_error.decode('utf-8', 'replace') if isinstance(err.smtp_error, bytes) else str(err.smtp_error)
            if _looks_rate_limited(err.smtp_code, detail):
                raise ProviderRateLimited(f"{err.smtp_code} {detail}") from err
            raise RuntimeError(f"Mail server refused the message: {err.smtp_code} {detail}") from err
        except smtplib.SMTPException as err:
            raise RuntimeError(f"Mail server error: {err}") from err
        finally:
            try:
                server.quit()
            except (smtplib.SMTPException, OSError):
                pass
        return msg['Message-ID']


def get_provider(account: dict) -> EmailProvider:
    """`account` is the email_accounts row with the secret already
    decrypted into account['api_key'] (see sending.get_ready_provider).
    For SMTP that secret is the mailbox password."""
    if account['provider'] == 'smtp':
        config = dict(account.get('smtp_config') or {})
        config['password'] = account.get('api_key')
        return SmtpProvider(config)
    raise ValueError(f"Unknown provider: {account['provider']}")
