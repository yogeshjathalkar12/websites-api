"""
One interface, swappable providers. Add a new provider by implementing
send() — the sender loop doesn't care which one it's talking to.
"""
from abc import ABC, abstractmethod
import resend


class EmailProvider(ABC):
    @abstractmethod
    def send(self, from_email: str, from_name: str, to: str, subject: str, html: str) -> str:
        """Returns the provider's message ID."""
        ...


class ResendProvider(EmailProvider):
    def __init__(self, api_key: str):
        resend.api_key = api_key

    def send(self, from_email: str, from_name: str, to: str, subject: str, html: str) -> str:
        result = resend.Emails.send({
            "from": f"{from_name} <{from_email}>",
            "to": [to],
            "subject": subject,
            "html": html,
        })
        return result["id"]


# Stub for when you add SMTP — same interface, different transport.
class SmtpProvider(EmailProvider):
    def __init__(self, config: dict):
        self.config = config  # host, port, username, password

    def send(self, from_email: str, from_name: str, to: str, subject: str, html: str) -> str:
        import smtplib
        from email.mime.text import MIMEText
        from email.mime.multipart import MIMEMultipart

        msg = MIMEMultipart('alternative')
        msg['Subject'] = subject
        msg['From'] = f"{from_name} <{from_email}>"
        msg['To'] = to
        msg.attach(MIMEText(html, 'html'))

        with smtplib.SMTP(self.config['host'], self.config['port']) as server:
            server.starttls()
            server.login(self.config['username'], self.config['password'])
            server.sendmail(from_email, [to], msg.as_string())
        return ''  # SMTP has no provider message ID to track


def get_provider(account: dict) -> EmailProvider:
    if account['provider'] == 'resend':
        return ResendProvider(account['api_key'])
    if account['provider'] == 'smtp':
        return SmtpProvider(account['smtp_config'])
    raise ValueError(f"Unknown provider: {account['provider']}")
