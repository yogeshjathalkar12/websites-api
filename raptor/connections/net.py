"""Safe outbound requests for connectors that call an address a customer typed in (a news feed, a Slack or Teams webhook).

A person can type any address, so every one is checked first: https only, a real public host, never an address inside our own network
(the server must not be turned into a way of reaching internal services), and the answer is read only up to a size limit."""
from __future__ import annotations

import ipaddress
import socket
from typing import Optional
from urllib.parse import urlparse

import httpx

from .registry import ConnectorError

MAX_BYTES = 1_000_000
TIMEOUT = 15


def _resolve(host: str) -> list:
    """The addresses a host name points to (a separate function so tests can stand in for DNS)."""
    try:
        return [info[4][0] for info in socket.getaddrinfo(host, None)]
    except socket.gaierror:
        return []


def assert_public_url(url: str, allow_hosts: Optional[tuple] = None) -> str:
    """Returns the address if it is safe to call, otherwise raises a ConnectorError saying what is wrong."""
    parsed = urlparse((url or "").strip())
    if parsed.scheme != "https" or not parsed.hostname:
        raise ConnectorError("The address must start with https://")
    if parsed.username or parsed.password:
        raise ConnectorError("The address must not contain a user name or password.")
    host = parsed.hostname.lower()
    if allow_hosts is not None and not any(host == h or host.endswith("." + h) for h in allow_hosts):
        raise ConnectorError("That address is not one this connection can use. Copy it again from the service.")
    if parsed.port not in (None, 443):
        raise ConnectorError("Only the standard https port is allowed.")
    addresses = _resolve(host)
    if not addresses:
        raise ConnectorError("That address could not be found. Check it for typing mistakes.")
    for raw in addresses:
        ip = ipaddress.ip_address(raw.split("%")[0])
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved or ip.is_unspecified:
            raise ConnectorError("That address points inside a private network, which is not allowed.")
    return parsed.geturl()


def fetch_text(url: str, allow_hosts: Optional[tuple] = None, max_bytes: int = MAX_BYTES, headers: Optional[dict] = None) -> str:
    """GET a public https address and return its text, never more than max_bytes. Redirects are followed one hop at a time and each
    hop is checked again, so a harmless address cannot bounce the request to a private one."""
    current = assert_public_url(url, allow_hosts)
    for _ in range(4):
        try:
            with httpx.stream("GET", current, timeout=TIMEOUT, follow_redirects=False,
                              headers={"User-Agent": "RaptorBot/1.0 (+https://shoonyaorigins.com)", **(headers or {})}) as resp:
                if resp.status_code in (301, 302, 303, 307, 308) and resp.headers.get("location"):
                    nxt = httpx.URL(current).join(resp.headers["location"])
                    current = assert_public_url(str(nxt), allow_hosts)
                    continue
                if resp.status_code != 200:
                    raise ConnectorError("That address answered with an error (%s)." % resp.status_code)
                chunks, size = [], 0
                for chunk in resp.iter_bytes():
                    size += len(chunk)
                    if size > max_bytes:
                        raise ConnectorError("That page is too large to read.")
                    chunks.append(chunk)
                return b"".join(chunks).decode(resp.encoding or "utf-8", errors="replace")
        except httpx.HTTPError:
            raise ConnectorError("Could not reach that address right now. Try again in a minute.")
    raise ConnectorError("That address redirects too many times.")


def post_json(url: str, payload: dict, allow_hosts: Optional[tuple] = None, headers: Optional[dict] = None) -> httpx.Response:
    """POST JSON to a public https address (alert webhooks). No redirects are followed."""
    target = assert_public_url(url, allow_hosts)
    try:
        return httpx.post(target, json=payload, headers=headers, timeout=TIMEOUT, follow_redirects=False)
    except httpx.HTTPError:
        raise ConnectorError("Could not reach the service right now. Try again in a minute.")
