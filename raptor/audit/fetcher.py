"""raptor/audit/fetcher.py: fetching other people's web pages safely, for the audit.

A person types any address, so the server must never be turned into a way of reaching our own network: every host is resolved and refused if
any address is private, loopback, link-local or reserved, redirects are followed one hop at a time and each hop is checked again, only ports
80 and 443 are used, and every answer is read only up to a size limit. The fetcher says plainly who it is (RaptorAudit) and, when a site refuses
(403, 429, 503, a bot-check page), it reports "refused" and stops. It never tries to get around that.
"""
from __future__ import annotations

import ipaddress
import socket
import time
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urljoin, urlparse

import httpx

UA = "Mozilla/5.0 (compatible; RaptorAudit/1.0; +https://shoonyaorigins.com/ventures/raptor/tools/audit.html)"
MAX_BYTES = 1_500_000
TIMEOUT = 12.0
MAX_REDIRECTS = 5
REFUSED_STATUS = (401, 403, 429, 451, 503)
BOT_WALL_MARKERS = ("cf-chl", "just a moment...", "attention required! | cloudflare", "captcha", "access denied", "px-captcha", "are you a robot", "bm-verify",
                    "_incapsula_resource", "challenge-platform", "ddos-guard", "perimeterx", "datadome", "sucuri website firewall", "checking your browser")


@dataclass
class Fetched:
    url: str
    final_url: str = ""
    status: int = 0
    headers: dict = field(default_factory=dict)       # lower-case names
    body: str = ""
    size: int = 0
    elapsed_ms: int = 0
    redirects: list = field(default_factory=list)     # every address passed through, in order, ending with the final one
    error: str = ""                                   # '' when an HTTP answer arrived; otherwise a short kind: blocked | dns | timeout | tls | connect | too_large | other
    error_detail: str = ""

    @property
    def ok(self) -> bool:
        return not self.error and 200 <= self.status < 300

    @property
    def refused(self) -> bool:
        """The site answered but would not let an automated visitor in (we stop there)."""
        if self.error:
            return False
        if self.status in REFUSED_STATUS:
            return True
        low = (self.body or "")[:4000].lower()
        return self.status in (200, 202) and any(m in low for m in BOT_WALL_MARKERS) and len(self.body) < 20000


class Unsafe(Exception):
    pass


def _resolve(host: str) -> list:
    """The addresses a host name points to (its own function so tests can stand in for DNS)."""
    try:
        return [info[4][0] for info in socket.getaddrinfo(host, None)]
    except socket.gaierror as e:
        # "no such name" is a fact about the domain; any other failure (a timeout, a resolver hiccup) says nothing about it
        return [] if e.errno in (socket.EAI_NONAME, getattr(socket, "EAI_NODATA", None), 11001) else None


def assert_public(url: str) -> str:
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise Unsafe("not a web address")
    if parsed.username or parsed.password:
        raise Unsafe("address has a user name or password")
    if parsed.port not in (None, 80, 443):
        raise Unsafe("only the standard web ports are used")
    addresses = _resolve(parsed.hostname)
    if addresses is None:
        raise Unsafe("dns_unavailable")
    if not addresses:
        raise Unsafe("dns")
    for raw in addresses:
        if not isinstance(raw, str) or not is_public_ip(raw):
            raise Unsafe("points inside a private network")
    return url


_NAT64 = ipaddress.ip_network("64:ff9b::/96")


def is_public_ip(raw: str) -> bool:
    """True only for an address on the open internet. IPv6 addresses that merely wrap an IPv4 one (IPv4-mapped, and the 64:ff9b::/96 range that
    networks without IPv4 use to reach IPv4 sites) are judged by the IPv4 address inside, so they cannot be used to hide a private target and
    real sites on such networks are not refused."""
    ip = ipaddress.ip_address(raw.split("%")[0])
    if ip.version == 6:
        if ip.ipv4_mapped is not None:
            ip = ip.ipv4_mapped
        elif ip in _NAT64:
            ip = ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF)
    return bool(ip.is_global) and not ip.is_multicast


def fetch(url: str, *, method: str = "GET", max_bytes: int = MAX_BYTES, timeout: float = TIMEOUT, headers: Optional[dict] = None) -> Fetched:
    out = Fetched(url=url, final_url=url)
    started = time.monotonic()
    current = url
    out.redirects.append(current)
    try:
        for _ in range(MAX_REDIRECTS + 1):
            try:
                assert_public(current)
            except Unsafe as e:
                if str(e) == "dns":
                    out.error, out.error_detail = "dns", "the address could not be found"
                elif str(e) == "dns_unavailable":
                    out.error, out.error_detail = "other", "the name lookup failed for now"
                else:
                    out.error, out.error_detail = "blocked", str(e)
                return out
            try:
                with httpx.stream(method, current, timeout=timeout, follow_redirects=False, headers={"User-Agent": UA, "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", **(headers or {})}) as resp:
                    out.status = resp.status_code
                    out.headers = {k.lower(): v for k, v in resp.headers.items()}
                    location = resp.headers.get("location")
                    if resp.status_code in (301, 302, 303, 307, 308) and location:
                        current = urljoin(current, location)
                        out.redirects.append(current)
                        continue
                    out.final_url = current
                    if method != "HEAD":
                        chunks, size = [], 0
                        for chunk in resp.iter_bytes():
                            size += len(chunk)
                            if size > max_bytes:
                                out.error, out.error_detail = "too_large", "the page is larger than the %d KB we read" % (max_bytes // 1000)
                                break
                            chunks.append(chunk)
                        out.size = size
                        out.body = b"".join(chunks).decode(resp.encoding or "utf-8", errors="replace")
                    else:
                        out.size = int(resp.headers.get("content-length") or 0)
                    out.elapsed_ms = int((time.monotonic() - started) * 1000)
                    return out
            except httpx.ConnectTimeout:
                out.error, out.error_detail = "timeout", "the server did not answer in time"
                return out
            except httpx.ReadTimeout:
                out.error, out.error_detail = "timeout", "the server was too slow to send the page"
                return out
            except httpx.ConnectError as e:
                text = str(e)
                if "CERTIFICATE" in text.upper() or "SSL" in text.upper() or "TLS" in text.upper():
                    out.error, out.error_detail = "tls", text[:200]
                else:
                    out.error, out.error_detail = "connect", "the server could not be reached"
                return out
            except httpx.HTTPError as e:
                out.error, out.error_detail = "other", type(e).__name__
                return out
        out.error, out.error_detail = "other", "too many redirects"
        return out
    finally:
        out.elapsed_ms = out.elapsed_ms or int((time.monotonic() - started) * 1000)
