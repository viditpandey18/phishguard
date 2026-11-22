"""ACTIVE probes - these connect to the suspect server.

Safety controls (defence in depth):
1. Disabled unless ``PG_ENABLE_ACTIVE_PROBING=true``.
2. Intended to run only in the ``sandbox`` compose service: separate
   container, no volumes, egress-only network, read-only FS, non-root.
3. SSRF guard: hostnames are resolved and *every* resolved address must be
   public (no loopback/private/link-local/metadata 169.254.169.254).
4. HEAD requests only, no body download, no JavaScript, no cookies kept,
   redirects followed manually (each hop re-validated), hop and time limits.

Residual risk: DNS rebinding between our check and httpx's own resolution.
The sandbox network policy is the real boundary; this guard is a second layer.
"""

from __future__ import annotations

import ipaddress
import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urljoin, urlsplit

import httpx

from phishguard.features.domain import registered_domain_of
from phishguard.intel.base import IntelProvider
from phishguard.signals import Signal


class UnsafeTargetError(ValueError):
    pass


def assert_public_host(host: str, port: int = 443) -> None:
    try:
        infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise UnsafeTargetError(f"cannot resolve {host}") from exc
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if not ip.is_global or ip.is_multicast:
            raise UnsafeTargetError(f"{host} resolves to non-public address")


class RedirectChainProbe(IntelProvider):
    name = "redirect_chain"
    active = True

    def __init__(self, timeout: float, max_hops: int) -> None:
        self.timeout, self.max_hops = timeout, max_hops

    def resolve_chain(self, url: str) -> list[str]:
        chain = [url]
        with httpx.Client(follow_redirects=False, timeout=self.timeout, headers={"User-Agent": "Mozilla/5.0"},
                          cookies=None, verify=True) as client:
            for _ in range(self.max_hops):
                parts = urlsplit(chain[-1])
                if parts.scheme not in ("http", "https") or not parts.hostname:
                    break
                assert_public_host(parts.hostname, parts.port or (443 if parts.scheme == "https" else 80))
                r = client.head(chain[-1])
                if r.status_code in (301, 302, 303, 307, 308) and "location" in r.headers:
                    chain.append(urljoin(chain[-1], r.headers["location"]))
                else:
                    break
        return chain

    def check(self, url: str, registered_domain: str) -> list[Signal]:
        from phishguard.features.url_features import analyze_url  # local import: avoid cycle

        chain = self.resolve_chain(url)
        signals: list[Signal] = []
        domains = {registered_domain_of(urlsplit(u).hostname or "") for u in chain}
        if len(domains) >= 3:
            signals.append(Signal("intel.redirect_offsite", f"{len(chain) - 1} redirects across {len(domains)} domains"))
        if len(chain) > 1:
            # analyse the *final* destination lexically (e.g. what a shortener hides)
            for s in analyze_url(chain[-1]).signals:
                s.evidence = f"final destination: {s.evidence}"
                signals.append(s)
        return signals


class TLSCertificateProbe(IntelProvider):
    name = "tls_certificate"
    active = True

    def __init__(self, timeout: float) -> None:
        self.timeout = timeout

    def check(self, url: str, registered_domain: str) -> list[Signal]:
        parts = urlsplit(url if "://" in url else "https://" + url)
        host = parts.hostname
        if not host or parts.scheme != "https":
            return []
        assert_public_host(host, 443)
        ctx = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=self.timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                cert = tls.getpeercert()
        not_before = datetime.strptime(cert["notBefore"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        age = (datetime.now(timezone.utc) - not_before).days
        if age < 7:
            return [Signal("intel.cert_new", f"certificate issued {age} day(s) ago")]
        return []
