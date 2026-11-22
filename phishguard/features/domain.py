"""Safe, offline URL / domain parsing helpers.

Nothing in this module performs DNS resolution or network I/O.
"""

from __future__ import annotations

import ipaddress
import math
import re
from collections import Counter
from dataclasses import dataclass
from urllib.parse import unquote, urlsplit

from phishguard.features.resources import MULTI_PART_SUFFIXES

_SCHEME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*:")


@dataclass
class ParsedURL:
    raw: str
    scheme: str
    host: str  # lowercase; punycode-decoded to Unicode where possible
    host_ascii: str  # lowercase ASCII/punycode form
    port: int | None
    path: str
    query: str
    userinfo: str
    registered_domain: str  # e.g. "evil.co.in"
    subdomain: str  # e.g. "paypal.com.login"
    tld: str
    is_ip: bool
    had_scheme: bool


def _decode_idna(host: str) -> str:
    if "xn--" not in host:
        return host
    labels = []
    for label in host.split("."):
        if label.startswith("xn--"):
            try:
                labels.append(label.encode("ascii").decode("idna"))
                continue
            except (UnicodeError, ValueError):
                pass
        labels.append(label)
    return ".".join(labels)


def _encode_idna(host: str) -> str:
    try:
        return host.encode("idna").decode("ascii")
    except (UnicodeError, ValueError):
        return host


def parse_ip(host: str) -> ipaddress._BaseAddress | None:
    """Detect IPs including obfuscated forms: decimal (3232235777), hex (0xC0A80101), octal."""
    h = host.strip("[]")
    try:
        return ipaddress.ip_address(h)
    except ValueError:
        pass
    if re.fullmatch(r"\d{8,10}", h):  # single decimal integer
        n = int(h)
        if n <= 0xFFFFFFFF:
            return ipaddress.IPv4Address(n)
    if re.fullmatch(r"0x[0-9a-fA-F]{1,8}", h):
        return ipaddress.IPv4Address(int(h, 16))
    parts = h.split(".")
    if len(parts) == 4 and all(re.fullmatch(r"(0x[0-9a-f]+|0[0-7]*|\d+)", p, re.I) for p in parts):
        try:
            octets = [int(p, 0) if not re.fullmatch(r"0\d+", p) else int(p, 8) for p in parts]
            if all(0 <= o <= 255 for o in octets):
                return ipaddress.IPv4Address(".".join(map(str, octets)))
        except ValueError:
            return None
    return None


def split_registered_domain(host: str) -> tuple[str, str, str]:
    """Return (subdomain, registered_domain, suffix) using a built-in suffix list.

    Limitation: not a full Public Suffix List. For production accuracy install
    ``tldextract`` with a bundled snapshot (no network) - see docs/ARCHITECTURE.md.
    """
    labels = [l for l in host.split(".") if l]
    if len(labels) < 2:
        return "", host, ""
    # longest matching multi-part suffix wins
    for n in (4, 3, 2):
        if len(labels) > n:
            suffix = ".".join(labels[-n:])
            if suffix in MULTI_PART_SUFFIXES:
                return ".".join(labels[: -n - 1]), ".".join(labels[-n - 1 :]), suffix
    return ".".join(labels[:-2]), ".".join(labels[-2:]), labels[-1]


def parse_url(raw: str) -> ParsedURL | None:
    """Parse a URL without touching the network. Returns None if unparseable."""
    url = raw.strip().strip("<>\"'")
    had_scheme = bool(_SCHEME_RE.match(url)) and not re.match(r"^[\w.-]+:\d+", url)
    if not had_scheme:
        url = "http://" + url
    try:
        parts = urlsplit(url)
    except ValueError:
        return None
    scheme = parts.scheme.lower()
    netloc = parts.netloc
    userinfo = ""
    if "@" in netloc:
        userinfo, _, netloc = netloc.rpartition("@")
    host = netloc
    port: int | None = None
    m = re.match(r"^(\[[^\]]+\]|[^:]+)(?::(\d{1,5}))?$", netloc)
    if m:
        host = m.group(1)
        port = int(m.group(2)) if m.group(2) else None
    host = unquote(host).lower().rstrip(".")
    host_unicode = _decode_idna(host)
    host_ascii = _encode_idna(host_unicode)
    ip = parse_ip(host)
    if ip is not None:
        sub, reg, tld = "", str(ip), ""
    else:
        sub, reg, tld = split_registered_domain(host_unicode)
    return ParsedURL(
        raw=raw,
        scheme=scheme,
        host=host_unicode,
        host_ascii=host_ascii,
        port=port,
        path=parts.path or "",
        query=parts.query or "",
        userinfo=userinfo,
        registered_domain=reg,
        subdomain=sub,
        tld=tld.split(".")[-1] if tld else "",
        is_ip=ip is not None,
        had_scheme=had_scheme,
    )


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


def registered_domain_of(host_or_email_domain: str) -> str:
    host = _decode_idna(host_or_email_domain.lower().strip().rstrip("."))
    if parse_ip(host):
        return host
    return split_registered_domain(host)[1]
