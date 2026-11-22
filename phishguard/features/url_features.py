"""URL analysis layer: lexical features + typosquatting, fully offline.

The URL is never fetched here. Network-based enrichment lives in
``phishguard.intel`` and is disabled by default.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from phishguard.features import typosquat
from phishguard.features.domain import ParsedURL, parse_url, shannon_entropy
from phishguard.features.resources import (
    COMMON_TLDS,
    FREE_HOSTING_SUFFIXES,
    RISKY_DOWNLOAD_EXTENSIONS,
    SENSITIVE_URL_TOKENS,
    SHORT_BRANDS,
    SUSPICIOUS_TLDS,
    TRUSTED_DOMAINS,
    URL_SHORTENERS,
)
from phishguard.sanitize import defang_url, refang
from phishguard.signals import Signal


@dataclass
class URLReport:
    url: str
    parsed: ParsedURL | None
    signals: list[Signal] = field(default_factory=list)
    features: dict[str, float] = field(default_factory=dict)  # numeric features for ML

    @property
    def display(self) -> str:
        return defang_url(self.url)


_SCHEME_URL_RE = re.compile(r"""(?i)\b(?:https?|ftp|hxxps?)(?:://|\[:\]//)[^\s<>"'`]+""")
_WWW_RE = re.compile(r"""(?i)\bwww\d?\.[^\s<>"'`]+""")
_BARE_DOMAIN_RE = re.compile(
    r"""(?i)(?<![@\w.-])((?:[a-z0-9¡-￿](?:[a-z0-9¡-￿-]{0,61}[a-z0-9¡-￿])?\.)+"""
    r"""([a-z]{2,24}))(?::\d{2,5})?(?:/[^\s<>"'`]*)?"""
)
_IP_URL_RE = re.compile(r"""\b(?:\d{1,3}\.){3}\d{1,3}(?::\d{2,5})?/[^\s<>"'`]*""")
_TRAILING_PUNCT = ".,;:!?)]}'\"…"


def extract_urls(text: str, limit: int = 25) -> list[str]:
    """Extract URLs incl. defanged ('hxxp', '[.]') and bare domains ('sbi-kyc.top/x')."""
    text = refang(text)
    found: list[str] = []
    spans: list[tuple[int, int]] = []

    def add(m: re.Match, value: str | None = None) -> None:
        s, e = m.span()
        if any(s < pe and e > ps for ps, pe in spans):
            return
        url = (value or m.group(0)).rstrip(_TRAILING_PUNCT)
        if url and url not in found:
            spans.append((s, e))
            found.append(url)

    for m in _SCHEME_URL_RE.finditer(text):
        add(m)
    for m in _WWW_RE.finditer(text):
        add(m)
    for m in _IP_URL_RE.finditer(text):
        add(m)
    for m in _BARE_DOMAIN_RE.finditer(text):
        tld = m.group(2).lower()
        if tld in COMMON_TLDS and not re.fullmatch(r"[\d.]+", m.group(1)):
            add(m)
    return found[:limit]


def mask_urls(text: str) -> str:
    """Replace URLs with a placeholder so text rules don't double-count URL tokens
    (e.g. 'kyc-update' inside a domain is the URL layer's job, not the text layer's)."""
    text = refang(text)

    # Placeholder must not contain words the text rules look for (e.g. "link").
    def bare(m: re.Match) -> str:
        return " [url] " if m.group(2).lower() in COMMON_TLDS else m.group(0)

    for rx in (_SCHEME_URL_RE, _WWW_RE, _IP_URL_RE):
        text = rx.sub(" [url] ", text)
    return _BARE_DOMAIN_RE.sub(bare, text)


_SENSITIVE_RE = re.compile("|".join(re.escape(t) for t in sorted(SENSITIVE_URL_TOKENS, key=len, reverse=True)))


def _matches_suffix(host: str, suffixes: set[str]) -> str | None:
    for s in suffixes:
        if host == s or host.endswith("." + s):
            return s
    return None


def _looks_random(label: str, entropy: float) -> bool:
    """DGA-like label: long, high entropy, few vowels or letters+digits mixed, no word separators."""
    if len(label) < 10 or "-" in label or entropy < 3.3:
        return False
    letters = [c for c in label if c.isalpha()]
    vowel_ratio = sum(c in "aeiou" for c in letters) / max(1, len(letters))
    digit_mix = sum(c.isdigit() for c in label) >= 3 and len(letters) >= 3
    return vowel_ratio < 0.22 or digit_mix


def analyze_url(raw: str) -> URLReport:
    url = refang(raw.strip())
    report = URLReport(url=url, parsed=parse_url(url))
    p = report.parsed
    sig = report.signals.append
    if p is None or not p.host and p.scheme not in ("javascript", "data", "vbscript"):
        report.features["unparseable"] = 1.0
        return report

    host, reg = p.host, p.registered_domain
    full = url.lower()
    f = report.features
    f.update(
        url_length=len(url),
        host_length=len(host),
        num_dots=host.count("."),
        num_subdomain_levels=len([x for x in p.subdomain.split(".") if x]),
        num_hyphens=host.count("-"),
        num_digits_host=sum(c.isdigit() for c in host),
        has_at=float("@" in url.split("?")[0]),
        is_ip=float(p.is_ip),
        entropy=shannon_entropy(reg.split(".")[0]) if not p.is_ip else 0.0,
        path_depth=p.path.count("/"),
        query_length=len(p.query),
        pct_encoded=len(re.findall(r"%[0-9a-fA-F]{2}", url)),
    )

    if p.scheme in ("javascript", "data", "vbscript"):
        sig(Signal("url.dangerous_scheme", f"{p.scheme}: scheme"))
        return report

    is_trusted = reg in TRUSTED_DOMAINS
    if is_trusted:
        sig(Signal("url.trusted_domain", reg))

    # --- host-level indicators --------------------------------------------
    if p.is_ip:
        sig(Signal("url.ip_host", host))
    if p.userinfo:
        sig(Signal("url.at_symbol", f"text before '@': {p.userinfo[:40]}"))
    if "xn--" in p.host_ascii and not is_trusted:
        sig(Signal("url.punycode", p.host_ascii))
    if p.port and p.port not in (80, 443):
        sig(Signal("url.nonstandard_port", f"port {p.port}"))
    if p.scheme == "http" and p.had_scheme and not is_trusted:
        sig(Signal("url.no_tls", "http://"))
    if reg in URL_SHORTENERS or host in URL_SHORTENERS:
        sig(Signal("url.shortener", host))
    hosting = _matches_suffix(host, FREE_HOSTING_SUFFIXES)
    if hosting:
        sig(Signal("url.free_hosting", hosting))
    if p.tld in SUSPICIOUS_TLDS and not is_trusted:
        sig(Signal("url.suspicious_tld", f".{p.tld}"))
    if f["num_subdomain_levels"] >= 4 or (f["num_subdomain_levels"] >= 3 and not is_trusted):
        sig(Signal("url.many_subdomains", f"{int(f['num_subdomain_levels'])} subdomain levels"))
    if host.count("-") >= 3 and not is_trusted:
        sig(Signal("url.many_hyphens", host))
    if len(url) > 120:
        sig(Signal("url.long_url", f"{len(url)} characters"))
    label = reg.split(".")[0] if not p.is_ip else ""
    if label and not is_trusted and not hosting and _looks_random(label, f["entropy"]):
        sig(Signal("url.high_entropy_domain", label))
    if f["num_digits_host"] >= 5 and not p.is_ip:
        sig(Signal("url.digits_in_domain", host))
    if f["pct_encoded"] >= 6 or re.search(r"%[0-9a-f]{2}", p.host_ascii, re.I):
        sig(Signal("url.encoded_obfuscation", f"{int(f['pct_encoded'])} percent-encoded characters"))
    if re.search(r"(?:https?(?:%3a|:)(?:%2f|/){2})", p.query + p.path[1:], re.I) or "//" in p.path[1:]:
        sig(Signal("url.embedded_redirect", "URL embedded in path/query"))

    # --- path / file indicators ---------------------------------------------
    path_l = p.path.lower()
    for ext in RISKY_DOWNLOAD_EXTENSIONS:
        if path_l.endswith(ext):
            sig(Signal("url.executable_download", ext))
            break
    if not is_trusted:
        hits = sorted(set(_SENSITIVE_RE.findall(full.split("://", 1)[-1])))
        if hits:
            # stronger if the keyword is in the hostname itself (login-sbi.xyz)
            in_host = any(h in host for h in hits)
            sig(Signal("url.sensitive_keywords", ", ".join(hits[:5]), strength=1.0 if in_host else 0.6))

    # --- brand impersonation ----------------------------------------------------
    if not is_trusted:
        _brand_checks(report, p, label, bool(hosting))
    return report


def _brand_checks(report: URLReport, p: ParsedURL, label: str, on_hosting: bool) -> None:
    sig = report.signals.append
    squat = None
    # For free-hosting platforms the "label" is the user-chosen site name.
    candidates = [label] + ([l for l in p.subdomain.split(".") if l] if on_hosting else [])
    for cand in candidates if not p.is_ip else []:
        squat = typosquat.check_label(cand, p.registered_domain)
        if squat:
            break
    if squat:
        if squat.kind == "homoglyph":
            sig(Signal("url.homoglyph_brand", f"'{squat.label}' imitates {squat.brand}"))
        elif squat.kind == "typosquat":
            strength = 1.0 if len(squat.brand) >= 7 else 0.75
            sig(Signal("url.typosquat", f"'{squat.label}' ≈ {squat.brand} (edit distance {squat.distance})",
                       strength=strength))
        else:
            lure = "-" in squat.label or bool(_SENSITIVE_RE.search(squat.label.lower()))
            sig(Signal("url.combosquat", f"'{squat.label}' contains brand {squat.brand}",
                       strength=1.0 if lure else 0.6))
    sub_brands: set[str] = set()
    if p.subdomain and not on_hosting:
        # long brands: substring match ("paypal.com.secure-update"); short brands
        # (sbi, hdfc...) only as whole tokens to avoid "groups" -> "ups" noise.
        sub_brands = typosquat.find_brand_tokens(p.subdomain, min_len=5)
        tokens = set(re.split(r"[.\-_]", p.subdomain.lower()))
        sub_brands |= {b for b in SHORT_BRANDS if b in tokens and len(b) >= 3}
    if sub_brands and not (squat and squat.brand in sub_brands):
        sig(Signal("url.brand_in_subdomain", f"{', '.join(sorted(sub_brands))} in '{p.subdomain}'"))
    path_brands = typosquat.find_brand_tokens(p.path + "?" + p.query, min_len=5)
    path_tokens = set(re.split(r"[/._\-?=&]", (p.path + "?" + p.query).lower()))
    path_brands |= {b for b in SHORT_BRANDS if b in path_tokens and len(b) >= 3}
    if path_brands and not squat and not sub_brands:
        sig(Signal("url.brand_in_path", ", ".join(sorted(path_brands))))
