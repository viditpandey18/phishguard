"""Adversarial perturbations for robustness evaluation.

Each transform keeps the *human-visible meaning* of a malicious sample but
attacks a specific weakness of text/URL filters. A robust detector's score
should not drop materially after perturbation.
"""

from __future__ import annotations

import random
import re
from collections.abc import Callable

ZW = "​"
_LATIN_TO_CYRILLIC = {"a": "а", "e": "е", "o": "о", "p": "р", "c": "с", "x": "х", "y": "у", "i": "і"}


def zero_width_insert(text: str, rate: float = 0.3, seed: int = 0) -> str:
    rng = random.Random(seed)
    return "".join(ch + (ZW if ch.isalpha() and rng.random() < rate else "") for ch in text)


def homoglyph_swap(text: str, rate: float = 0.5, seed: int = 0) -> str:
    rng = random.Random(seed)
    return "".join(_LATIN_TO_CYRILLIC[c] if c in _LATIN_TO_CYRILLIC and rng.random() < rate else c for c in text)


def fullwidth(text: str) -> str:
    return "".join(chr(ord(c) + 0xFEE0) if "!" <= c <= "~" else c for c in text)


def defang_urls(text: str) -> str:
    text = re.sub(r"https?://", lambda m: m.group(0).replace("http", "hxxp"), text)
    return re.sub(r"(?<=\w)\.(?=(com|xyz|top|in|net|org|ly)\b)", "[.]", text)


def spaced_letters(text: str, words=("otp", "password", "kyc", "verify", "urgent")) -> str:
    for w in words:
        text = re.sub(rf"\b{w}\b", " ".join(w.upper()), text, flags=re.I)
    return text


def url_userinfo_trick(url: str, decoy: str = "www.paypal.com") -> str:
    """http://evil.com/x -> http://www.paypal.com@evil.com/x"""
    return re.sub(r"^(https?://)", rf"\1{decoy}@", url)


def url_decimal_ip(url: str) -> str:
    """http://1.2.3.4/x -> http://16909060/x"""
    def conv(m: re.Match) -> str:
        a, b, c, d = map(int, m.groups())
        return str((a << 24) + (b << 16) + (c << 8) + d)
    return re.sub(r"(?<=://)(\d+)\.(\d+)\.(\d+)\.(\d+)", conv, url)


def url_percent_encode_path(url: str) -> str:
    head, sep, path = url.partition("://")
    host, slash, rest = path.partition("/")
    return f"{head}{sep}{host}{slash}" + "".join(f"%{ord(c):02X}" if c.isalnum() and i % 2 else c for i, c in enumerate(rest))


TEXT_ATTACKS: dict[str, Callable[[str], str]] = {
    "zero_width": zero_width_insert,
    "homoglyph": homoglyph_swap,
    "fullwidth": fullwidth,
    "defanged_urls": defang_urls,
    "spaced_letters": spaced_letters,
}

URL_ATTACKS: dict[str, Callable[[str], str]] = {
    "userinfo_decoy": url_userinfo_trick,
    "percent_encoded_path": url_percent_encode_path,
}

IMAGE_ONLY_EMAIL_TEMPLATE = """From: "Account Team" <notice@{domain}>
To: victim@example.com
Subject: Important notice
MIME-Version: 1.0
Content-Type: text/html; charset=utf-8

<html><body><a href="http://{domain}/login"><img src="cid:banner1"></a></body></html>
"""
