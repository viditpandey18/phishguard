"""Brand typosquatting / homoglyph / combosquatting detection.

Approach (all offline):
1. If the registered domain is officially owned by a brand -> not squatting.
2. Homoglyph: skeleton(label) == skeleton(brand) but label != brand
   (catches "pаypal" with Cyrillic а, "paypa1", "rnicrosoft").
3. Typosquat: Damerau-Levenshtein distance small relative to brand length
   ("paypall", "amazom", "hdfcbnak").
4. Combosquat: brand appears as a token inside the label with extra words
   ("paypal-secure-login", "sbikyc", "hdfc-netbanking").
"""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache

from phishguard.features.resources import BRAND_DOMAINS, SHORT_BRANDS, TRUSTED_DOMAINS
from phishguard.sanitize import domain_skeleton


@dataclass
class SquatResult:
    kind: str  # "homoglyph" | "typosquat" | "combosquat"
    brand: str
    label: str
    distance: int = 0


def damerau_levenshtein(a: str, b: str, max_dist: int | None = None) -> int:
    """Optimal-string-alignment distance (transpositions count as 1 edit)."""
    if a == b:
        return 0
    la, lb = len(a), len(b)
    if max_dist is not None and abs(la - lb) > max_dist:
        return max_dist + 1
    prev2: list[int] = []
    prev = list(range(lb + 1))
    for i in range(1, la + 1):
        cur = [i] + [0] * lb
        row_min = cur[0]
        for j in range(1, lb + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                cur[j] = min(cur[j], prev2[j - 2] + 1)
            row_min = min(row_min, cur[j])
        if max_dist is not None and row_min > max_dist:
            return max_dist + 1
        prev2, prev = prev, cur
    return prev[lb]


def _allowed_distance(brand: str) -> int:
    if len(brand) <= 4:
        return 0  # too short: "ups" vs "ops" would be noise; rely on homoglyph only
    if len(brand) <= 8:
        return 1
    return 2


@lru_cache(maxsize=1)
def _brand_skeletons() -> dict[str, str]:
    return {brand: domain_skeleton(brand) for brand in BRAND_DOMAINS}


def is_official(registered_domain: str) -> bool:
    return registered_domain in TRUSTED_DOMAINS


def brand_owner(registered_domain: str) -> str | None:
    for brand, domains in BRAND_DOMAINS.items():
        if registered_domain in domains:
            return brand
    return None


def check_label(label: str, registered_domain: str) -> SquatResult | None:
    """Check a single domain label (the part left of the public suffix)."""
    if not label or is_official(registered_domain):
        return None
    label_l = label.lower()
    skel = domain_skeleton(label_l)
    plain = label_l.replace("-", "")
    best: SquatResult | None = None
    for brand, bskel in _brand_skeletons().items():
        # 1. homoglyph / leet: visually identical but different characters
        if skel == bskel and plain != brand:
            return SquatResult("homoglyph", brand, label)
        # 2. exact brand label on an unofficial suffix (paypal.xyz, sbi.top)
        if plain == brand and len(brand) >= 3:
            return SquatResult("combosquat", brand, label)
        # 3. small edit distance
        allowed = _allowed_distance(brand)
        if allowed:
            d = damerau_levenshtein(plain, brand, allowed)
            if 0 < d <= allowed and len(plain) >= len(brand) - 1:
                cand = SquatResult("typosquat", brand, label, d)
                if best is None or best.kind != "typosquat" or d < best.distance:
                    best = cand
                continue
        # 4. brand embedded with extra tokens (paypal-secure, sbikyc, hdfcnetbanking)
        if best is None and brand not in SHORT_BRANDS and len(brand) >= 5 and brand in skel:
            best = SquatResult("combosquat", brand, label)
        elif best is None and brand in SHORT_BRANDS and len(brand) >= 3:
            tokens = label_l.split("-")
            if brand in tokens or (skel.startswith(brand) and _looks_like_brand_prefix(skel, brand)):
                best = SquatResult("combosquat", brand, label)
    return best


_LURE_SUFFIXES = ("kyc", "login", "online", "update", "verify", "secure", "bank", "netbanking",
                  "rewards", "reward", "card", "help", "support", "care", "pay", "upi", "alert")


def _looks_like_brand_prefix(skel: str, brand: str) -> bool:
    """For short brands (sbi, hdfc...) only flag 'sbi' + known lure word."""
    rest = skel[len(brand):]
    return any(rest.startswith(s) or rest.endswith(s) for s in _LURE_SUFFIXES)


def find_brand_tokens(text: str, min_len: int = 5) -> set[str]:
    """Brands mentioned as substrings (used for subdomain/path brand checks)."""
    t = domain_skeleton(text)
    return {b for b, s in _brand_skeletons().items() if len(b) >= min_len and s in t}
