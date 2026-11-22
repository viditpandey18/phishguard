"""Input normalisation and de-obfuscation.

Attackers routinely evade keyword/ML filters with:
  * zero-width / invisible characters inside words ("pa​ypal")
  * Unicode compatibility forms (fullwidth "ＰａｙＰａｌ", math bold "𝐏𝐚𝐲𝐏𝐚𝐥")
  * cross-script homoglyphs (Cyrillic "раypal")
  * defanged / obfuscated URLs ("hxxps://evil[.]com")

We produce several *views* of the input so each detector can pick the right
one, and we record what we removed - the obfuscation itself is a red flag.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field

# Invisible / formatting characters abused for filter evasion.
_INVISIBLE_CHARS = (
    "​‌‍‎‏"  # zero-width space/non-joiner/joiner, LRM/RLM
    "⁠⁡⁢⁣⁤"  # word joiner, invisible operators
    "﻿­͏᠎ᅟᅠㅤﾠ"  # BOM, soft hyphen, fillers
    "‪‫‬‭‮"  # bidi embeddings/overrides (RLO trick)
    "⁦⁧⁨⁩"  # bidi isolates
)
_INVISIBLE_RE = re.compile(f"[{_INVISIBLE_CHARS}]")
_INVISIBLE_NON_JOINER_RE = re.compile(
    "[" + _INVISIBLE_CHARS.replace("‌", "").replace("‍", "") + "]"
)
# ZWJ/ZWNJ are legitimately used inside Devanagari conjuncts; only count them
# as obfuscation when adjacent to Latin letters.
_ZW_JOINERS_LATIN_RE = re.compile(r"(?<=[A-Za-z])[‌‍]|[‌‍](?=[A-Za-z])")
_CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")

# Cross-script confusables -> Latin. A focused subset of Unicode TR39
# confusables covering the characters seen in real phishing campaigns.
CONFUSABLES: dict[str, str] = {
    # Cyrillic
    "а": "a", "в": "b", "с": "c", "ԁ": "d", "е": "e", "һ": "h", "і": "i", "ј": "j",
    "к": "k", "ӏ": "l", "м": "m", "п": "n", "о": "o", "р": "p", "ԛ": "q", "г": "r",
    "ѕ": "s", "т": "t", "ц": "u", "ѵ": "v", "ԝ": "w", "х": "x", "у": "y", "ʐ": "z",
    "А": "a", "В": "b", "С": "c", "Е": "e", "Н": "h", "І": "i", "Ј": "j", "К": "k",
    "М": "m", "О": "o", "Р": "p", "Ѕ": "s", "Т": "t", "Х": "x", "У": "y", "ё": "e",
    # Greek
    "α": "a", "β": "b", "ε": "e", "η": "n", "ι": "i", "κ": "k", "ν": "v", "ο": "o",
    "ρ": "p", "τ": "t", "υ": "u", "χ": "x", "Α": "a", "Β": "b", "Ε": "e", "Η": "h",
    "Ι": "i", "Κ": "k", "Μ": "m", "Ν": "n", "Ο": "o", "Ρ": "p", "Τ": "t", "Χ": "x",
    "Υ": "y", "Ζ": "z",
    # Latin look-alikes / IPA
    "ɑ": "a", "ɡ": "g", "ɩ": "i", "ı": "i", "ȷ": "j", "ʟ": "l", "ɴ": "n", "ᴏ": "o",
    "ʀ": "r", "ꜱ": "s", "ᴛ": "t", "ᴜ": "u", "ᴠ": "v", "ᴡ": "w", "ʏ": "y", "ᴢ": "z",
    "ł": "l", "ɫ": "l", "đ": "d", "ħ": "h",
    # Armenian / Cherokee commonly abused
    "օ": "o", "ս": "u", "ց": "g", "հ": "h", "Ꭺ": "a", "Ꮯ": "c", "Ꭼ": "e", "Ꮋ": "h",
}
_CONFUSABLE_TABLE = str.maketrans(CONFUSABLES)

# Digit/leet substitutions used ONLY for domain-label skeletons (never applied
# to message text, where digits carry meaning, e.g. OTPs and amounts).
LEET: dict[str, str] = {"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b",
                        "$": "s", "@": "a", "!": "i", "|": "l"}
_LEET_TABLE = str.maketrans(LEET)
_MULTI_CHAR_CONFUSABLES = (("rn", "m"), ("vv", "w"), ("cl", "d"), ("nn", "m"))

_DEFANG_PATTERNS = [
    (re.compile(r"\bhxxp(s?)://", re.I), r"http\1://"),
    (re.compile(r"\bhxxp(s?)\[:\]//", re.I), r"http\1://"),
    (re.compile(r"\[(\.|dot)\]|\((\.|dot)\)|\{(\.|dot)\}", re.I), "."),
    (re.compile(r"\s\[dot\]\s|\s\(dot\)\s", re.I), "."),
    (re.compile(r"\[:\]"), ":"),
    (re.compile(r"\[/\]"), "/"),
]


class InputTooLargeError(ValueError):
    """Raised when an input exceeds configured size limits."""


@dataclass
class NormalizedText:
    original_length: int
    clean: str  # NFKC + invisibles/control chars removed (case preserved)
    deconfused: str  # clean + cross-script homoglyphs mapped to Latin, lowercased
    invisible_count: int = 0
    nfkc_changed: bool = False
    mixed_script_words: list[str] = field(default_factory=list)


def enforce_limit(value: str | bytes, limit: int, what: str) -> None:
    if len(value) > limit:
        raise InputTooLargeError(f"{what} exceeds limit of {limit} ({len(value)} given)")


def strip_invisibles(text: str) -> tuple[str, int]:
    """Remove invisible chars; return (text, number_removed)."""
    text, n_joiners = _ZW_JOINERS_LATIN_RE.subn("", text)
    # ZWJ/ZWNJ not touching Latin letters are kept (needed for Indic shaping).
    text, n_other = _INVISIBLE_NON_JOINER_RE.subn("", text)
    return text, n_joiners + n_other


def _script_of(ch: str) -> str | None:
    if not ch.isalpha():
        return None
    try:
        name = unicodedata.name(ch)
    except ValueError:
        return None
    for script in ("LATIN", "CYRILLIC", "GREEK", "ARMENIAN", "CHEROKEE", "DEVANAGARI"):
        if name.startswith(script):
            return script
    return "OTHER"


def find_mixed_script_words(text: str, limit: int = 10) -> list[str]:
    """Words that mix Latin with Cyrillic/Greek/Armenian/Cherokee letters.

    Mixing Latin + Devanagari is normal in Hinglish, so it is not flagged.
    """
    found: list[str] = []
    for word in re.findall(r"\w+", text):
        scripts = {s for s in (_script_of(c) for c in word) if s}
        if "LATIN" in scripts and scripts & {"CYRILLIC", "GREEK", "ARMENIAN", "CHEROKEE"}:
            found.append(word)
            if len(found) >= limit:
                break
    return found


_SPACED_LETTERS_RE = re.compile(r"(?<![\w])(?:[A-Za-z][ .\-_*]){2,}[A-Za-z](?![\w])")


def collapse_spaced_letters(text: str) -> str:
    """'O T P' / 'K.Y.C' -> 'OTP' / 'KYC' (evasion of keyword filters)."""
    return _SPACED_LETTERS_RE.sub(lambda m: re.sub(r"[ .\-_*]", "", m.group(0)), text)


def deconfuse(text: str) -> str:
    return collapse_spaced_letters(text.translate(_CONFUSABLE_TABLE)).lower()


def domain_skeleton(label: str) -> str:
    """Aggressive skeleton for *domain labels* only: homoglyphs, leet, rn->m."""
    s = deconfuse(label).translate(_LEET_TABLE)
    for src, dst in _MULTI_CHAR_CONFUSABLES:
        s = s.replace(src, dst)
    return s.replace("-", "").replace("_", "")


def refang(text: str) -> str:
    for pattern, repl in _DEFANG_PATTERNS:
        text = pattern.sub(repl, text)
    return text


def defang_url(url: str) -> str:
    """Make a URL non-clickable for safe display in UIs, logs and API output."""
    return url.replace("http", "hxxp", 1).replace(".", "[.]")


def normalize_text(text: str, max_chars: int) -> NormalizedText:
    enforce_limit(text, max_chars, "text")
    original_length = len(text)
    text = _CONTROL_RE.sub(" ", text)
    text, invisible_count = strip_invisibles(text)
    nfkc = unicodedata.normalize("NFKC", text)
    mixed = find_mixed_script_words(nfkc)
    return NormalizedText(
        original_length=original_length,
        clean=nfkc,
        deconfused=deconfuse(nfkc),
        invisible_count=invisible_count,
        nfkc_changed=nfkc != text,
        mixed_script_words=mixed,
    )


def truncate(value: str, n: int = 120) -> str:
    return value if len(value) <= n else value[: n - 1] + "…"
