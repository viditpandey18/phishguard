import logging

import pytest

from phishguard.logging_utils import RedactingFilter, redact
from phishguard.sanitize import (
    InputTooLargeError,
    defang_url,
    domain_skeleton,
    normalize_text,
    refang,
)


def test_invisible_chars_removed_and_counted():
    n = normalize_text("pa​y​pal ‮evil", 1000)
    assert "paypal" in n.clean and n.invisible_count == 3


def test_devanagari_joiners_preserved():
    n = normalize_text("क्‍ष", 1000)  # ZWJ inside Devanagari is legitimate shaping
    assert n.invisible_count == 0 and "‍" in n.clean


def test_nfkc_and_confusables():
    n = normalize_text("𝐏𝐚𝐲𝐏𝐚𝐥 ＰａｙＰａｌ раypal", 1000)
    assert n.deconfused.count("paypal") == 3


def test_domain_skeleton():
    assert domain_skeleton("paypa1") == domain_skeleton("paypal")
    assert domain_skeleton("rnicrosoft") == domain_skeleton("microsoft")


def test_size_limit():
    with pytest.raises(InputTooLargeError):
        normalize_text("x" * 101, 100)


def test_refang_defang_roundtrip():
    assert refang("hxxps://evil[.]com") == "https://evil.com"
    assert "[.]" in defang_url("https://evil.com") and defang_url("https://evil.com").startswith("hxxps")


@pytest.mark.parametrize("raw,leak", [
    ("mail me at ravi.kumar@example.com", "ravi.kumar@example.com"),
    ("pay to ravi@okaxis", "ravi@okaxis"),
    ("call +91 98765 43210", "98765"),
    ("card 4111 1111 1111 1111", "4111"),
    ("a/c 123456789012", "123456789012"),
    ("PAN ABCDE1234F", "ABCDE1234F"),
    ("OTP is 482913", "482913"),
])
def test_pii_redaction(raw, leak):
    assert leak not in redact(raw)


def test_logging_filter_redacts_args():
    rec = logging.LogRecord("t", logging.INFO, "", 0, "user %s sent %s", ("a@b.com", "9876543210"), None)
    RedactingFilter().filter(rec)
    assert "a@b.com" not in rec.getMessage() and "9876543210" not in rec.getMessage()
