"""Robustness: obfuscated variants of malicious samples must stay non-safe."""

import pytest

from conftest import load_cases
from phishguard.eval.adversarial import TEXT_ATTACKS, URL_ATTACKS, url_decimal_ip

MALICIOUS_TEXT = [c for c in load_cases() if c["input_type"] == "text" and "safe" not in c["expected"]]
MALICIOUS_URL = [c for c in load_cases() if c["input_type"] == "url" and "safe" not in c["expected"]
                 and c["content"].startswith("http")]


@pytest.mark.parametrize("attack", sorted(TEXT_ATTACKS))
def test_text_attacks_do_not_evade(analyzer, attack):
    fn = TEXT_ATTACKS[attack]
    evaded = []
    for c in MALICIOUS_TEXT:
        if analyzer.analyze(fn(c["content"]), "text").label == "safe":
            evaded.append(c["id"])
    # Allow at most 10% evasion per attack (documented in the evaluation report).
    assert len(evaded) <= max(1, len(MALICIOUS_TEXT) // 10), f"{attack} evaded on {evaded}"


@pytest.mark.parametrize("attack", sorted(URL_ATTACKS))
def test_url_attacks_do_not_evade(analyzer, attack):
    for c in MALICIOUS_URL:
        r = analyzer.analyze(URL_ATTACKS[attack](c["content"]), "url")
        assert r.label != "safe", f"{attack} evaded on {c['id']}"


def test_decimal_ip_still_flagged(analyzer):
    r = analyzer.analyze(url_decimal_ip("http://45.67.89.12/sbi/login.php"), "url")
    assert "url.ip_host" in {f.id for f in r.red_flags}


def test_good_link_cannot_launder_bad_link(analyzer):
    text = "Verify now at https://www.google.com and http://paypa1-secure.com/login to avoid suspension"
    r = analyzer.analyze(text, "text")
    assert "url.trusted_domain" not in {f.id for f in r.mitigating_factors}
    assert r.label in ("phishing", "scam")
