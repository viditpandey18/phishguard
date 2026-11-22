"""End-to-end labeled cases (safe / scam / phishing across text, URL, email)."""

import pytest

from conftest import load_cases

CASES = load_cases()


def test_case_count_and_coverage():
    assert len(CASES) >= 20
    expected = {lab for c in CASES for lab in c["expected"]}
    assert {"safe", "scam", "phishing"} <= expected
    assert {c["input_type"] for c in CASES} == {"text", "url", "email"}


@pytest.mark.parametrize("case", CASES, ids=[c["id"] for c in CASES])
def test_labeled_case(analyzer, case):
    r = analyzer.analyze(case["content"], case["input_type"])
    assert r.label in case["expected"], (
        f"{case['id']}: got {r.label} ({r.risk_score}); flags={[f.id for f in r.red_flags]}")
    # Every non-safe verdict must be explained by at least one concrete red flag.
    if r.label != "safe":
        assert r.red_flags and all(f.description for f in r.red_flags)
    assert 0 <= r.risk_score <= 100 and 0 <= r.confidence <= 1


@pytest.mark.parametrize("case", [c for c in CASES if c["input_type"] != "email"], ids=lambda c: c["id"])
def test_auto_detection_matches_declared_type(analyzer, case):
    r = analyzer.analyze(case["content"], "auto")
    assert r.input_type == case["input_type"]
