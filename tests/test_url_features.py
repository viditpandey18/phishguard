import pytest

from phishguard.features.domain import parse_ip, parse_url, split_registered_domain
from phishguard.features.typosquat import check_label, damerau_levenshtein
from phishguard.features.url_features import analyze_url, extract_urls


def ids(url):
    return {s.id for s in analyze_url(url).signals}


@pytest.mark.parametrize("url,signal", [
    ("http://45.67.89.12/login", "url.ip_host"),
    ("http://3232235777/x", "url.ip_host"),  # decimal-encoded IP
    ("http://0xC0A80101/x", "url.ip_host"),  # hex-encoded IP
    ("https://www.paypal.com@evil.example/x", "url.at_symbol"),
    ("https://xn--pypal-4ve.com", "url.punycode"),
    ("https://xn--pypal-4ve.com", "url.homoglyph_brand"),
    ("https://rnicrosoft.com/login", "url.homoglyph_brand"),  # rn -> m
    ("https://hdfcbnak.com", "url.typosquat"),
    ("https://paypal-secure-login.com", "url.combosquat"),
    ("https://paypal.com.account-verify.top/", "url.brand_in_subdomain"),
    ("https://bit.ly/abc", "url.shortener"),
    ("https://example.xyz/", "url.suspicious_tld"),
    ("https://sbi-rewards.web.app/claim", "url.free_hosting"),
    ("http://example.com:8081/x", "url.nonstandard_port"),
    ("javascript:alert(1)", "url.dangerous_scheme"),
    ("https://files.example.net/update/setup.apk", "url.executable_download"),
    ("https://example.com/redirect?u=https%3A%2F%2Fevil.example", "url.embedded_redirect"),
])
def test_url_signal_fires(url, signal):
    assert signal in ids(url)


@pytest.mark.parametrize("url", [
    "https://www.google.com/search?q=x", "https://github.com/a/b", "https://www.hdfcbank.com/personal",
    "https://onlinesbi.sbi/", "https://www.irctc.co.in/nget", "https://accounts.google.com/signin",
])
def test_trusted_urls_have_no_risky_signals(url):
    sig = ids(url)
    assert "url.trusted_domain" in sig
    assert not sig & {"url.typosquat", "url.combosquat", "url.homoglyph_brand", "url.brand_in_subdomain"}


def test_registered_domain_multi_part_suffix():
    assert split_registered_domain("netbanking.hdfcbank.co.in")[1] == "hdfcbank.co.in"
    assert split_registered_domain("a.b.example.com") == ("a.b", "example.com", "com")
    assert parse_url("paypal-login.firebaseapp.com/x").registered_domain == "paypal-login.firebaseapp.com"


def test_parse_ip_variants():
    assert str(parse_ip("0x7f.0.0.1")) == "127.0.0.1"
    assert parse_ip("example.com") is None


def test_extract_urls_defanged_and_bare():
    found = extract_urls("Go to hxxps://evil[.]com/x or sbi-kyc.top/verify. Pay Rs.500, e.g. now.")
    assert "https://evil.com/x" in found
    assert "sbi-kyc.top/verify" in found
    assert not any("Rs.500" in u or u == "e.g" for u in found)


def test_typosquat_helpers():
    assert damerau_levenshtein("paypal", "paypla") == 1  # transposition
    assert check_label("paypal", "paypal.com") is None  # official
    assert check_label("amazom", "amazom.com").kind == "typosquat"
    assert check_label("weather", "weather.com") is None
