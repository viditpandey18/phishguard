import json

import pytest
from fastapi.testclient import TestClient

from phishguard.analyzer import Analyzer
from phishguard.api.main import create_app
from phishguard.config import Settings


@pytest.fixture
def make_client(tmp_path):
    def _make(**overrides) -> TestClient:
        s = Settings(artifacts_dir=tmp_path / "a", text_model="none", feedback_file=tmp_path / "fb.jsonl",
                     log_json=False, **overrides)
        app = create_app(s, analyzer=Analyzer(s, text_model=None, providers=[]))
        return TestClient(app)
    return _make


def test_scan_text_response_shape(make_client):
    with make_client() as c:
        r = c.post("/v1/scan/text", json={"text": "Your KYC expired. Share OTP to avoid account block: http://sbi-kyc.top/x"})
        assert r.status_code == 200
        body = r.json()
        assert body["label"] in ("phishing", "scam") and body["risk_score"] >= 70
        assert body["red_flags"] and body["explanation"] and body["recommended_action"]
        # URLs are returned defanged so UIs never render a live link.
        assert all("hxxp" in u or "[.]" in u for u in body["urls_analyzed"])
        assert r.headers["x-content-type-options"] == "nosniff"
        assert "default-src 'none'" in r.headers["content-security-policy"]


def test_scan_url_and_auto(make_client):
    with make_client() as c:
        assert c.post("/v1/scan/url", json={"url": "https://github.com"}).json()["label"] == "safe"
        r = c.post("/v1/scan", json={"content": "http://paypa1.com/signin"}).json()
        assert r["input_type"] == "url" and r["label"] == "phishing"


def test_scan_email_and_upload(make_client):
    eml = ("From: \"PayPal\" <x@paypa1-help.com>\nSubject: Account limited\nAuthentication-Results: mx; dmarc=fail\n"
           "Content-Type: text/plain\n\nVerify your password within 24 hours: http://paypa1-help.com/login\n")
    with make_client() as c:
        assert c.post("/v1/scan/email", json={"raw": eml}).json()["label"] == "phishing"
        r = c.post("/v1/scan/email/upload", files={"file": ("m.eml", eml.encode(), "message/rfc822")})
        assert r.status_code == 200 and r.json()["input_type"] == "email"


def test_validation_and_size_limits(make_client):
    with make_client(max_request_bytes=5_000) as c:
        assert c.post("/v1/scan/text", json={"text": ""}).status_code == 422
        assert c.post("/v1/scan/text", json={"text": "hi", "extra": 1}).status_code == 422
        assert c.post("/v1/scan/text", json={"text": "x" * 10_000}).status_code == 413
    with make_client(max_text_chars=50) as c:
        assert c.post("/v1/scan", json={"content": "word " * 30}).status_code == 413


def test_rate_limit(make_client):
    with make_client(rate_limit_per_minute=1, rate_limit_burst=2) as c:
        codes = [c.post("/v1/scan/url", json={"url": "https://example.com"}).status_code for _ in range(4)]
        assert codes[:2] == [200, 200] and 429 in codes[2:]


def test_api_key_auth(make_client):
    with make_client(api_keys="secret-key-1") as c:
        assert c.post("/v1/scan/url", json={"url": "https://a.com"}).status_code == 401
        ok = c.post("/v1/scan/url", json={"url": "https://a.com"}, headers={"x-api-key": "secret-key-1"})
        assert ok.status_code == 200


def test_feedback_stores_features_not_content(make_client, tmp_path):
    secret = "Share OTP 991122 with agent Ravi at 9876543210"
    with make_client() as c:
        scan = c.post("/v1/scan/text", json={"text": secret}).json()
        fb = c.post("/v1/feedback", json={"scan_id": scan["scan_id"], "correct_label": "scam",
                                          "comment": "sender was 9876543210"})
        assert fb.status_code == 200 and fb.json()["stored_features"] is True
    stored = (tmp_path / "fb.jsonl").read_text(encoding="utf-8")
    assert "991122" not in stored and "9876543210" not in stored and "Ravi" not in stored
    rec = json.loads(stored.splitlines()[0])
    assert rec["features"] and rec["correct_label"] == "scam"


def test_web_ui_served_with_strict_csp(make_client):
    with make_client() as c:
        assert c.get("/", follow_redirects=False).headers["location"] == "/ui/"
        page = c.get("/ui/")
        assert page.status_code == 200 and "PhishGuard" in page.text
        csp = page.headers["content-security-policy"]
        assert "script-src 'self'" in csp and "unsafe-inline" not in csp and "frame-ancestors 'none'" in csp
        js = c.get("/ui/app.js").text
        assert ".innerHTML" not in js and ".outerHTML" not in js  # API output only inserted as text
        # JSON endpoints keep the locked-down policy
        assert c.get("/healthz").headers["content-security-policy"].startswith("default-src 'none'")
    with make_client(enable_web_ui=False) as c:
        assert c.get("/ui/").status_code == 404


def test_health_and_info(make_client):
    with make_client() as c:
        assert c.get("/healthz").json() == {"status": "ok"}
        info = c.get("/v1/info").json()
        assert info["stores_content"] is False and "thresholds" in info
