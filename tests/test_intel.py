import pytest

from phishguard.config import Settings
from phishguard.intel import build_providers, run_providers
from phishguard.intel.probing import UnsafeTargetError, assert_public_host
from phishguard.intel.providers import GoogleSafeBrowsing, OpenPhishFeed


def test_network_providers_off_by_default():
    names = {p.name for p in build_providers(Settings())}
    assert names == {"openphish_local"}  # offline-only by default
    assert not any(p.active for p in build_providers(Settings(enable_network_intel=True)))


def test_missing_api_keys_are_skipped(monkeypatch):
    monkeypatch.delenv("GSB_API_KEY", raising=False)
    res = run_providers([GoogleSafeBrowsing(1.0)], "http://x.example", "x.example")
    assert res[0].status == "skipped"


def test_local_openphish_feed(tmp_path):
    feed = tmp_path / "feed.txt"
    feed.write_text("http://evil.example/login\nhttps://bad.example/\n")
    p = OpenPhishFeed(feed)
    assert p.check("http://evil.example/login", "evil.example")[0].id == "intel.blocklisted"
    assert p.check("http://good.example/", "good.example") == []


@pytest.mark.parametrize("host", ["127.0.0.1", "localhost", "10.0.0.5", "169.254.169.254", "192.168.1.1", "::1"])
def test_ssrf_guard_blocks_internal_targets(host):
    with pytest.raises(UnsafeTargetError):
        assert_public_host(host)


def test_provider_errors_are_contained():
    class Boom(OpenPhishFeed):
        name = "boom"

        def available(self):
            return True

        def check(self, url, rd):
            raise RuntimeError("down")

    assert run_providers([Boom(None)], "http://x", "x")[0].status == "error"
