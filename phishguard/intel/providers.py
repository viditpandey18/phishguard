"""Passive threat-intel providers. API keys come from env vars only."""

from __future__ import annotations

import base64
import os
from datetime import datetime, timezone
from pathlib import Path

import httpx

from phishguard.intel.base import IntelProvider
from phishguard.signals import Signal

_UA = "phishguard-intel/1.0"  # generic client id; no user/org details


class OpenPhishFeed(IntelProvider):
    """Lookup against a *locally downloaded* OpenPhish feed - nothing leaves the host."""

    name = "openphish_local"

    def __init__(self, feed_file: Path | None) -> None:
        self.feed_file = feed_file
        self._urls: set[str] | None = None
        self._hosts: set[str] = set()

    def available(self) -> bool:
        return bool(self.feed_file and Path(self.feed_file).exists())

    def _load(self) -> None:
        if self._urls is None:
            lines = Path(self.feed_file).read_text(encoding="utf-8", errors="ignore").splitlines()
            self._urls = {l.strip().rstrip("/").lower() for l in lines if l.strip()}
            self._hosts = {u.split("://", 1)[-1].split("/", 1)[0] for u in self._urls}

    def check(self, url: str, registered_domain: str) -> list[Signal]:
        self._load()
        u = url.strip().rstrip("/").lower()
        host = u.split("://", 1)[-1].split("/", 1)[0]
        if u in self._urls:
            return [Signal("intel.blocklisted", "exact URL listed in OpenPhish feed")]
        if host in self._hosts:
            return [Signal("intel.blocklisted", "host listed in OpenPhish feed", strength=0.8)]
        return []


class GoogleSafeBrowsing(IntelProvider):
    """Safe Browsing Lookup API v4. Discloses the URL to Google."""

    name = "google_safe_browsing"
    endpoint = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

    def __init__(self, timeout: float) -> None:
        self.key = os.getenv("GSB_API_KEY", "")
        self.timeout = timeout

    def available(self) -> bool:
        return bool(self.key)

    def check(self, url: str, registered_domain: str) -> list[Signal]:
        body = {
            "client": {"clientId": "phishguard", "clientVersion": "1.0"},
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                "platformTypes": ["ANY_PLATFORM"], "threatEntryTypes": ["URL"], "threatEntries": [{"url": url}],
            },
        }
        r = httpx.post(self.endpoint, params={"key": self.key}, json=body, timeout=self.timeout, headers={"User-Agent": _UA})
        r.raise_for_status()
        matches = r.json().get("matches", [])
        if matches:
            return [Signal("intel.blocklisted", f"Google Safe Browsing: {matches[0].get('threatType', 'listed')}")]
        return []


class PhishTank(IntelProvider):
    name = "phishtank"
    endpoint = "https://checkurl.phishtank.com/checkurl/"

    def __init__(self, timeout: float) -> None:
        self.key = os.getenv("PHISHTANK_APP_KEY", "")
        self.timeout = timeout

    def available(self) -> bool:
        return bool(self.key)

    def check(self, url: str, registered_domain: str) -> list[Signal]:
        r = httpx.post(self.endpoint, data={"url": url, "format": "json", "app_key": self.key},
                       timeout=self.timeout, headers={"User-Agent": "phishtank/phishguard"})
        r.raise_for_status()
        res = r.json().get("results", {})
        if res.get("in_database") and res.get("valid"):
            return [Signal("intel.blocklisted", "PhishTank: verified phish")]
        return []


class VirusTotal(IntelProvider):
    """VirusTotal v3 URL report lookup (does not submit new URLs for scanning)."""

    name = "virustotal"

    def __init__(self, timeout: float) -> None:
        self.key = os.getenv("VT_API_KEY", "")
        self.timeout = timeout

    def available(self) -> bool:
        return bool(self.key)

    def check(self, url: str, registered_domain: str) -> list[Signal]:
        url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
        r = httpx.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", timeout=self.timeout,
                      headers={"x-apikey": self.key, "User-Agent": _UA})
        if r.status_code == 404:
            return []
        r.raise_for_status()
        stats = r.json()["data"]["attributes"].get("last_analysis_stats", {})
        mal = int(stats.get("malicious", 0)) + int(stats.get("phishing", 0))
        if mal >= 3:
            return [Signal("intel.blocklisted", f"VirusTotal: {mal} engines flag this URL")]
        if mal >= 1:
            return [Signal("intel.blocklisted", f"VirusTotal: {mal} engine(s) flag this URL", strength=0.4)]
        return []


class RDAPDomainAge(IntelProvider):
    """Domain registration date via RDAP (modern WHOIS). Sends the domain only."""

    name = "rdap_domain_age"

    def __init__(self, timeout: float) -> None:
        self.timeout = timeout

    def check(self, url: str, registered_domain: str) -> list[Signal]:
        if not registered_domain or registered_domain.replace(".", "").isdigit():
            return []
        r = httpx.get(f"https://rdap.org/domain/{registered_domain}", timeout=self.timeout,
                      follow_redirects=True, headers={"User-Agent": _UA, "Accept": "application/rdap+json"})
        if r.status_code != 200:
            return []
        for ev in r.json().get("events", []):
            if ev.get("eventAction") == "registration":
                created = datetime.fromisoformat(ev["eventDate"].replace("Z", "+00:00"))
                age_days = (datetime.now(timezone.utc) - created).days
                if age_days < 7:
                    return [Signal("intel.young_domain", f"registered {age_days} day(s) ago", strength=1.3)]
                if age_days < 60:
                    return [Signal("intel.young_domain", f"registered {age_days} days ago")]
        return []
