"""External intelligence (optional, off by default)."""

from __future__ import annotations

from phishguard.config import Settings
from phishguard.intel.base import IntelProvider, IntelResult, run_providers
from phishguard.intel.probing import RedirectChainProbe, TLSCertificateProbe
from phishguard.intel.providers import GoogleSafeBrowsing, OpenPhishFeed, PhishTank, RDAPDomainAge, VirusTotal

__all__ = ["IntelProvider", "IntelResult", "build_providers", "run_providers"]


def build_providers(settings: Settings) -> list[IntelProvider]:
    providers: list[IntelProvider] = [OpenPhishFeed(settings.openphish_feed_file)]  # offline, always safe
    if settings.enable_network_intel:
        t = settings.intel_timeout_s
        providers += [GoogleSafeBrowsing(t), PhishTank(t), VirusTotal(t), RDAPDomainAge(t)]
    if settings.enable_active_probing:
        providers += [RedirectChainProbe(settings.probe_timeout_s, settings.probe_max_redirects),
                      TLSCertificateProbe(settings.probe_timeout_s)]
    return providers
