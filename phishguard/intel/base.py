"""Pluggable external-intelligence interface.

Two classes of provider, with different risk profiles:

* PASSIVE - asks a third party about the URL/domain (Safe Browsing,
  PhishTank, VirusTotal, RDAP). Never contacts the suspect server, but the
  URL *is disclosed* to that third party (privacy!). Gated by
  ``PG_ENABLE_NETWORK_INTEL``.
* ACTIVE - connects to the suspect server (TLS cert, redirect chain).
  Gated separately by ``PG_ENABLE_ACTIVE_PROBING`` and intended to run only
  inside the isolated ``sandbox`` container (see docker-compose.yml).

Every provider is optional: missing API keys or failures => skipped, never an error.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field

from phishguard.signals import Signal

log = logging.getLogger(__name__)


@dataclass
class IntelResult:
    provider: str
    status: str  # "ok" | "skipped" | "error" | "timeout"
    signals: list[Signal] = field(default_factory=list)
    detail: str = ""


class IntelProvider:
    name = "base"
    active = False  # True => contacts the suspect host

    def available(self) -> bool:
        return True

    def check(self, url: str, registered_domain: str) -> list[Signal]:
        raise NotImplementedError


def run_providers(providers: list[IntelProvider], url: str, registered_domain: str,
                  budget_s: float = 8.0) -> list[IntelResult]:
    results: list[IntelResult] = []
    deadline = time.monotonic() + budget_s
    for p in providers:
        if time.monotonic() > deadline:
            results.append(IntelResult(p.name, "skipped", detail="time budget exhausted"))
            continue
        if not p.available():
            results.append(IntelResult(p.name, "skipped", detail="not configured"))
            continue
        try:
            results.append(IntelResult(p.name, "ok", p.check(url, registered_domain)))
        except TimeoutError:
            results.append(IntelResult(p.name, "timeout"))
        except Exception as exc:  # provider failures must never break scanning
            log.warning("intel provider failed", extra={"provider": p.name, "error": type(exc).__name__})
            results.append(IntelResult(p.name, "error", detail=type(exc).__name__))
    return results
