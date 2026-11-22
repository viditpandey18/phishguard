"""Top-level orchestration: detect input type -> run layers -> ensemble -> response."""

from __future__ import annotations

import logging
import re
import time
import uuid
from collections import OrderedDict
from dataclasses import dataclass, field
from threading import Lock

from phishguard.config import Settings, get_settings
from phishguard.ensemble import EnsembleScorer, Verdict, build_explanation
from phishguard.features.email_parser import EmailDoc, looks_like_email, parse_email
from phishguard.features.header_features import analyze_attachments, analyze_headers, analyze_html
from phishguard.features.text_features import analyze_text
from phishguard.features.url_features import URLReport, analyze_url, extract_urls
from phishguard.intel import IntelProvider, IntelResult, build_providers, run_providers
from phishguard.models.text_model import TextModel, load_text_model
from phishguard.sanitize import enforce_limit, normalize_text, refang
from phishguard.schemas import IntelStatus, ModelInfo, RedFlag, ScanResponse
from phishguard.signals import SIGNAL_SPECS, Signal

log = logging.getLogger(__name__)

_SINGLE_URL_RE = re.compile(r"^\s*(?:(?:https?|hxxps?|ftp)://|www\.)?[^\s/]+\.[^\s/]{2,}(?:[/?#]\S*)?\s*$|^\s*(javascript|data):\S+\s*$", re.I)
_SIGNAL_IDS = sorted(SIGNAL_SPECS)


def detect_input_type(content: str) -> str:
    if looks_like_email(content):
        return "email"
    stripped = refang(content.strip())
    if "\n" not in stripped and " " not in stripped and _SINGLE_URL_RE.match(stripped):
        return "url"
    return "text"


@dataclass
class _Collected:
    signals: list[Signal] = field(default_factory=list)
    url_reports: list[URLReport] = field(default_factory=list)
    intel: list[IntelResult] = field(default_factory=list)
    model_prob: float | None = None
    model_terms: list[tuple[str, float]] = field(default_factory=list)


class _FeatureCache:
    """Short-lived scan_id -> signal-vector cache so user feedback can be linked to
    *features* (never content) for active learning."""

    def __init__(self, max_items: int = 5000) -> None:
        self._data: OrderedDict[str, tuple[float, dict]] = OrderedDict()
        self._lock = Lock()
        self.max_items = max_items

    def put(self, key: str, value: dict) -> None:
        with self._lock:
            self._data[key] = (time.time(), value)
            while len(self._data) > self.max_items:
                self._data.popitem(last=False)

    def get(self, key: str, ttl: float = 3600) -> dict | None:
        with self._lock:
            item = self._data.get(key)
        if item and time.time() - item[0] < ttl:
            return item[1]
        return None


class Analyzer:
    def __init__(self, settings: Settings | None = None, text_model: TextModel | None | str = "auto",
                 scorer: EnsembleScorer | None = None, providers: list[IntelProvider] | None = None) -> None:
        self.settings = settings or get_settings()
        s = self.settings
        if text_model == "auto":
            text_model = load_text_model(s.text_model, s.artifacts_dir, s.transformer_model_dir)
        self.text_model: TextModel | None = text_model  # type: ignore[assignment]
        if scorer is None:
            kw = dict(threshold_suspicious=s.threshold_suspicious, threshold_malicious=s.threshold_malicious)
            weights_file = s.ensemble_weights_file or (s.artifacts_dir / "ensemble_weights.json")
            scorer = EnsembleScorer.from_file(weights_file, **kw) if weights_file.exists() else EnsembleScorer(**kw)
        self.scorer = scorer
        self.providers = build_providers(s) if providers is None else providers
        self.feature_cache = _FeatureCache()

    # ------------------------------------------------------------------ public
    def analyze(self, content: str | bytes, input_type: str = "auto") -> ScanResponse:
        t0 = time.perf_counter()
        if isinstance(content, bytes):
            enforce_limit(content, self.settings.max_email_bytes, "email")
            input_type = "email" if input_type == "auto" else input_type
            if input_type != "email":
                content = content.decode("utf-8", errors="replace")
        if input_type == "auto":
            input_type = detect_input_type(content)  # type: ignore[arg-type]

        if input_type == "url":
            col = self._scan_url(content)  # type: ignore[arg-type]
        elif input_type == "email":
            col = self._scan_email(content)
        else:
            col = self._scan_text(content)  # type: ignore[arg-type]

        verdict = self.scorer.score(col.signals, col.model_prob, input_type)
        scan_id = uuid.uuid4().hex
        self.feature_cache.put(scan_id, {
            "input_type": input_type, "label": verdict.label, "probability": verdict.probability,
            "features": {sid: s.strength for sid, s in EnsembleScorer.dedupe(col.signals).items()},
            "model_prob": col.model_prob,
        })
        resp = self._build_response(scan_id, input_type, verdict, col, (time.perf_counter() - t0) * 1000)
        log.info("scan complete", extra={"scan_id": scan_id, "input_type": input_type, "label": verdict.label,
                                         "risk_score": verdict.risk_score, "latency_ms": resp.latency_ms,
                                         "n_signals": len(verdict.contributions)})
        return resp

    def signal_vector(self, content: str | bytes, input_type: str = "auto") -> tuple[list[Signal], float | None, str]:
        """Raw signals for training the ensemble (no scoring)."""
        if input_type == "auto":
            input_type = "email" if isinstance(content, bytes) else detect_input_type(content)
        col = {"url": self._scan_url, "email": self._scan_email}.get(input_type, self._scan_text)(content)
        return col.signals, col.model_prob, input_type

    # ------------------------------------------------------------------ layers
    def _scan_url(self, url: str) -> _Collected:
        enforce_limit(url, self.settings.max_url_chars, "url")
        rep = analyze_url(url.strip())
        col = _Collected(signals=list(rep.signals), url_reports=[rep])
        self._run_intel(col, [rep])
        return col

    def _urls_from(self, text: str, extra: list[str] | None = None) -> list[URLReport]:
        urls = list(dict.fromkeys((extra or []) + extract_urls(text, self.settings.max_urls_per_input)))
        return [analyze_url(u) for u in urls[: self.settings.max_urls_per_input]]

    def _add_url_signals(self, col: _Collected, reports: list[URLReport]) -> None:
        col.url_reports.extend(reports)
        all_trusted = bool(reports) and all(any(s.id == "url.trusted_domain" for s in r.signals) for r in reports)
        for r in reports:
            for s in r.signals:
                # "trusted domain" only mitigates if *every* link is trusted; one
                # good link must not launder a malicious one in the same message.
                if s.id == "url.trusted_domain" and not all_trusted:
                    continue
                col.signals.append(Signal(s.id, f"{r.display}: {s.evidence}", s.strength))
        self._run_intel(col, reports)

    def _scan_text(self, text: str) -> _Collected:
        norm = normalize_text(text, self.settings.max_text_chars)
        col = _Collected(signals=list(analyze_text(norm).signals))
        self._add_url_signals(col, self._urls_from(norm.clean))
        self._apply_model(col, norm.clean)
        return col

    def _scan_email(self, raw: str | bytes) -> _Collected:
        enforce_limit(raw, self.settings.max_email_bytes, "email")
        doc: EmailDoc = parse_email(raw)
        col = _Collected()
        col.signals += analyze_headers(doc) + analyze_attachments(doc) + analyze_html(doc)
        body = f"{doc.subject}\n{doc.body}"[: self.settings.max_text_chars]
        norm = normalize_text(body, self.settings.max_text_chars)
        col.signals += analyze_text(norm).signals
        hrefs = [a.href for a in doc.anchors if a.href and not a.href.lower().startswith(("mailto:", "tel:", "#", "cid:"))]
        self._add_url_signals(col, self._urls_from(norm.clean, hrefs))
        self._apply_model(col, norm.clean)
        return col

    def _apply_model(self, col: _Collected, text: str) -> None:
        if self.text_model is None or len(text.strip()) < 8:
            return
        try:
            col.model_prob = self.text_model.predict_proba(text)
            col.model_terms = [(t, round(v, 3)) for t, v in self.text_model.explain(text, 5) if v > 0]
        except Exception as exc:
            log.error("text model failed", extra={"error": type(exc).__name__})

    def _run_intel(self, col: _Collected, reports: list[URLReport]) -> None:
        if not self.providers or not reports:
            return
        # Only enrich the riskiest few URLs: bounds latency and third-party disclosure.
        ranked = sorted(reports, key=lambda r: -sum(SIGNAL_SPECS[s.id].weight * s.strength for s in r.signals))[:3]
        for r in ranked:
            if r.parsed is None or any(s.id == "url.trusted_domain" for s in r.signals):
                continue
            results = run_providers(self.providers, r.url, r.parsed.registered_domain, budget_s=8.0)
            col.intel.extend(results)
            for res in results:
                col.signals.extend(res.signals)

    # ---------------------------------------------------------------- response
    def _build_response(self, scan_id: str, input_type: str, v: Verdict, col: _Collected, latency: float) -> ScanResponse:
        def flag(c) -> RedFlag:
            sev = "high" if abs(c.contribution) >= 2 else "medium" if abs(c.contribution) >= 1 else "low"
            return RedFlag(id=c.id, layer=c.layer, severity=sev, description=c.description,
                           evidence=c.evidence[:200], contribution=c.contribution)

        explanation, action = build_explanation(v, input_type)
        level = "high" if v.confidence >= 0.9 else "medium" if v.confidence >= 0.7 else "low"
        return ScanResponse(
            scan_id=scan_id, input_type=input_type, label=v.label, risk_score=v.risk_score,
            probability=v.probability, confidence=v.confidence, confidence_level=level,
            explanation=explanation, recommended_action=action,
            red_flags=[flag(c) for c in v.contributions if c.contribution > 0],
            mitigating_factors=[flag(c) for c in v.contributions if c.contribution < 0],
            layer_scores=v.layer_scores,
            urls_analyzed=[r.display for r in col.url_reports][:25],
            model_terms=col.model_terms,
            intel=[IntelStatus(provider=i.provider, status=i.status, detail=i.detail) for i in col.intel],
            model=ModelInfo(ensemble_version=self.scorer.version,
                            text_model=getattr(self.text_model, "name", None),
                            calibrated=self.scorer.calibrator is not None),
            latency_ms=round(latency, 2),
        )
