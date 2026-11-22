"""Ensemble: combine URL/text/header/model/intel signals into a calibrated verdict.

Scoring is a (learnable) logistic model in log-odds space:

    logit = bias + Σ weight_i * strength_i  [+ w_model * logit(p_text_model)]
    p     = calibrator(logit)        (Platt/isotonic, or plain sigmoid)

Why not gradient boosting as the serving meta-model?
  * Additive log-odds gives *exact* per-signal contributions; for a linear
    model these equal SHAP values w.r.t. an all-zero baseline, so explanations
    are faithful by construction rather than approximated.
  * Weights are 70-odd auditable numbers that security staff can review.
  * It degrades gracefully when a layer is absent (e.g. no headers for SMS).
GBM can capture interactions (e.g. "dmarc fail AND brand display name") and
``training/train_ensemble.py --compare-gbm`` reports whether it is worth the
loss of transparency on your data.
"""

from __future__ import annotations

import json
import math
from dataclasses import dataclass, field
from pathlib import Path

from phishguard.models.calibration import calibrator_from_dict
from phishguard.signals import DEFAULT_BIAS, SIGNAL_SPECS, Kind, Signal

MODEL_LOGIT_CLIP = 3.0


@dataclass
class Contribution:
    id: str
    layer: str
    kind: str
    contribution: float  # log-odds
    description: str
    evidence: str


@dataclass
class Verdict:
    label: str
    probability: float
    risk_score: int
    confidence: float
    contributions: list[Contribution]
    layer_scores: dict[str, int]
    kind_scores: dict[str, float] = field(default_factory=dict)
    logit: float = 0.0


def _sigmoid(z: float) -> float:
    z = max(-35.0, min(35.0, z))
    return 1.0 / (1.0 + math.exp(-z))


class EnsembleScorer:
    def __init__(self, weights: dict[str, float] | None = None, bias: float = DEFAULT_BIAS,
                 calibrator=None, version: str = "default-v1",
                 threshold_suspicious: float = 0.40, threshold_malicious: float = 0.70) -> None:
        self.weights = {sid: spec.weight for sid, spec in SIGNAL_SPECS.items()}
        if weights:
            unknown = set(weights) - set(SIGNAL_SPECS)
            if unknown:
                raise ValueError(f"unknown signal ids in weights: {sorted(unknown)[:5]}")
            self.weights.update(weights)
        self.bias = bias
        self.calibrator = calibrator
        self.version = version
        self.t_susp, self.t_mal = threshold_suspicious, threshold_malicious

    @classmethod
    def from_file(cls, path: Path, **kw) -> "EnsembleScorer":
        data = json.loads(Path(path).read_text())
        return cls(weights=data["weights"], bias=data["bias"], calibrator=calibrator_from_dict(data.get("calibrator")),
                   version=data.get("version", Path(path).stem), **kw)

    # -- feature vector (used by training/train_ensemble.py) -------------------
    @staticmethod
    def dedupe(signals: list[Signal]) -> dict[str, Signal]:
        """Keep the strongest instance of each signal id (multiple URLs etc.)."""
        best: dict[str, Signal] = {}
        for s in signals:
            if s.id not in SIGNAL_SPECS:
                raise KeyError(f"unregistered signal id: {s.id}")
            cur = best.get(s.id)
            if cur is None or abs(s.strength) > abs(cur.strength):
                best[s.id] = s
        return best

    @staticmethod
    def feature_vector(signals: list[Signal], ids: list[str]) -> list[float]:
        d = EnsembleScorer.dedupe(signals)
        return [d[i].strength if i in d else 0.0 for i in ids]

    # -- scoring --------------------------------------------------------------
    def score(self, signals: list[Signal], model_prob: float | None = None, input_type: str = "text") -> Verdict:
        signals = list(signals)
        if model_prob is not None:
            lo = math.log(max(1e-6, model_prob) / max(1e-6, 1 - model_prob))
            signals.append(Signal("model.text_classifier", f"model probability {model_prob:.2f}",
                                  strength=max(-MODEL_LOGIT_CLIP, min(MODEL_LOGIT_CLIP, lo))))
        best = self.dedupe(signals)
        contribs: list[Contribution] = []
        layer_sum: dict[str, float] = {}
        kind_sum = {Kind.PHISHING.value: 0.0, Kind.SCAM.value: 0.0}
        for sid, s in best.items():
            spec = SIGNAL_SPECS[sid]
            c = self.weights[sid] * s.strength
            if abs(c) < 1e-9:
                continue
            desc = spec.description
            if sid == "model.text_classifier" and c < 0:
                desc = "The machine-learning text model rates the wording as typical of legitimate messages."
            contribs.append(Contribution(sid, spec.layer.value, spec.kind.value, round(c, 3), desc, s.evidence))
            layer_sum[spec.layer.value] = layer_sum.get(spec.layer.value, 0.0) + c
            if c > 0 and spec.kind.value in kind_sum:
                kind_sum[spec.kind.value] += c

        z = self.bias + sum(c.contribution for c in contribs)
        p = float(self.calibrator.transform([z])[0]) if self.calibrator else _sigmoid(z)
        contribs.sort(key=lambda c: -c.contribution)
        layer_scores = {k: int(round(100 * _sigmoid(self.bias + v))) for k, v in layer_sum.items()}

        if any(c.id == "intel.blocklisted" for c in contribs):
            p = max(p, self.t_mal)  # authoritative blocklist hit floors the verdict

        if p < self.t_susp:
            label = "safe"
        elif p < self.t_mal:
            label = "suspicious"
        else:
            label = self._malicious_kind(kind_sum, input_type)

        confidence = max(p, 1 - p) if label != "suspicious" else 0.5 + abs(p - (self.t_susp + self.t_mal) / 2)
        return Verdict(label=label, probability=round(p, 4), risk_score=int(round(100 * p)),
                       confidence=round(min(confidence, 0.99), 3), contributions=contribs,
                       layer_scores=layer_scores, kind_scores={k: round(v, 3) for k, v in kind_sum.items()},
                       logit=round(z, 3))

    @staticmethod
    def _malicious_kind(kind_sum: dict[str, float], input_type: str) -> str:
        if input_type == "url":
            return "phishing"
        ph, sc = kind_sum[Kind.PHISHING.value], kind_sum[Kind.SCAM.value]
        if abs(ph - sc) < 0.5:
            return "phishing" if input_type == "email" else "scam"
        return "phishing" if ph > sc else "scam"


def build_explanation(verdict: Verdict, input_type: str, max_flags: int = 6) -> tuple[str, str]:
    """Plain-language summary + recommended action."""
    flags = [c for c in verdict.contributions if c.contribution > 0][:max_flags]
    mitigating = [c for c in verdict.contributions if c.contribution < 0]
    noun = {"url": "link", "email": "email", "text": "message"}.get(input_type, "input")
    label = verdict.label
    if label == "safe":
        head = f"This {noun} looks safe (risk {verdict.risk_score}/100)."
        if flags:
            head += " Minor indicators were noted but are not enough to call it malicious: " + \
                    "; ".join(f.description.rstrip('.').lower() for f in flags[:2]) + "."
        action = "No action needed. Stay cautious and never share OTPs, PINs or passwords."
    elif label == "suspicious":
        head = f"This {noun} is suspicious (risk {verdict.risk_score}/100). Red flags: " + \
               "; ".join(f.description.rstrip('.') for f in flags[:4]) + "."
        action = "Do not click links or reply. Verify directly with the organisation using a phone number or website you already trust."
    else:
        what = "a phishing attempt" if label == "phishing" else "a scam"
        head = f"This {noun} is very likely {what} (risk {verdict.risk_score}/100). Red flags: " + \
               "; ".join(f.description.rstrip('.') for f in flags[:4]) + "."
        action = ("Do not click any links, open attachments, call numbers in it, or share any codes. Delete it and "
                  "report it (India: cybercrime.gov.in or helpline 1930, fraud SMS/calls via Sanchar Saathi 'Chakshu'; "
                  "email: use your provider's 'Report phishing' button).")
    if mitigating and label != "safe":
        head += " Mitigating factors: " + "; ".join(m.description.rstrip('.').lower() for m in mitigating[:2]) + "."
    return head, action
