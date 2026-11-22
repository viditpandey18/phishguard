"""Pydantic request/response schemas (the public API contract)."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

Label = Literal["safe", "suspicious", "phishing", "scam"]
InputType = Literal["text", "url", "email"]


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=False)


class ScanTextRequest(_Strict):
    text: str = Field(..., min_length=1, max_length=20_000, description="Raw SMS/WhatsApp/email body text")
    channel: Literal["sms", "whatsapp", "email", "other"] = "other"


class ScanURLRequest(_Strict):
    url: str = Field(..., min_length=1, max_length=4_096)


class ScanEmailRequest(_Strict):
    raw: str = Field(..., min_length=1, max_length=2_000_000, description="Full RFC 5322 message or pasted headers+body")


class ScanAutoRequest(_Strict):
    content: str = Field(..., min_length=1, max_length=2_000_000)
    input_type: Literal["auto", "text", "url", "email"] = "auto"


class RedFlag(BaseModel):
    id: str
    layer: str
    severity: Literal["high", "medium", "low"]
    description: str
    evidence: str = ""
    contribution: float = Field(..., description="log-odds contribution to the verdict (exact, additive)")


class IntelStatus(BaseModel):
    provider: str
    status: str
    detail: str = ""


class ModelInfo(BaseModel):
    ensemble_version: str
    text_model: str | None
    calibrated: bool


class ScanResponse(BaseModel):
    scan_id: str
    input_type: InputType
    label: Label
    risk_score: int = Field(..., ge=0, le=100)
    probability: float = Field(..., ge=0, le=1, description="calibrated probability of being malicious")
    confidence: float = Field(..., ge=0, le=1)
    confidence_level: Literal["low", "medium", "high"]
    explanation: str
    recommended_action: str
    red_flags: list[RedFlag]
    mitigating_factors: list[RedFlag]
    layer_scores: dict[str, int]
    urls_analyzed: list[str] = Field(default_factory=list, description="defanged, non-clickable")
    model_terms: list[tuple[str, float]] = Field(default_factory=list, description="top n-grams pushing the ML text model")
    intel: list[IntelStatus] = Field(default_factory=list)
    model: ModelInfo
    latency_ms: float


class FeedbackRequest(_Strict):
    scan_id: str = Field(..., min_length=8, max_length=64, pattern=r"^[a-f0-9]+$")
    correct_label: Label
    comment: str | None = Field(default=None, max_length=500)


class FeedbackResponse(BaseModel):
    accepted: bool
    stored_features: bool
