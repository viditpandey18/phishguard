"""Runtime configuration (12-factor: everything from env vars / .env).

All network-touching features are OFF by default. Nothing here should ever
need to be edited in code to deploy safely.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

PROJECT_ROOT = Path(__file__).resolve().parent.parent


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="PG_", env_file=".env", extra="ignore")

    # --- input limits (defence against resource exhaustion) -----------------
    max_text_chars: int = 20_000
    max_url_chars: int = 4_096
    max_email_bytes: int = 2_000_000  # 2 MB raw .eml
    max_request_bytes: int = 2_500_000
    max_urls_per_input: int = 25

    # --- decision thresholds on calibrated probability ---------------------
    # Tuned for LOW false positives on legitimate mail: "phishing"/"scam"
    # requires strong evidence; the grey zone is reported as "suspicious".
    threshold_suspicious: float = 0.40
    threshold_malicious: float = 0.70

    # --- models -------------------------------------------------------------
    artifacts_dir: Path = PROJECT_ROOT / "phishguard" / "models" / "artifacts"
    text_model: str = "baseline"  # baseline | transformer | none
    transformer_model_dir: Path | None = None
    ensemble_weights_file: Path | None = None  # learned weights (train_ensemble.py)

    # --- external threat intel (passive lookups: send URL/domain to a 3rd party)
    enable_network_intel: bool = False
    intel_timeout_s: float = 3.0
    openphish_feed_file: Path | None = None  # local feed snapshot -> no data leaves host

    # --- active probing (connects to the *suspect* server). Only enable inside
    # the isolated sandbox container. Never on a workstation / prod API host.
    enable_active_probing: bool = False
    probe_timeout_s: float = 4.0
    probe_max_redirects: int = 5

    # --- API ------------------------------------------------------------------
    rate_limit_per_minute: int = 60
    rate_limit_burst: int = 20
    api_keys: str = ""  # comma-separated; empty = auth disabled (dev only)
    cors_origins: str = ""  # comma-separated allowlist
    trust_proxy_headers: bool = False  # honour X-Forwarded-For only behind a known proxy
    enable_web_ui: bool = True  # serve the built-in paste-and-scan page at /ui

    # --- privacy ----------------------------------------------------------------
    store_content: bool = False  # never persist raw messages unless explicitly enabled
    feedback_file: Path = PROJECT_ROOT / "data" / "feedback" / "feedback.jsonl"

    log_level: str = "INFO"
    log_json: bool = True

    environment: str = Field(default="dev")

    @property
    def api_key_set(self) -> set[str]:
        return {k.strip() for k in self.api_keys.split(",") if k.strip()}

    @property
    def cors_origin_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()
