import json
from pathlib import Path

import pytest

from phishguard.analyzer import Analyzer
from phishguard.config import Settings

FIXTURES = Path(__file__).parent / "fixtures"
ROOT = Path(__file__).parent.parent


@pytest.fixture(scope="session")
def settings(tmp_path_factory) -> Settings:
    tmp = tmp_path_factory.mktemp("pg")
    # Isolated, deterministic settings: no model artifacts, no network, temp feedback file.
    return Settings(artifacts_dir=tmp / "artifacts", text_model="none", enable_network_intel=False,
                    enable_active_probing=False, feedback_file=tmp / "feedback.jsonl", log_json=False)


@pytest.fixture(scope="session")
def analyzer(settings) -> Analyzer:
    """Heuristics-only analyzer: tests the deterministic layers without a trained model."""
    return Analyzer(settings, text_model=None, providers=[])


def load_cases() -> list[dict]:
    return json.loads((FIXTURES / "labeled_cases.json").read_text(encoding="utf-8"))


def load_seed() -> list[dict]:
    lines = (ROOT / "data" / "seed" / "samples.jsonl").read_text(encoding="utf-8").splitlines()
    return [json.loads(l) for l in lines if l.strip()]
