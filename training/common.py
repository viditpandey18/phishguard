"""Shared helpers for training/evaluation scripts."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from phishguard.features.email_parser import parse_email  # noqa: E402

PROCESSED = ROOT / "data" / "processed"
ARTIFACTS = ROOT / "phishguard" / "models" / "artifacts"
REPORTS = ROOT / "reports"


def load_jsonl(path: Path) -> list[dict]:
    return [json.loads(l) for l in path.read_text(encoding="utf-8").splitlines() if l.strip()]


def load_splits(directory: Path = PROCESSED) -> dict[str, list[dict]]:
    return {s: load_jsonl(directory / f"{s}.jsonl") for s in ("train", "val", "test")}


def record_text(r: dict) -> str:
    """Text view used by the text model: SMS as-is, email subject+body, URL as-is."""
    if r["input_type"] == "email":
        doc = parse_email(r["content"])
        return f"{doc.subject}\n{doc.body}"[:20_000]
    return r["content"][:20_000]


def write_report(name: str, payload: dict) -> Path:
    REPORTS.mkdir(exist_ok=True)
    path = REPORTS / f"{name}.json"
    path.write_text(json.dumps(payload, indent=2, default=float))
    return path


def fmt_metrics(m: dict) -> str:
    ops = " ".join(f"R@{k}={v['recall']:.3f}" for k, v in m.get("operating_points", {}).items())
    return (f"n={m['n']} P={m['precision']:.3f} R={m['recall']:.3f} F1={m['f1']:.3f} FPR={m['fpr']:.4f} "
            f"ROC-AUC={m['roc_auc']:.3f} PR-AUC={m['pr_auc']:.3f} ECE={m['ece']:.3f} {ops}")
