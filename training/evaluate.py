"""End-to-end evaluation of the full Analyzer on the test split + robustness.

    python training/evaluate.py                       # writes reports/evaluation_<date>.md
    python training/evaluate.py --split val

Reports overall and per-input-type metrics, recall at fixed FPR operating
points, the confusion matrix at the serving threshold, adversarial
robustness, and the top false positives/negatives *by signal pattern*
(never by content, so the report can be shared).
"""

from __future__ import annotations

import argparse
from collections import Counter
from datetime import date

import numpy as np

from common import REPORTS, ROOT, load_splits, write_report
from phishguard.analyzer import Analyzer
from phishguard.config import Settings
from phishguard.eval.adversarial import TEXT_ATTACKS, URL_ATTACKS
from phishguard.eval.metrics import full_report


def score(an: Analyzer, rows: list[dict]) -> tuple[np.ndarray, list]:
    probs, resps = [], []
    for r in rows:
        resp = an.analyze(r["content"], r["input_type"])
        probs.append(resp.probability)
        resps.append(resp)
    return np.array(probs), resps


def robustness(an: Analyzer, rows: list[dict], limit: int = 300) -> dict:
    mal = [r for r in rows if r["label"] == 1][:limit]
    out = {}
    base_det = {r["id"]: an.analyze(r["content"], r["input_type"]).label != "safe" for r in mal}
    for name, fn in {**TEXT_ATTACKS, **URL_ATTACKS}.items():
        kind = "url" if name in URL_ATTACKS else "text"
        subset = [r for r in mal if r["input_type"] == kind and base_det[r["id"]]]
        if not subset:
            continue
        still = sum(an.analyze(fn(r["content"]), kind).label != "safe" for r in subset)
        out[name] = {"n": len(subset), "detection_retained": still / len(subset)}
    return out


def fmt(x: float) -> str:
    return "n/a" if x != x else f"{x:.3f}"


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--split", default="test")
    args = ap.parse_args()

    an = Analyzer(Settings(), providers=[])
    rows = load_splits()[args.split]
    y = np.array([r["label"] for r in rows])
    probs, resps = score(an, rows)
    thr = an.scorer.t_mal

    overall = full_report(y, probs, threshold=thr)
    overall_susp = full_report(y, probs, threshold=an.scorer.t_susp)
    per_type = {}
    for t in ("text", "url", "email"):
        m = np.array([r["input_type"] == t for r in rows])
        if m.sum() and len(set(y[m])) == 2:
            per_type[t] = full_report(y[m], probs[m], threshold=thr)

    fp_patterns = Counter(tuple(f.id for f in rs.red_flags[:3]) for rs, yy in zip(resps, y) if yy == 0 and rs.probability >= thr)
    fn_types = Counter(r["input_type"] for r, rs, yy in zip(rows, resps, y) if yy == 1 and rs.probability < an.scorer.t_susp)
    rob = robustness(an, rows)

    payload = {"split": args.split, "overall": overall, "overall_at_suspicious": overall_susp,
               "per_type": per_type, "robustness": rob,
               "top_fp_patterns": [[list(k), v] for k, v in fp_patterns.most_common(10)],
               "fn_by_type": dict(fn_types),
               "models": {"ensemble": an.scorer.version, "text_model": getattr(an.text_model, "name", None)}}
    write_report(f"evaluation_{args.split}", payload)

    # Fill the markdown template
    tpl = (ROOT / "docs" / "EVALUATION_REPORT_TEMPLATE.md").read_text(encoding="utf-8")
    op = overall.get("operating_points", {})
    rows_md = "\n".join(
        f"| {t} | {m['n']} | {fmt(m['precision'])} | {fmt(m['recall'])} | {fmt(m['f1'])} | {fmt(m['roc_auc'])} | "
        f"{fmt(m['pr_auc'])} | {m['fpr']:.4f} |" for t, m in {"overall": overall, **per_type}.items())
    rob_md = "\n".join(f"| {k} | {v['n']} | {v['detection_retained']:.1%} |" for k, v in rob.items()) or "| - | - | - |"
    filled = (tpl.replace("{{DATE}}", date.today().isoformat())
              .replace("{{SPLIT}}", args.split)
              .replace("{{ENSEMBLE}}", an.scorer.version)
              .replace("{{TEXT_MODEL}}", str(getattr(an.text_model, "name", None)))
              .replace("{{THRESHOLD}}", str(thr))
              .replace("{{METRICS_ROWS}}", rows_md)
              .replace("{{R_AT_0.001}}", fmt(op.get("fpr<=0.001", {}).get("recall", float("nan"))))
              .replace("{{R_AT_0.01}}", fmt(op.get("fpr<=0.01", {}).get("recall", float("nan"))))
              .replace("{{R_AT_0.05}}", fmt(op.get("fpr<=0.05", {}).get("recall", float("nan"))))
              .replace("{{TP}}", str(overall["tp"])).replace("{{FP}}", str(overall["fp"]))
              .replace("{{TN}}", str(overall["tn"])).replace("{{FN}}", str(overall["fn"]))
              .replace("{{BRIER}}", fmt(overall["brier"])).replace("{{ECE}}", fmt(overall["ece"]))
              .replace("{{ROBUSTNESS_ROWS}}", rob_md))
    REPORTS.mkdir(exist_ok=True)
    out = REPORTS / f"evaluation_{args.split}_{date.today().isoformat()}.md"
    out.write_text(filled, encoding="utf-8")
    print(filled)
    print(f"\nwritten: {out}")


if __name__ == "__main__":
    main()
