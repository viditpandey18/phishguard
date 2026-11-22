"""Train the TF-IDF + logistic-regression text baseline.

    python data/prepare.py --sources seed            # or real datasets
    python training/train_text_baseline.py           # numpy backend (default, what we serve)
    python training/train_text_baseline.py --compare-sklearn   # also report sklearn TF-IDF+LR

Only text-bearing records (SMS/text and email bodies) are used; URLs have
their own lexical layer.

Class imbalance: balanced class weights in the loss, *evaluation on the
natural distribution*, and threshold selection on validation at a target FPR.
"""

from __future__ import annotations

import argparse
from datetime import date

import numpy as np

from common import ARTIFACTS, fmt_metrics, load_splits, record_text, write_report
from phishguard.eval.metrics import full_report
from phishguard.models.calibration import IsotonicCalibrator, PlattCalibrator, enough_for_calibration
from phishguard.models.text_model import BaselineTextModel


def xy(rows: list[dict]) -> tuple[list[str], np.ndarray]:
    rows = [r for r in rows if r["input_type"] in ("text", "email")]
    return [record_text(r) for r in rows], np.array([r["label"] for r in rows])


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--n-features", type=int, default=2**18)
    ap.add_argument("--epochs", type=int, default=200)
    ap.add_argument("--l2", type=float, default=1e-5)
    ap.add_argument("--calibration", choices=["platt", "isotonic", "none"], default="platt")
    ap.add_argument("--compare-sklearn", action="store_true")
    ap.add_argument("--out", default=str(ARTIFACTS))
    args = ap.parse_args()

    splits = load_splits()
    (Xtr, ytr), (Xva, yva), (Xte, yte) = (xy(splits[s]) for s in ("train", "val", "test"))
    print(f"train={len(Xtr)} (pos {ytr.sum()}), val={len(Xva)}, test={len(Xte)}")
    if len(set(ytr)) < 2:
        raise SystemExit("training split needs both classes")

    model = BaselineTextModel.train(Xtr, ytr.tolist(), n_features=args.n_features, epochs=args.epochs, l2=args.l2)
    model.version = f"tfidf-lr-{date.today().isoformat()}"
    if args.calibration != "none" and enough_for_calibration(yva):
        val_scores = model.raw_scores(Xva)
        model.calibrator = (PlattCalibrator() if args.calibration == "platt" else IsotonicCalibrator()).fit(val_scores, yva)
    elif args.calibration != "none":
        print("WARNING: validation split too small to calibrate reliably; serving uncalibrated sigmoid")

    report = {"model": model.version, "params": vars(args)}
    for name, (X, y) in {"val": (Xva, yva), "test": (Xte, yte)}.items():
        if len(y) and len(set(y)) == 2:
            m = full_report(y, model.predict_proba_batch(X))
            report[name] = m
            print(f"[numpy {name}] {fmt_metrics(m)}")

    if args.compare_sklearn:
        try:
            from sklearn.feature_extraction.text import TfidfVectorizer
            from sklearn.linear_model import LogisticRegression
            from sklearn.pipeline import make_pipeline, make_union

            sk = make_pipeline(
                make_union(TfidfVectorizer(ngram_range=(1, 2), sublinear_tf=True, min_df=2),
                           TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), sublinear_tf=True, min_df=2)),
                LogisticRegression(max_iter=2000, class_weight="balanced", C=4.0))
            sk.fit(Xtr, ytr)
            if len(set(yte)) == 2:
                report["sklearn_test"] = full_report(yte, sk.predict_proba(Xte)[:, 1])
                print(f"[sklearn test] {fmt_metrics(report['sklearn_test'])}")
        except ImportError:
            print("scikit-learn not installed; skipping comparison (pip install -e .[ml])")

    from pathlib import Path
    model.save(Path(args.out))
    print(f"saved model to {args.out}; report -> {write_report('text_baseline', report)}")


if __name__ == "__main__":
    main()
