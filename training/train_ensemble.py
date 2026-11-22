"""Learn ensemble weights (meta-classifier) + calibrator from labelled data.

    python training/train_ensemble.py                    # logistic meta-model (served)
    python training/train_ensemble.py --compare-gbm      # also report HistGradientBoosting (+SHAP if installed)

Pipeline: every training record goes through the *same* detectors as
production (Analyzer.signal_vector), producing a vector of signal strengths
plus the text-model logit. A logistic regression on those features yields the
weights; a Platt/isotonic calibrator is fitted on the validation split.

Sign constraints: red-flag signals are clipped at >= 0 and mitigating signals
at <= 0 so explanations never say "this red flag made it *safer*" - a common
artefact of correlated features. The effect of clipping is reported.
"""

from __future__ import annotations

import argparse
import json
from datetime import date

import numpy as np

from common import ARTIFACTS, fmt_metrics, load_splits, write_report
from phishguard.analyzer import Analyzer
from phishguard.config import Settings
from phishguard.ensemble import MODEL_LOGIT_CLIP, EnsembleScorer
from phishguard.eval.metrics import full_report
from phishguard.models.calibration import IsotonicCalibrator, PlattCalibrator, enough_for_calibration
from phishguard.models.linear import LogisticRegressionNP, sigmoid
from phishguard.signals import DEFAULT_BIAS, SIGNAL_SPECS

IDS = sorted(SIGNAL_SPECS)
MODEL_IDX = IDS.index("model.text_classifier")


def featurize(an: Analyzer, rows: list[dict]) -> tuple[np.ndarray, np.ndarray]:
    X = np.zeros((len(rows), len(IDS)))
    for i, r in enumerate(rows):
        sigs, model_prob, _ = an.signal_vector(r["content"], r["input_type"])
        X[i] = EnsembleScorer.feature_vector(sigs, IDS)
        if model_prob is not None:
            lo = np.log(max(1e-6, model_prob) / max(1e-6, 1 - model_prob))
            X[i, MODEL_IDX] = float(np.clip(lo, -MODEL_LOGIT_CLIP, MODEL_LOGIT_CLIP))
    return X, np.array([r["label"] for r in rows])


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--l2", type=float, default=1e-2, help="strong L2: shrinks weights of rare signals towards 0")
    ap.add_argument("--calibration", choices=["platt", "isotonic"], default="platt")
    ap.add_argument("--blend-prior", type=float, default=0.3,
                    help="shrink learned weights towards expert defaults (0=pure data, 1=defaults)")
    ap.add_argument("--compare-gbm", action="store_true")
    args = ap.parse_args()

    an = Analyzer(Settings(), providers=[])  # loads text model if trained; no network intel in training
    splits = load_splits()
    (Xtr, ytr), (Xva, yva), (Xte, yte) = (featurize(an, splits[s]) for s in ("train", "val", "test"))
    print(f"features: train {Xtr.shape}, val {Xva.shape}, test {Xte.shape}")

    clf = LogisticRegressionNP(l2=args.l2, lr=0.05, epochs=2000, class_weight=None).fit(Xtr, ytr)
    w = clf.coef_.copy()
    # Blend with expert prior: signals rarely/never seen in training keep sensible weights.
    prior = np.array([SIGNAL_SPECS[i].weight for i in IDS])
    seen = (Xtr != 0).sum(0)
    alpha = np.where(seen >= 20, args.blend_prior, 1.0)  # unseen/rare -> keep default
    w = alpha * prior + (1 - alpha) * w
    bias = float(args.blend_prior * DEFAULT_BIAS + (1 - args.blend_prior) * clf.intercept_)

    clipped = []
    for j, sid in enumerate(IDS):
        expected_sign = np.sign(SIGNAL_SPECS[sid].weight)
        if sid != "model.text_classifier" and expected_sign and np.sign(w[j]) == -expected_sign:
            clipped.append(sid)
            w[j] = 0.0
    if clipped:
        print(f"sign-clipped {len(clipped)} weights: {clipped[:10]}")

    z_va = Xva @ w + bias
    cal = (PlattCalibrator() if args.calibration == "platt" else IsotonicCalibrator()).fit(z_va, yva) \
        if enough_for_calibration(yva) else None
    if cal is None:
        print("WARNING: validation split too small to calibrate; using plain sigmoid")
    scorer_probs = lambda X: cal.transform(X @ w + bias) if cal else sigmoid(X @ w + bias)  # noqa: E731

    report: dict = {"params": vars(args), "clipped": clipped}
    default_probs = lambda X: sigmoid(X @ prior + DEFAULT_BIAS)  # noqa: E731
    for name, X, y in (("val", Xva, yva), ("test", Xte, yte)):
        if len(set(y)) == 2:
            report[f"{name}_learned"] = full_report(y, scorer_probs(X))
            report[f"{name}_default_weights"] = full_report(y, default_probs(X))
            print(f"[{name} learned ] {fmt_metrics(report[f'{name}_learned'])}")
            print(f"[{name} defaults] {fmt_metrics(report[f'{name}_default_weights'])}")

    if args.compare_gbm:
        try:
            from sklearn.ensemble import HistGradientBoostingClassifier

            gbm = HistGradientBoostingClassifier(max_depth=4, learning_rate=0.05, max_iter=300).fit(Xtr, ytr)
            if len(set(yva)) == 2:
                gcal = PlattCalibrator().fit(gbm.decision_function(Xva), yva)
                report["test_gbm"] = full_report(yte, gcal.transform(gbm.decision_function(Xte)))
                print(f"[test GBM    ] {fmt_metrics(report['test_gbm'])}")
            try:
                import shap

                sv = shap.TreeExplainer(gbm).shap_values(Xte[:500])
                imp = np.abs(sv).mean(0)
                report["gbm_shap_top"] = sorted(zip(IDS, imp.tolist()), key=lambda kv: -kv[1])[:15]
            except ImportError:
                print("shap not installed; skipping SHAP summary")
        except ImportError:
            print("scikit-learn not installed; skipping GBM comparison (pip install -e .[ml])")

    out = {"version": f"learned-{date.today().isoformat()}", "bias": bias,
           "weights": {sid: round(float(w[j]), 4) for j, sid in enumerate(IDS)},
           "calibrator": cal.to_dict() if cal else None}
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    (ARTIFACTS / "ensemble_weights.json").write_text(json.dumps(out, indent=2))
    print(f"saved {ARTIFACTS / 'ensemble_weights.json'}; report -> {write_report('ensemble', report)}")


if __name__ == "__main__":
    main()
