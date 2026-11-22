"""Evaluation metrics (numpy only) with an emphasis on false-positive control.

For a filter that sits in front of real users, the most important numbers
are *recall at a fixed, low false-positive rate* (e.g. FPR <= 0.1% on
legitimate mail), not accuracy or F1 at 0.5.
"""

from __future__ import annotations

import numpy as np


def confusion(y: np.ndarray, pred: np.ndarray) -> dict[str, int]:
    y, pred = np.asarray(y).astype(int), np.asarray(pred).astype(int)
    return {"tp": int(((y == 1) & (pred == 1)).sum()), "fp": int(((y == 0) & (pred == 1)).sum()),
            "tn": int(((y == 0) & (pred == 0)).sum()), "fn": int(((y == 1) & (pred == 0)).sum())}


def prf(y: np.ndarray, pred: np.ndarray) -> dict[str, float]:
    c = confusion(y, pred)
    precision = c["tp"] / max(1, c["tp"] + c["fp"])
    recall = c["tp"] / max(1, c["tp"] + c["fn"])
    f1 = 2 * precision * recall / max(1e-12, precision + recall)
    fpr = c["fp"] / max(1, c["fp"] + c["tn"])
    return {"precision": precision, "recall": recall, "f1": f1, "fpr": fpr, **c}


def roc_curve(y: np.ndarray, scores: np.ndarray) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    y, s = np.asarray(y).astype(int), np.asarray(scores, float)
    order = np.argsort(-s, kind="mergesort")
    s, y = s[order], y[order]
    distinct = np.where(np.diff(s))[0]
    idx = np.r_[distinct, len(y) - 1]
    tps = np.cumsum(y)[idx]
    fps = 1 + idx - tps
    P, N = max(1, y.sum()), max(1, len(y) - y.sum())
    return np.r_[0, fps / N], np.r_[0, tps / P], np.r_[np.inf, s[idx]]


def roc_auc(y: np.ndarray, scores: np.ndarray) -> float:
    fpr, tpr, _ = roc_curve(y, scores)
    return float(np.trapezoid(tpr, fpr)) if hasattr(np, "trapezoid") else float(np.trapz(tpr, fpr))


def average_precision(y: np.ndarray, scores: np.ndarray) -> float:
    """PR-AUC as average precision (step-wise, no interpolation)."""
    y, s = np.asarray(y).astype(int), np.asarray(scores, float)
    order = np.argsort(-s, kind="mergesort")
    y = y[order]
    tp = np.cumsum(y)
    precision = tp / np.arange(1, len(y) + 1)
    return float((precision * y).sum() / max(1, y.sum()))


def recall_at_fpr(y: np.ndarray, scores: np.ndarray, max_fpr: float) -> tuple[float, float]:
    """Best recall achievable with FPR <= max_fpr, and the threshold that achieves it."""
    fpr, tpr, thr = roc_curve(y, scores)
    ok = np.where(fpr <= max_fpr)[0]
    i = ok[np.argmax(tpr[ok])]
    return float(tpr[i]), float(thr[i])


def expected_calibration_error(y: np.ndarray, probs: np.ndarray, bins: int = 10) -> float:
    y, p = np.asarray(y, float), np.asarray(probs, float)
    edges = np.linspace(0, 1, bins + 1)
    ece = 0.0
    for lo, hi in zip(edges[:-1], edges[1:]):
        m = (p >= lo) & (p < hi) if hi < 1 else (p >= lo) & (p <= hi)
        if m.any():
            ece += m.mean() * abs(p[m].mean() - y[m].mean())
    return float(ece)


def full_report(y: np.ndarray, probs: np.ndarray, threshold: float = 0.7,
                fpr_points=(0.001, 0.01, 0.05)) -> dict:
    y, probs = np.asarray(y).astype(int), np.asarray(probs, float)
    rep = {"n": int(len(y)), "positives": int(y.sum()), "threshold": threshold,
           **prf(y, probs >= threshold),
           "roc_auc": roc_auc(y, probs) if 0 < y.sum() < len(y) else float("nan"),
           "pr_auc": average_precision(y, probs),
           "brier": float(np.mean((probs - y) ** 2)),
           "ece": expected_calibration_error(y, probs),
           "operating_points": {}}
    if 0 < y.sum() < len(y):
        for f in fpr_points:
            r, t = recall_at_fpr(y, probs, f)
            rep["operating_points"][f"fpr<={f:g}"] = {"recall": r, "threshold": t}
    return rep
