"""Probability calibration: Platt scaling and isotonic regression (numpy only).

Fit on a held-out validation split, never on training data, otherwise the
calibrator learns the model's over-confidence on examples it memorised.

Platt (2 params) is preferred for small calibration sets (< ~1k positives);
isotonic is more flexible but can overfit and produces step functions.
"""

from __future__ import annotations

import numpy as np


class PlattCalibrator:
    """p = sigmoid(a * score + b), fitted by Newton's method on log-loss."""

    def __init__(self, a: float = 1.0, b: float = 0.0) -> None:
        self.a, self.b = a, b

    def fit(self, scores: np.ndarray, y: np.ndarray, iters: int = 100) -> "PlattCalibrator":
        s = np.asarray(scores, float)
        y = np.asarray(y, float)
        # Platt's target smoothing reduces overfitting on separable data
        n_pos, n_neg = y.sum(), len(y) - y.sum()
        t = np.where(y == 1, (n_pos + 1) / (n_pos + 2), 1 / (n_neg + 2))
        a, b = 1.0, 0.0
        for _ in range(iters):
            p = 1 / (1 + np.exp(-np.clip(a * s + b, -35, 35)))
            g = np.array([np.sum((p - t) * s), np.sum(p - t)])
            w = p * (1 - p) + 1e-12
            H = np.array([[np.sum(w * s * s), np.sum(w * s)], [np.sum(w * s), np.sum(w)]]) + 1e-9 * np.eye(2)
            step = np.linalg.solve(H, g)
            a, b = a - step[0], b - step[1]
            if np.abs(step).max() < 1e-9:
                break
        self.a, self.b = float(a), float(b)
        return self

    def transform(self, scores):
        return 1 / (1 + np.exp(-np.clip(self.a * np.asarray(scores, float) + self.b, -35, 35)))

    def to_dict(self) -> dict:
        return {"type": "platt", "a": self.a, "b": self.b}


class IsotonicCalibrator:
    """Pool-adjacent-violators isotonic regression mapping score -> probability."""

    def __init__(self) -> None:
        self.x_: np.ndarray = np.array([])
        self.y_: np.ndarray = np.array([])

    def fit(self, scores: np.ndarray, y: np.ndarray) -> "IsotonicCalibrator":
        order = np.argsort(scores)
        xs, ys = np.asarray(scores, float)[order], np.asarray(y, float)[order]
        blocks = [[v, 1.0, x, x] for v, x in zip(ys, xs)]  # mean, weight, xmin, xmax
        merged: list[list[float]] = []
        for blk in blocks:
            merged.append(blk)
            while len(merged) > 1 and merged[-2][0] > merged[-1][0]:
                b2, b1 = merged.pop(), merged.pop()
                w = b1[1] + b2[1]
                merged.append([(b1[0] * b1[1] + b2[0] * b2[1]) / w, w, b1[2], b2[3]])
        self.x_ = np.array([(m[2] + m[3]) / 2 for m in merged])
        self.y_ = np.clip(np.array([m[0] for m in merged]), 1e-4, 1 - 1e-4)
        return self

    def transform(self, scores):
        return np.interp(np.asarray(scores, float), self.x_, self.y_)

    def to_dict(self) -> dict:
        return {"type": "isotonic", "x": self.x_.tolist(), "y": self.y_.tolist()}


MIN_CALIBRATION_PER_CLASS = 15


def enough_for_calibration(y) -> bool:
    """Calibrating on a handful of points makes probabilities *worse*, not better."""
    y = np.asarray(y)
    return min((y == 1).sum(), (y == 0).sum()) >= MIN_CALIBRATION_PER_CLASS


def calibrator_from_dict(d: dict | None):
    if not d:
        return None
    if d["type"] == "platt":
        return PlattCalibrator(d["a"], d["b"])
    iso = IsotonicCalibrator()
    iso.x_, iso.y_ = np.array(d["x"]), np.array(d["y"])
    return iso
