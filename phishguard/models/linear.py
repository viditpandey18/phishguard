"""L2-regularised logistic regression trained with Adam (numpy only).

Works on dense ``np.ndarray`` (ensemble meta-features) and on
``SparseRows`` (hashed text features). Supports per-class weights for
imbalanced data.
"""

from __future__ import annotations

import numpy as np

from phishguard.models.vectorizer import SparseRows


def sigmoid(z: np.ndarray) -> np.ndarray:
    return 1.0 / (1.0 + np.exp(-np.clip(z, -35, 35)))


def logit(p: np.ndarray | float, eps: float = 1e-6) -> np.ndarray:
    p = np.clip(p, eps, 1 - eps)
    return np.log(p / (1 - p))


def _dot(X, w):
    return X.dot(w) if isinstance(X, SparseRows) else X @ w


def _rmat(X, r):
    return X.rmatvec(r) if isinstance(X, SparseRows) else X.T @ r


def _n(X) -> int:
    return X.n_rows if isinstance(X, SparseRows) else X.shape[0]


def _d(X) -> int:
    return X.n_features if isinstance(X, SparseRows) else X.shape[1]


class LogisticRegressionNP:
    def __init__(self, l2: float = 1e-4, lr: float = 0.05, epochs: int = 300, class_weight: str | None = "balanced",
                 batch_size: int | None = None, seed: int = 0, tol: float = 1e-6) -> None:
        self.l2, self.lr, self.epochs = l2, lr, epochs
        self.class_weight, self.batch_size, self.seed, self.tol = class_weight, batch_size, seed, tol
        self.coef_: np.ndarray | None = None
        self.intercept_: float = 0.0

    def fit(self, X, y: np.ndarray, sample_weight: np.ndarray | None = None) -> "LogisticRegressionNP":
        y = np.asarray(y, dtype=float)
        n, d = _n(X), _d(X)
        sw = np.ones(n) if sample_weight is None else np.asarray(sample_weight, float)
        if self.class_weight == "balanced":
            pos = max(1.0, y.sum())
            neg = max(1.0, n - y.sum())
            sw = sw * np.where(y == 1, n / (2 * pos), n / (2 * neg))
        w = np.zeros(d)
        b = 0.0
        m_w, v_w = np.zeros(d), np.zeros(d)
        m_b = v_b = 0.0
        beta1, beta2, eps = 0.9, 0.999, 1e-8
        rng = np.random.default_rng(self.seed)
        bs = self.batch_size or n
        prev_loss = np.inf
        t = 0
        for _ in range(self.epochs):
            order = rng.permutation(n) if bs < n else np.arange(n)
            for start in range(0, n, bs):
                rows = order[start: start + bs]
                Xb = X.take(rows) if isinstance(X, SparseRows) else X[rows]
                yb, swb = y[rows], sw[rows]
                p = sigmoid(_dot(Xb, w) + b)
                r = (p - yb) * swb / swb.sum()
                gw = _rmat(Xb, r) + self.l2 * w
                gb = r.sum()
                t += 1
                m_w = beta1 * m_w + (1 - beta1) * gw
                v_w = beta2 * v_w + (1 - beta2) * gw**2
                m_b = beta1 * m_b + (1 - beta1) * gb
                v_b = beta2 * v_b + (1 - beta2) * gb**2
                lr_t = self.lr * np.sqrt(1 - beta2**t) / (1 - beta1**t)
                w -= lr_t * m_w / (np.sqrt(v_w) + eps)
                b -= lr_t * m_b / (np.sqrt(v_b) + eps)
            p = sigmoid(_dot(X, w) + b)
            loss = -np.sum(sw * (y * np.log(p + 1e-12) + (1 - y) * np.log(1 - p + 1e-12))) / sw.sum() + 0.5 * self.l2 * w @ w
            if abs(prev_loss - loss) < self.tol:
                break
            prev_loss = loss
        self.coef_, self.intercept_ = w, float(b)
        return self

    def decision_function(self, X) -> np.ndarray:
        assert self.coef_ is not None, "model not fitted"
        return _dot(X, self.coef_) + self.intercept_

    def predict_proba(self, X) -> np.ndarray:
        return sigmoid(self.decision_function(X))
