"""Text classifier wrappers with a common interface.

``BaselineTextModel``: hashed TF-IDF + logistic regression (numpy). Fast,
tiny, explainable; the default.
``TransformerTextModel`` (models/transformer.py): fine-tuned multilingual
encoder; better recall on paraphrased scams, ~100x slower, needs torch.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Protocol

import numpy as np

from phishguard.models.calibration import calibrator_from_dict
from phishguard.models.linear import LogisticRegressionNP, sigmoid
from phishguard.models.vectorizer import HashingTfidf

log = logging.getLogger(__name__)


class TextModel(Protocol):
    name: str

    def predict_proba(self, text: str) -> float: ...

    def explain(self, text: str, top_k: int = 5) -> list[tuple[str, float]]: ...


class BaselineTextModel:
    name = "tfidf-logreg-np"

    def __init__(self, vectorizer: HashingTfidf, clf: LogisticRegressionNP, calibrator=None, version: str = "dev") -> None:
        self.vectorizer, self.clf, self.calibrator, self.version = vectorizer, clf, calibrator, version

    @classmethod
    def train(cls, texts: list[str], labels: list[int], n_features: int = 2**18, epochs: int = 200,
              l2: float = 1e-5) -> "BaselineTextModel":
        vec = HashingTfidf(n_features=n_features)
        X = vec.fit_transform(texts)
        clf = LogisticRegressionNP(l2=l2, lr=0.05, epochs=epochs, class_weight="balanced").fit(X, np.array(labels))
        return cls(vec, clf)

    def raw_scores(self, texts: list[str]) -> np.ndarray:
        return self.clf.decision_function(self.vectorizer.transform(texts))

    def predict_proba_batch(self, texts: list[str]) -> np.ndarray:
        s = self.raw_scores(texts)
        return self.calibrator.transform(s) if self.calibrator else sigmoid(s)

    def predict_proba(self, text: str) -> float:
        return float(self.predict_proba_batch([text])[0])

    def explain(self, text: str, top_k: int = 5) -> list[tuple[str, float]]:
        return self.vectorizer.term_contributions(text, self.clf.coef_, top_k)

    # -- persistence (no pickle: npz + json are safe to load) --------------------
    def save(self, directory: Path) -> None:
        directory.mkdir(parents=True, exist_ok=True)
        np.savez_compressed(directory / "text_baseline.npz", coef=self.clf.coef_, idf=self.vectorizer.idf)
        meta = {
            "name": self.name, "version": self.version, "intercept": self.clf.intercept_,
            "n_features": self.vectorizer.n_features, "word_ngrams": self.vectorizer.word_ngrams,
            "char_ngrams": self.vectorizer.char_ngrams,
            "calibrator": self.calibrator.to_dict() if self.calibrator else None,
        }
        (directory / "text_baseline.json").write_text(json.dumps(meta, indent=2))

    @classmethod
    def load(cls, directory: Path) -> "BaselineTextModel":
        meta = json.loads((directory / "text_baseline.json").read_text())
        arrays = np.load(directory / "text_baseline.npz", allow_pickle=False)
        vec = HashingTfidf(meta["n_features"], tuple(meta["word_ngrams"]), tuple(meta["char_ngrams"]))
        vec.idf = arrays["idf"]
        clf = LogisticRegressionNP()
        clf.coef_, clf.intercept_ = arrays["coef"], float(meta["intercept"])
        return cls(vec, clf, calibrator_from_dict(meta.get("calibrator")), meta.get("version", "dev"))


def load_text_model(kind: str, artifacts_dir: Path, transformer_dir: Path | None = None) -> TextModel | None:
    """Load the configured model; return None (heuristics-only) if unavailable."""
    if kind == "none":
        return None
    if kind == "transformer":
        try:
            from phishguard.models.transformer import TransformerTextModel

            if transformer_dir is None:
                raise FileNotFoundError("PG_TRANSFORMER_MODEL_DIR not set")
            return TransformerTextModel(transformer_dir)
        except Exception as exc:  # torch missing, bad path...
            log.warning("transformer model unavailable (%s); falling back to baseline", type(exc).__name__)
    path = artifacts_dir / "text_baseline.json"
    if path.exists():
        try:
            return BaselineTextModel.load(artifacts_dir)
        except Exception as exc:
            log.error("failed to load baseline text model: %s", type(exc).__name__)
    else:
        log.info("no text model artifact at %s; running heuristics-only", artifacts_dir)
    return None
