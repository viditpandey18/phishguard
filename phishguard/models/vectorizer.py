"""Hashed TF-IDF vectoriser (numpy only, no scipy).

Why hashing instead of a vocabulary?
  * constant memory, no vocabulary file to version or leak training text,
  * new tokens (fresh scam slang, new brand typos) still get a feature slot,
  * stable across processes (CRC32, not Python's salted ``hash``).
Cost: collisions (mitigated with signed hashing + 2^18 buckets) and the
need to keep n-gram strings at inference time for explanations.

Features: word 1-2 grams + character 3-5 grams (char n-grams are robust to
misspellings, Hinglish spelling variation and leetspeak).
"""

from __future__ import annotations

import math
import re
import zlib
from dataclasses import dataclass

import numpy as np

_TOKEN_RE = re.compile(r"[\wऀ-ॿ]+", re.UNICODE)
_URL_RE = re.compile(r"(?:https?://|www\.)\S+|\b[\w-]+\.(?:com|in|net|org|xyz|top|ly|io|co|info)\S*", re.I)
_NUM_RE = re.compile(r"\d+")


def preprocess(text: str) -> str:
    """Normalise volatile tokens so the model learns patterns, not specifics."""
    text = _URL_RE.sub(" urltoken ", text.lower())
    text = re.sub(r"[\w.+-]+@[\w-]+\.[\w.]+", " emailtoken ", text)
    text = re.sub(r"(rs\.?|inr|₹|\$)\s?[\d,]+", " moneytoken ", text)
    return _NUM_RE.sub(lambda m: " num%d " % min(len(m.group(0)), 8), text)


@dataclass
class SparseRows:
    """Minimal CSR matrix: row i has indices[indptr[i]:indptr[i+1]]."""

    indices: np.ndarray
    values: np.ndarray
    indptr: np.ndarray
    n_features: int

    @property
    def n_rows(self) -> int:
        return len(self.indptr) - 1

    def dot(self, w: np.ndarray) -> np.ndarray:
        prod = w[self.indices] * self.values
        out = np.zeros(self.n_rows)
        nonempty = np.diff(self.indptr) > 0
        if prod.size:
            sums = np.add.reduceat(prod, self.indptr[:-1][nonempty]) if nonempty.any() else np.array([])
            out[nonempty] = sums
        return out

    def rmatvec(self, r: np.ndarray) -> np.ndarray:
        """X^T r"""
        g = np.zeros(self.n_features)
        rep = np.repeat(r, np.diff(self.indptr))
        np.add.at(g, self.indices, self.values * rep)
        return g

    def take(self, rows: np.ndarray) -> "SparseRows":
        idx, val, ptr = [], [], [0]
        for r in rows:
            s, e = self.indptr[r], self.indptr[r + 1]
            idx.append(self.indices[s:e])
            val.append(self.values[s:e])
            ptr.append(ptr[-1] + e - s)
        return SparseRows(
            np.concatenate(idx) if idx else np.array([], dtype=np.int64),
            np.concatenate(val) if val else np.array([]),
            np.array(ptr, dtype=np.int64),
            self.n_features,
        )


class HashingTfidf:
    def __init__(self, n_features: int = 2**18, word_ngrams=(1, 2), char_ngrams=(3, 5)) -> None:
        self.n_features = n_features
        self.word_ngrams = tuple(word_ngrams)
        self.char_ngrams = tuple(char_ngrams)
        self.idf: np.ndarray | None = None

    # -- tokenisation ---------------------------------------------------------
    def ngrams(self, text: str) -> list[str]:
        text = preprocess(text)
        words = _TOKEN_RE.findall(text)
        grams: list[str] = []
        lo, hi = self.word_ngrams
        for n in range(lo, hi + 1):
            grams.extend("w:" + " ".join(words[i: i + n]) for i in range(len(words) - n + 1))
        joined = " " + " ".join(words) + " "
        clo, chi = self.char_ngrams
        for n in range(clo, chi + 1):
            grams.extend("c:" + joined[i: i + n] for i in range(len(joined) - n + 1))
        return grams

    def _hash(self, gram: str) -> tuple[int, float]:
        h = zlib.crc32(gram.encode("utf-8"))
        return h % self.n_features, (1.0 if (h >> 31) & 1 == 0 else -1.0)

    def _row(self, text: str) -> dict[int, float]:
        counts: dict[int, float] = {}
        for g in self.ngrams(text):
            i, sign = self._hash(g)
            counts[i] = counts.get(i, 0.0) + sign
        return counts

    # -- fit / transform ----------------------------------------------------------
    def fit(self, texts: list[str]) -> "HashingTfidf":
        df = np.zeros(self.n_features)
        for t in texts:
            for i in self._row(t):
                df[i] += 1
        n = len(texts)
        self.idf = np.log((1 + n) / (1 + df)) + 1.0
        return self

    def transform(self, texts: list[str]) -> SparseRows:
        idx: list[int] = []
        val: list[float] = []
        ptr = [0]
        for t in texts:
            row = self._row(t)
            keys = np.fromiter(row.keys(), dtype=np.int64, count=len(row))
            tf = np.fromiter(row.values(), dtype=float, count=len(row))
            tf = np.sign(tf) * (1.0 + np.log(np.abs(tf) + 1e-12)) * (np.abs(tf) > 0)  # sublinear tf
            if self.idf is not None and len(keys):
                tf = tf * self.idf[keys]
            norm = math.sqrt(float((tf**2).sum())) or 1.0
            idx.extend(keys.tolist())
            val.extend((tf / norm).tolist())
            ptr.append(len(idx))
        return SparseRows(np.array(idx, dtype=np.int64), np.array(val), np.array(ptr, dtype=np.int64), self.n_features)

    def fit_transform(self, texts: list[str]) -> SparseRows:
        return self.fit(texts).transform(texts)

    def term_contributions(self, text: str, weights: np.ndarray, top_k: int = 5) -> list[tuple[str, float]]:
        """Approximate per-n-gram contribution to the logit (for explanations)."""
        x = self.transform([text])
        grams = {}
        for g in self.ngrams(text):
            if g.startswith("w:"):
                i, _ = self._hash(g)
                grams.setdefault(i, g[2:])
        contrib = {}
        for i, v in zip(x.indices, x.values):
            if i in grams:
                contrib[grams[i]] = contrib.get(grams[i], 0.0) + float(weights[i] * v)
        return sorted(contrib.items(), key=lambda kv: -kv[1])[:top_k]
