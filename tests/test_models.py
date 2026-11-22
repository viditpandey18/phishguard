import numpy as np
import pytest

from conftest import load_seed
from phishguard.ensemble import EnsembleScorer
from phishguard.eval.metrics import average_precision, full_report, recall_at_fpr, roc_auc
from phishguard.models.calibration import IsotonicCalibrator, PlattCalibrator
from phishguard.models.linear import LogisticRegressionNP
from phishguard.models.text_model import BaselineTextModel
from phishguard.models.vectorizer import HashingTfidf
from phishguard.signals import SIGNAL_SPECS, Signal


def test_sparse_dot_matches_dense():
    vec = HashingTfidf(n_features=2**10)
    X = vec.fit_transform(["hello world", "", "pay the fee now"])
    dense = np.zeros((3, 2**10))
    for r in range(3):
        for i, v in zip(X.indices[X.indptr[r]:X.indptr[r + 1]], X.values[X.indptr[r]:X.indptr[r + 1]]):
            dense[r, i] += v
    w = np.random.default_rng(0).normal(size=2**10)
    assert np.allclose(X.dot(w), dense @ w)
    assert np.allclose(X.rmatvec(np.ones(3)), dense.sum(0))


def test_logreg_learns_separable_data():
    rng = np.random.default_rng(0)
    X = rng.normal(size=(400, 3))
    y = (X[:, 0] - 2 * X[:, 1] > 0).astype(int)
    clf = LogisticRegressionNP(l2=1e-4, lr=0.1, epochs=300).fit(X, y)
    assert ((clf.predict_proba(X) > 0.5) == y).mean() > 0.95


def test_baseline_text_model_train_save_load(tmp_path):
    seed = load_seed()
    texts, labels = [s["text"] for s in seed], [s["label"] for s in seed]
    model = BaselineTextModel.train(texts, labels, n_features=2**16, epochs=150)
    probs = model.predict_proba_batch(texts)
    assert roc_auc(np.array(labels), probs) > 0.95  # training fit sanity, not a generalisation claim
    model.save(tmp_path)
    loaded = BaselineTextModel.load(tmp_path)
    assert np.allclose(loaded.predict_proba_batch(texts), probs)
    terms = loaded.explain("URGENT share OTP to unblock your card", 3)
    assert terms and all(isinstance(t, str) for t, _ in terms)


def test_calibrators_are_monotone_and_bounded():
    rng = np.random.default_rng(1)
    s = rng.normal(size=500)
    y = (rng.random(500) < 1 / (1 + np.exp(-2 * s))).astype(int)
    for cal in (PlattCalibrator().fit(s, y), IsotonicCalibrator().fit(s, y)):
        p = cal.transform(np.sort(s))
        assert np.all(np.diff(p) >= -1e-12) and p.min() >= 0 and p.max() <= 1
    assert PlattCalibrator().fit(s, y).a == pytest.approx(2.0, abs=0.6)


def test_metrics_known_values():
    y = np.array([0, 0, 1, 1])
    s = np.array([0.1, 0.4, 0.35, 0.8])
    assert roc_auc(y, s) == pytest.approx(0.75)
    assert average_precision(y, s) == pytest.approx((1 / 1 + 2 / 3) / 2)
    r, _ = recall_at_fpr(y, s, 0.0)
    assert r == pytest.approx(0.5)
    rep = full_report(y, s, threshold=0.5)
    assert rep["tp"] == 1 and rep["fp"] == 0 and "fpr<=0.01" in rep["operating_points"]


def test_ensemble_contributions_are_exact_and_additive():
    sc = EnsembleScorer()
    sigs = [Signal("url.ip_host"), Signal("text.urgency", strength=1.25), Signal("hdr.dmarc_pass")]
    v = sc.score(sigs, input_type="text")
    assert v.logit == pytest.approx(sc.bias + sum(c.contribution for c in v.contributions), abs=1e-3)
    assert {c.id for c in v.contributions} == {"url.ip_host", "text.urgency", "hdr.dmarc_pass"}


def test_ensemble_rejects_unknown_signals_and_weights():
    with pytest.raises(KeyError):
        EnsembleScorer().score([Signal("nope")])
    with pytest.raises(ValueError):
        EnsembleScorer(weights={"nope": 1.0})


def test_blocklist_floors_verdict():
    v = EnsembleScorer().score([Signal("intel.blocklisted"), Signal("url.trusted_domain")], input_type="url")
    assert v.label == "phishing"


def test_model_probability_can_mitigate():
    v = EnsembleScorer().score([Signal("text.urgency")], model_prob=0.02)
    model = [c for c in v.contributions if c.id == "model.text_classifier"][0]
    assert model.contribution < 0 and "legitimate" in model.description


def test_all_signal_specs_have_descriptions():
    assert all(s.description.endswith(".") for s in SIGNAL_SPECS.values())
