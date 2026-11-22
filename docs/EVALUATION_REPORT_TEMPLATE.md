# PhishGuard evaluation report

| Field | Value |
|---|---|
| Date | {{DATE}} |
| Split | {{SPLIT}} |
| Ensemble version | {{ENSEMBLE}} |
| Text model | {{TEXT_MODEL}} |
| Serving threshold (malicious) | {{THRESHOLD}} |

## 1. Dataset summary
_Fill from `data/processed/stats.json`: sources, counts per label/input type, split strategy (group / time), date range, dedup statistics. State the class balance of the test set. Metrics are reported on the **natural** distribution, with no resampling._

## 2. Headline metrics (threshold = serving "malicious" threshold)

| Slice | n | Precision | Recall | F1 | ROC-AUC | PR-AUC | FPR |
|---|---|---|---|---|---|---|---|
{{METRICS_ROWS}}

## 3. Fixed operating points (false-positive control)

Legitimate-mail FPR is the main constraint. Recall at the best threshold satisfying each FPR budget:

| FPR budget | Recall |
|---|---|
| ≤ 0.1 % | {{R_AT_0.001}} |
| ≤ 1 % | {{R_AT_0.01}} |
| ≤ 5 % | {{R_AT_0.05}} |

Confusion matrix at serving threshold: TP={{TP}} FP={{FP}} TN={{TN}} FN={{FN}}

## 4. Calibration
Brier score: {{BRIER}} · Expected calibration error (10 bins): {{ECE}}
_Attach a reliability diagram if available. ECE > 0.05 means the calibrator should be refit._

## 5. Adversarial robustness
Share of originally-detected malicious samples still detected after perturbation:

| Attack | n | Detection retained |
|---|---|---|
{{ROBUSTNESS_ROWS}}

Not covered automatically: image-only emails with OCR-only text, QR-code phishing ("quishing"), LLM-paraphrased scams, and voice/IVR scams. Evaluate these manually with a curated set.

## 6. Error analysis
- Top false-positive signal patterns: see `reports/evaluation_<split>.json → top_fp_patterns`.
- False negatives by input type: `fn_by_type`.
- _Reviewer notes: describe recurring FP classes (e.g. bank awareness SMS, OTP messages) and the planned fixes._

## 7. Comparison with baselines
| Model | PR-AUC | Recall @ FPR ≤ 1 % | Latency p50 / p95 |
|---|---|---|---|
| Heuristics only (default weights) | | | |
| TF-IDF + LR (numpy) | | | |
| TF-IDF + LR (scikit-learn) | | | |
| Transformer (xlm-roberta-base) | | | |
| Full ensemble (served) | | | |

## 8. Sign-off
- [ ] FPR on legitimate mail within budget
- [ ] No regression vs previous release on frozen test set
- [ ] Robustness retained ≥ 90 % for each attack
- [ ] Reviewed by: ____
