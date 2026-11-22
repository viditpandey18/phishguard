# Architecture

```
            ┌───────────── input (text | URL | .eml / pasted headers) ─────────────┐
            │  size limits → type auto-detect → normalise (NFKC, strip zero-width, │
            │  homoglyph→Latin "deconfused" view, refang hxxp/[.]), mask URLs       │
            └───────────────┬───────────────────────┬───────────────────────┬──────┘
                            │                       │                       │
                  ┌─────────▼────────┐   ┌──────────▼─────────┐   ┌─────────▼──────────┐
                  │  URL layer       │   │  Text layer        │   │  Header layer      │
                  │  lexical, IDN,   │   │  EN/HI/Hinglish    │   │  SPF/DKIM/DMARC,   │
                  │  typo/homoglyph/ │   │  rules + negation, │   │  From/Reply-To/    │
                  │  combosquat      │   │  HTML link/form    │   │  Return-Path,      │
                  └───┬──────────────┘   │  checks            │   │  display-name,     │
                      │ (opt-in)         │  + ML text model   │   │  Received, attach. │
                  ┌───▼──────────────┐   └──────────┬─────────┘   └─────────┬──────────┘
                  │ Intel providers  │              │                       │
                  │ passive: GSB, PT,│              │  named Signals        │
                  │ VT, RDAP, local  │              │  (id, evidence,       │
                  │ OpenPhish        │              │   strength)           │
                  │ active (sandbox):│              │                       │
                  │ redirects, TLS   │              │                       │
                  └───┬──────────────┘              │                       │
                      └──────────────┬──────────────┴───────────────────────┘
                              ┌──────▼───────────────────────────────────┐
                              │ Ensemble: logit = b + Σ wᵢ·sᵢ            │
                              │ (+ w·logit p_text_model) → calibrator    │
                              │ → label, risk, confidence, contributions │
                              └──────┬───────────────────────────────────┘
                                     │
                         JSON (FastAPI) · CLI · Streamlit · extension
```

## Module map

| Path | Responsibility |
|---|---|
| `phishguard/sanitize.py` | Size limits, invisible-char stripping, NFKC, confusables, spaced-letter collapse, refang/defang |
| `phishguard/signals.py` | Registry of every signal: layer, kind (phishing/scam), default weight, user-facing description |
| `phishguard/features/url_features.py` | URL extraction (incl. defanged/bare domains), lexical features, brand checks |
| `phishguard/features/typosquat.py` | Damerau-Levenshtein, skeleton matching, combosquatting |
| `phishguard/features/domain.py` | Offline URL parsing, IP obfuscation decoding, registered-domain split |
| `phishguard/features/text_features.py` | Multilingual social-engineering rules with negation handling |
| `phishguard/features/email_parser.py` | Safe MIME parsing; HTML tokenised, never rendered |
| `phishguard/features/header_features.py` | Auth results, sender identity, relay chain, attachments, HTML structure |
| `phishguard/models/` | numpy hashed TF-IDF + LR, calibration, optional transformer |
| `phishguard/intel/` | Pluggable providers: passive lookups and sandboxed active probes |
| `phishguard/ensemble.py` | Scoring, labelling, plain-language explanation |
| `phishguard/analyzer.py` | Orchestration; short-lived feature cache for feedback |
| `phishguard/api/` | FastAPI app, rate limiting, auth, body limits, security headers |
| `data/`, `training/` | Download, prepare, train, evaluate |

## Design decisions and trade-offs

1. **Signals and weights are separate.** Detectors only emit named evidence. All weights live in one table (`signals.py`) or in a learned `ensemble_weights.json`. Explanations are therefore exact, and retraining never touches detector code.
2. **The meta-model is linear in log-odds, not GBM.** For a linear model, each contribution `wᵢ·sᵢ` *is* the SHAP value relative to an all-zero baseline. It needs no approximation and no extra dependency, and it stays faithful under audit. `train_ensemble.py --compare-gbm` measures what interactions would add on your data. If GBM is clearly better, serve it and use TreeSHAP for explanations.
3. **The learned weights are shrunk towards expert priors.** Signals seen fewer than 20 times keep their default weight. The rest blend `alpha·prior + (1-alpha)·learned`. Red-flag weights are sign-clipped at ≥ 0, so the system never explains that a red flag made something safer.
4. **Serving needs only numpy.** No SciPy or scikit-learn at runtime. This gives a smaller attack surface and image, and it works where native BLAS DLLs are blocked (as on the dev machine this was built on). scikit-learn, SHAP and Transformers remain optional extras.
5. **Hashing vectorizer.** Memory is constant, there's no vocabulary file that could leak training text, and new tokens still get a slot. The cost is collisions, mitigated by signed hashing over 2¹⁸ buckets.
6. **Low false positives by default.** "Malicious" needs p ≥ 0.70. The 0.40–0.70 band is reported as "suspicious". Standard security advice ("never share your OTP") is negative evidence. A trusted domain only mitigates when *every* link in the message is trusted.
7. **Text rules see URL-masked text.** URL tokens (`sbi-kyc-update.xyz`) are scored once, by the URL layer.
8. **Phishing vs scam.** Each signal has a kind. Among malicious verdicts, the larger sum of positive contributions decides the label. URL-only inputs are always "phishing".

## Registered-domain parsing
`domain.py` ships a compact suffix list, including common ccSLDs and free-hosting platforms treated as public suffixes. For production accuracy, swap in `tldextract` with a bundled Public Suffix List snapshot (`tldextract.TLDExtract(suffix_list_urls=())`), so it never fetches the list at runtime.

## Performance
Measured in-process on the bundled labeled cases, heuristics-only, on a laptop CPU (p50 / p95):
text ≈ 1.1 / 1.4 ms · URL ≈ 0.2 / 0.3 ms · email ≈ 3.3 / 5.1 ms. The hashed TF-IDF model adds a few ms per message. A transformer typically adds tens to hundreds of ms on CPU (not measured here). Enable it only when that budget allows, or export to ONNX.
