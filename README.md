# 🛡️ PhishGuard

Defensive, explainable detection of **scam messages** (SMS, WhatsApp, email text), **phishing emails** (headers + content) and **phishing URLs**. It supports English, Hindi and Hinglish.

Every verdict comes as JSON: a label (`safe` / `suspicious` / `phishing` / `scam`), a 0–100 risk score, a calibrated probability, a confidence, and a plain-language list of the specific red flags that drove it, each with its exact contribution.

```
$ python -m phishguard.cli "Aapka KYC pending hai, account aaj raat band ho jayega. Turant link pe click karein: bit.ly/kyc-upd8"
SCAM  risk 96/100  confidence 0.95 (high)  [text]
  ! [medium] Asks you to update KYC/PAN/Aadhaar details - a common bank-impersonation lure.  ("kyc pending")
  ! [medium] Threatens account blocking, penalties or other consequences.  ("band ho jayega")
  ! [medium] Creates urgency or a short deadline to rush you.  ("turant")
  ! [low   ] The link uses a URL shortener that hides the real destination.  (bit[.]ly/kyc-upd8: bit.ly)
  ! [low   ] Pushes you to click a link or open an attachment.  ("link pe")
  ! [low   ] The link contains words like 'login', 'verify' or 'kyc' typical of credential phishing.  (bit[.]ly/kyc-upd8: kyc)
Advice: Do not click any links, open attachments, call numbers in it, or share any codes. ...
```

## How it works (summary; details in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md))

| Layer | What it checks |
|---|---|
| **URL** | length, subdomain depth, hyphens, `@`, IP hosts (incl. decimal/hex), punycode/IDN, shorteners, abused TLDs, free hosting, brand-in-subdomain/path, entropy, executable downloads, open-redirect patterns, **typosquat / homoglyph / combosquat** against ~60 global and Indian brands |
| **Text** | urgency, threats, police/"digital arrest", prizes/KBC lottery, **OTP/PIN/CVV requests (negation-aware)**, KYC/PAN/Aadhaar lures, fees, job/investment, gift cards/crypto, AnyDesk, electricity disconnection, personal mobile numbers, secrecy, generic greetings, misspellings, zero-width/mixed-script obfuscation, HTML link-text mismatch, forms, scripts, image-only |
| **Headers** | SPF/DKIM/DMARC (top-most Authentication-Results only), From vs Reply-To vs Return-Path, display-name spoofing, brand sent from free mail, sender typosquat, Received anomalies, risky attachments (exe, html, macro Office, iso, OneNote, double extensions, RTLO) |
| **ML** | hashed word+char n-gram TF-IDF + logistic regression (numpy; optional) or a fine-tuned multilingual transformer (optional) |
| **Intel** (opt-in) | local OpenPhish feed; Google Safe Browsing, PhishTank, VirusTotal, RDAP domain age; sandbox-only redirect chain and TLS certificate age |
| **Ensemble** | `logit = bias + Σ weight·strength` → calibrator. Weights are expert defaults, re-learnable from data. Contributions are exact (= SHAP for a linear model) |

## Quick start

```bash
python -m venv .venv && . .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -e .[dev]
pytest                                             # 189 tests, ~2 s
uvicorn phishguard.api.main:app --port 8000        # API + docs at http://localhost:8000/docs
python -m phishguard.cli --url "http://paypa1.com/signin"
python -m phishguard.cli --email path/to/message.eml --json
```

Docker:
```bash
cp .env.example .env
docker compose up --build                     # API on 127.0.0.1:8000 (read-only FS, non-root, no capabilities)
docker compose --profile ui up --build        # + Streamlit UI on :8501
```

**Deploy to Render (free):** push this repo to GitHub, then in Render choose *New → Blueprint* and pick the repo. `render.yaml` builds the Dockerfile, health-checks `/healthz`, and serves the UI at `https://<service>.onrender.com/ui/`. Free instances sleep after ~15 min idle, so the first request takes ~30–50 s.

**Android app (PhishGuard Shield):** `mobile/android` hides scam SMS, WhatsApp and Gmail notifications on your phone. Run the server with `.\run.ps1 -Lan` so the phone can reach it. Setup and limits: [mobile/README.md](mobile/README.md).

Browser extension stub: load `extension/` as an unpacked extension in Chrome. Add its origin to `PG_CORS_ORIGINS`. Right-click a link or a text selection and choose **PhishGuard: scan**.

API reference and real example responses: [docs/API.md](docs/API.md).

## Out-of-the-box behaviour
With no trained artifacts, the service runs **heuristics-only**, with expert default weights and no ML model. That is deterministic and useful, but uncalibrated. To add the ML layer and learned weights, train on real data:

```bash
python data/download.py --list                 # read licences!
python data/download.py sms_spam spamassassin nazario tranco openphish
python data/prepare.py --sources seed sms_spam spamassassin nazario tranco openphish
python training/train_text_baseline.py --compare-sklearn   # -> phishguard/models/artifacts/text_baseline.*
python training/train_ensemble.py --compare-gbm            # -> ensemble_weights.json (+ calibrator)
python training/evaluate.py                                # -> reports/evaluation_test_<date>.md
# optional: pip install -e .[transformer] && python training/train_transformer.py --base xlm-roberta-base
```

The API loads artifacts from `phishguard/models/artifacts/` automatically. `make demo-train` runs this whole chain on the 60-sample seed set as a **plumbing check only**; delete those artifacts afterwards (`phishguard/models/artifacts/`).

Datasets, licences, cleaning, dedup and leakage-safe splits: [data/README.md](data/README.md). Report template: [docs/EVALUATION_REPORT_TEMPLATE.md](docs/EVALUATION_REPORT_TEMPLATE.md). It covers precision, recall, F1, ROC-AUC, PR-AUC, **recall at FPR ≤ 0.1 % / 1 % / 5 %**, calibration (Brier, ECE) and adversarial robustness.

## Configuration
Everything is set through `PG_*` env vars or `.env`; see [.env.example](.env.example) and `phishguard/config.py`. Defaults that matter:

| Setting | Default | Why |
|---|---|---|
| `PG_THRESHOLD_MALICIOUS` | 0.70 | Low false positives on legitimate mail |
| `PG_ENABLE_NETWORK_INTEL` | false | Lookups disclose URLs to third parties |
| `PG_ENABLE_ACTIVE_PROBING` | false | Contacts suspect servers; sandbox container only |
| `PG_STORE_CONTENT` | false | Messages are never persisted; feedback stores features only |
| `PG_API_KEYS` | empty | **Set in production**. Empty disables auth |

## Security & privacy
Input is untrusted. Limits apply per field and per streamed body, plus per-client rate limits. HTML is never rendered. URLs in output are defanged. Responses carry a strict CSP. Logs hold metadata only, with a PII-redaction filter (emails, UPI IDs, phone numbers, cards, Aadhaar, PAN, account numbers, OTPs). Artifacts are loaded without pickle. Full analysis and **known limitations**: [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).

## Project layout
```
phishguard/            package
  features/            url_features, typosquat, domain, text_features, email_parser, header_features, resources
  models/              vectorizer, linear (numpy LR), calibration, text_model, transformer
  intel/               passive providers + sandboxed active probes
  api/                 FastAPI app + security middleware
  eval/                metrics, adversarial transforms
  ensemble.py analyzer.py signals.py sanitize.py schemas.py config.py logging_utils.py cli.py
data/                  download.py, prepare.py, seed/
training/              train_text_baseline.py, train_ensemble.py, train_transformer.py, evaluate.py
tests/                 pytest (labeled cases in tests/fixtures/labeled_cases.json)
notebooks/ docs/ ui/ extension/
```

## Roadmap
1. **Active learning from feedback.** `/v1/feedback` already captures signal vectors and corrected labels without content. Next steps:
   - a review queue (only human-verified labels go into training);
   - uncertainty sampling, prioritising `suspicious`-band items for review;
   - per-client caps and agreement thresholds against poisoning;
   - opt-in content donation with consent.
2. **Retraining pipeline.**
   - Scheduled job: `prepare → train_text_baseline → train_ensemble → evaluate`.
   - Promotion gate: no regression on a frozen golden set, FPR budget met, robustness ≥ 90 %.
   - Versioned, signed artifacts; shadow deployment before switching; drift monitoring on signal firing rates and score distributions.
3. **Multilingual expansion.** Human-verified Hindi/Hinglish test sets; MuRIL / XLM-R fine-tuning; rule packs for Tamil, Telugu, Bengali, Marathi and Gujarati; transliteration-aware normalisation.
4. **Coverage.** OCR for image-only emails, QR-code ("quishing") decoding, voice/IVR transcripts, attachment sandbox integration, brand-logo detection on landing pages (sandbox only).
5. **Infrastructure.** Tranco-based allowlist and PSL via `tldextract`; Redis-backed rate limiting; ONNX/int8 transformer; OpenTelemetry metrics; Gmail/Outlook add-ins built on the extension stub.

## License
Code: Apache-2.0 (suggested). Datasets keep their own licences (see data/README.md).
