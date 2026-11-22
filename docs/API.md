# REST API

Base URL `http://localhost:8000`. Interactive docs are at `/docs` (disabled when `PG_ENVIRONMENT=prod`).
If `PG_API_KEYS` is set, send `x-api-key: <key>`.

| Method | Path | Body | Purpose |
|---|---|---|---|
| GET | `/healthz` | – | Liveness |
| GET | `/v1/info` | – | Versions, thresholds, enabled providers (no secrets) |
| POST | `/v1/scan` | `{"content": str, "input_type": "auto"\|"text"\|"url"\|"email"}` | Auto-detecting scan |
| POST | `/v1/scan/text` | `{"text": str, "channel": "sms"\|"whatsapp"\|"email"\|"other"}` | Message text |
| POST | `/v1/scan/url` | `{"url": str}` | Single URL (never fetched unless sandbox probing is enabled) |
| POST | `/v1/scan/email` | `{"raw": str}` | Full RFC 5322 message, or pasted headers + body |
| POST | `/v1/scan/email/upload` | multipart `file=@message.eml` | .eml upload |
| POST | `/v1/feedback` | `{"scan_id": str, "correct_label": label, "comment"?: str}` | Report a wrong verdict (stores features only) |

Error codes: `401` bad/missing API key · `413` input too large · `422` schema violation (unknown fields are rejected) · `429` rate-limited (`Retry-After` header) · `500` generic error (no internals leaked).

## Examples

```bash
curl -s localhost:8000/v1/scan/text -H 'content-type: application/json' \
  -d '{"text":"Dear Customer, your SBI account will be blocked today. Update your PAN immediately: http://sbi-kyc-update.xyz/login","channel":"sms"}'

curl -s localhost:8000/v1/scan/url -H 'content-type: application/json' -d '{"url":"http://paypa1.com/signin"}'

curl -s localhost:8000/v1/scan/email/upload -F 'file=@suspicious.eml'
```

PowerShell:
```powershell
Invoke-RestMethod -Method Post -Uri http://localhost:8000/v1/scan -ContentType 'application/json' `
  -Body (@{ content = 'Aapka KYC pending hai, turant link pe click karein: bit.ly/kyc-upd8' } | ConvertTo-Json)
```

### Response (real output, heuristics-only configuration; abridged)

```json
{
  "scan_id": "3f1c…",
  "input_type": "text",
  "label": "phishing",
  "risk_score": 100,
  "probability": 0.9986,
  "confidence": 0.99,
  "confidence_level": "high",
  "explanation": "This message is very likely a phishing attempt (risk 100/100). Red flags: The domain combines a brand name with extra words but is not owned by that brand; Asks you to update KYC/PAN/Aadhaar details - a common bank-impersonation lure; Threatens account blocking, penalties or other consequences; The domain uses a top-level domain frequently abused for phishing.",
  "recommended_action": "Do not click any links, open attachments, call numbers in it, or share any codes. Delete it and report it (India: cybercrime.gov.in or helpline 1930, fraud SMS/calls via Sanchar Saathi 'Chakshu'; email: use your provider's 'Report phishing' button).",
  "red_flags": [
    {"id": "url.combosquat", "layer": "url", "severity": "high",
     "description": "The domain combines a brand name with extra words but is not owned by that brand.",
     "evidence": "hxxp://sbi-kyc-update[.]xyz/login: 'sbi-kyc-update' contains brand sbi", "contribution": 2.4},
    {"id": "text.kyc_update", "layer": "text", "severity": "medium",
     "description": "Asks you to update KYC/PAN/Aadhaar details - a common bank-impersonation lure.",
     "evidence": "\"update your pan\"", "contribution": 1.8},
    {"id": "text.threat", "layer": "text", "severity": "medium",
     "description": "Threatens account blocking, penalties or other consequences.",
     "evidence": "\"account will be blocked\"", "contribution": 1.3},
    {"id": "url.suspicious_tld", "layer": "url", "severity": "medium",
     "description": "The domain uses a top-level domain frequently abused for phishing.",
     "evidence": "hxxp://sbi-kyc-update[.]xyz/login: .xyz", "contribution": 1.0}
  ],
  "mitigating_factors": [],
  "layer_scores": {"text": 94, "url": 82},
  "urls_analyzed": ["hxxp://sbi-kyc-update[.]xyz/login"],
  "model_terms": [],
  "intel": [],
  "model": {"ensemble_version": "default-v1", "text_model": null, "calibrated": false},
  "latency_ms": 1.0
}
```

A safe URL (`https://github.com/python/cpython`) returns `"label": "safe", "risk_score": 0`, no red flags, and one mitigating factor: `url.trusted_domain` (-2.5).

### Field semantics
- `probability`: calibrated probability that the input is malicious. Raw sigmoid if no calibrator has been trained (`model.calibrated=false`).
- `risk_score`: `round(100 × probability)`.
- `label`: `safe` if p < 0.40, `suspicious` if p < 0.70, otherwise `phishing` or `scam` (see ARCHITECTURE.md §8).
- `confidence`: `max(p, 1-p)` for safe/malicious verdicts. For `suspicious` it's lower, reflecting the grey zone.
- `contribution`: exact additive log-odds. `bias + Σ contributions = logit(p)` before calibration.
- `urls_analyzed` / `evidence`: URLs are **defanged** (`hxxp`, `[.]`). Treat all evidence as untrusted text.
