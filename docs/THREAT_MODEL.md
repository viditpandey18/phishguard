# Threat model

## Assets
1. **User content** submitted for scanning (messages and emails, which may contain PII, OTPs and financial data).
2. **Verdict integrity.** Users act on our labels, so a false "safe" causes direct harm.
3. **The scanning host and its network.** It must never be used to reach the internal network, fetch payloads or run attacker code.
4. **API availability**, and the secrets behind it (threat-intel API keys, PhishGuard API keys).
5. **Models and training data**, including feedback labels.

## Adversaries
| Adversary | Goal | Capability |
|---|---|---|
| Scammer / phisher | Evade detection (false "safe") | Full control of message text, HTML, headers below the receiving MTA, URLs, attachments; can probe the public API |
| Malicious API user | DoS, SSRF, abuse API as an oracle, exfiltrate others' data | Arbitrary requests |
| Poisoner | Corrupt retraining through feedback | Submits false feedback labels |
| Curious operator / log reader | Read user content | Access to logs, disks |

## Threats and mitigations

| # | Threat (STRIDE) | Mitigation in this codebase | Residual risk / next step |
|---|---|---|---|
| T1 | **Evasion via obfuscation** (zero-width, homoglyphs, fullwidth, spaced letters, defanged URLs, IP encodings, `@` userinfo) | `sanitize.py` normalisation; the obfuscation itself is a signal (`text.invisible_chars`, `text.mixed_script`, `url.punycode`); robustness tests in `tests/test_adversarial.py` and `training/evaluate.py` | Paraphrase and LLM-generated scams evade rules. The ML model and continual retraining are the defence |
| T2 | **Header forgery** (fake `Authentication-Results: pass`) | Only the top-most Authentication-Results header is trusted | Deployments should also check `authserv-id` equals their own MTA and strip inbound A-R headers at the edge |
| T3 | **Image-only / attachment-only lures, QR codes** | `text.image_only`, attachment signals | No OCR or QR decoding yet (roadmap). These get "low evidence", not "safe-confident" |
| T4 | **SSRF / visiting attacker URLs** | URLs are never fetched by default. Active probing is a separate flag, meant for the isolated `sandbox` service: SSRF guard on every hop, HEAD only, no redirects followed automatically, timeouts and hop limits | DNS rebinding between the check and the connection. The network egress policy is the real boundary |
| T5 | **Unsafe rendering of attacker HTML** (XSS in UI/extension) | HTML is tokenised, never rendered. API output is JSON with CSP `default-src 'none'`. URLs are returned defanged. UI and extension use plain text / `textContent` only | Consumers of the API must not render `evidence` as HTML |
| T6 | **Resource exhaustion** (huge emails, MIME bombs, regex DoS) | Streaming body limit (413), per-field limits, MIME part cap, body truncation, token-bucket rate limit, CPU/memory limits in compose. Regexes avoid nested quantifiers | Rate limiter is per process; use a gateway or Redis for multi-replica deployments |
| T7 | **Privacy leakage through logs and storage** | Content is never logged. A PII-redaction filter is the second line of defence. Feedback stores the signal vector only, and comments are redacted. `PG_STORE_CONTENT=false` by default | Third-party intel lookups disclose URLs. They're opt-in, documented and limited to the 3 riskiest URLs |
| T8 | **Oracle attacks** (iterate against the API until "safe") | API keys and rate limits. Explanations reveal *categories*, not weights | Determined attackers can still probe. Monitor high-volume clients and consider returning coarser output to untrusted callers |
| T9 | **Feedback poisoning** | Feedback is appended to a review queue, never auto-trained (see roadmap: human review, per-client caps, agreement thresholds) | Requires process controls |
| T10 | **Model artifact tampering / unsafe deserialization** | Artifacts are npz (with `allow_pickle=False`) plus JSON, not pickle. Transformer loads use `local_files_only=True`. Artifacts are mounted read-only | Sign artifacts and verify hashes in CI/CD |
| T11 | **Malicious dataset files** (archives, phishing samples) | Download size caps; tar `filter="data"` / zip path checks; files are parsed, never opened in a mail client | Keep `data/raw` off shared drives; it contains live phishing and PII |
| T12 | **Credential leakage** (intel API keys) | Keys come only from environment variables, never from logs or responses. `/v1/info` lists provider names only | Use a secret manager in production |

## Known limitations
- **Language coverage.** Rules cover English, Hindi (Devanagari) and romanized Hinglish. Other Indian languages (Tamil, Telugu, Bengali, Marathi…) fall back to URL, header and ML signals.
- **Brand list.** About 60 brands. Unknown local brands get no typosquat protection until added, or until a Tranco-based allowlist and brand mining are built (roadmap).
- **Simplified public-suffix list.** See ARCHITECTURE.md.
- **Hand-set default weights**, validated only on the bundled synthetic cases. **Measured metrics on real data come from running `training/evaluate.py` on your own data. None are claimed here.**
- **Legitimate fraud-awareness messages** ("police never ask for money… digital arrest is a scam") can trigger rule signals. Security-advice phrasing mitigates this but doesn't fully remove it.
- **No OCR / QR / voice** analysis. Attachments are not sandboxed or detonated.
- **Point-in-time verdicts.** A clean link can be weaponised after scanning. Pair with click-time protection.
