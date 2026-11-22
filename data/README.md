# Datasets

> **Licensing:** verify every dataset's current terms before use. This table is a summary, not legal advice. Several sources are research-only or non-commercial.
> **Safety:** raw data contains *live phishing* and real PII (Enron). Keep `data/raw/` local and out of git. Never open samples in a mail client or browser.

| Name (`download.py`) | Type | Size | Licence / terms | Notes |
|---|---|---|---|---|
| `sms_spam` – UCI SMS Spam Collection | SMS text | 5.5k | CC BY 4.0 | English only; "spam" is mostly prize/subscription scams |
| `spamassassin` – SpamAssassin public corpus | email | ~6k | Research use (see corpus readme) | 2002–2005; spam ≠ phishing. Good for headers and ham diversity |
| `nazario` – Jose Nazario phishing corpus | email (mbox) | ~10k+ | Research use, attribution | Real phishing 2005–present; file names change yearly |
| `enron` – Enron email (CMU) | email | ~500k | Public record (FERC) | Legitimate corporate mail. Sample 10–20k. Contains PII |
| `tranco` – Tranco top-1M | domains | 1M | Free incl. commercial (cite) | Benign URL source plus a better allowlist |
| `openphish` – OpenPhish community feed | URLs | ~500 live | Free, **non-commercial** | Also usable as an offline blocklist |
| `phishtank` – PhishTank verified | URLs | ~50k | Free with registration + attribution | Has timestamps, so time-based splits are possible |
| `uci_phishing_websites` | features | 11k | CC BY 4.0 | Pre-computed features only (no URLs). Comparison baseline |

**Hindi / Hinglish:** no large, openly licensed scam corpus exists. Recommended approach:
1. Collect consented samples (user feedback with opt-in content storage, or partner fraud teams).
2. Augment by translating and transliterating English scams, and keep augmented data **out of the test set**.
3. Build a **human-verified** Hindi/Hinglish test set of at least 500 per class before claiming any multilingual metrics.

## Pipeline

```bash
python data/download.py --list
python data/download.py sms_spam spamassassin nazario tranco openphish
python data/prepare.py --sources seed sms_spam spamassassin nazario tranco openphish   # [--by-time]
```

`prepare.py` does the following:
- **Cleaning:** drops empty records, caps length at 200k characters, normalises the schema.
- **Deduplication:** exact *and* template-level (lower-case, digits→0, URLs→`<url>`, whitespace collapsed). Duplicates with conflicting labels are dropped.
- **Leakage-safe split:** grouped by registered domain (URLs), sender domain (email) or template hash (SMS), so a campaign never straddles train and test. Use `--by-time` when timestamps exist (PhishTank) to test on the future. It asserts that no group appears in both train and test.
- **Class imbalance:** handled in training (balanced class weights), *not* by resampling the test set. Metrics are reported on the natural distribution, with recall at fixed FPR.

`seed/samples.jsonl` holds 60 hand-written synthetic messages (EN/HI/Hinglish) for plumbing tests only. It is **not** a training set.
