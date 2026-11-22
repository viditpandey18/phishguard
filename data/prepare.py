"""Build clean, deduplicated, leakage-safe train/val/test splits.

    python data/prepare.py --sources sms_spam nazario spamassassin tranco openphish seed
    -> data/processed/{train,val,test}.jsonl + stats.json

Unified record schema:
    {id, input_type: text|url|email, content, label: 0|1, category: ham|scam|phishing|spam,
     source, lang, group, timestamp}

Leakage controls
----------------
* Exact + template dedup: content normalised (lower-case, digits->0, URLs-><url>,
  whitespace collapsed) and hashed; duplicates dropped *before* splitting.
* Group split: records sharing a group (registered domain for URLs, sender domain
  for email, template hash for SMS) always land in the same split, so the model
  can't score well by memorising one campaign's wording or domain.
* Time split (preferred when timestamps exist, e.g. PhishTank): train on the past,
  test on the future - mirrors deployment and exposes concept drift.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import mailbox
import random
import re
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parent))

from phishguard.features.domain import parse_url, registered_domain_of  # noqa: E402

RAW, OUT = ROOT / "raw", ROOT / "processed"
MAX_CONTENT = 200_000


def norm_key(text: str) -> str:
    t = text.lower()
    t = re.sub(r"(https?://|www\.)\S+", "<url>", t)
    t = re.sub(r"\d", "0", t)
    t = re.sub(r"\s+", " ", t).strip()
    return hashlib.sha1(t.encode("utf-8", "ignore")).hexdigest()


def rec(content: str, label: int, category: str, source: str, input_type: str, group: str = "",
        lang: str = "en", timestamp: str | None = None) -> dict:
    content = content[:MAX_CONTENT]
    return {"id": hashlib.sha1(f"{source}:{content}".encode("utf-8", "ignore")).hexdigest()[:16],
            "input_type": input_type, "content": content, "label": label, "category": category,
            "source": source, "lang": lang, "group": group or norm_key(content)[:12], "timestamp": timestamp}


# ----------------------------------------------------------------- loaders
def load_sms_spam() -> list[dict]:
    path = next((RAW / "sms_spam").rglob("SMSSpamCollection"), None)
    if not path:
        return []
    out = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        lab, _, text = line.partition("\t")
        if text:
            # SMS spam here is mostly prize/subscription scams -> "scam"
            out.append(rec(text, int(lab == "spam"), "scam" if lab == "spam" else "ham", "sms_spam", "text"))
    return out


def _sender_domain(raw: bytes) -> str:
    m = re.search(rb"^From:.*?@([\w.-]+)", raw[:20000], re.M | re.I)
    return registered_domain_of(m.group(1).decode("ascii", "ignore")) if m else ""


def load_spamassassin() -> list[dict]:
    base = RAW / "spamassassin" / "extracted"
    out = []
    for d in base.glob("*") if base.exists() else []:
        is_spam = "spam" in d.name
        for f in d.iterdir():
            if f.is_file() and f.name != "cmds":
                raw = f.read_bytes()[:MAX_CONTENT]
                out.append(rec(raw.decode("utf-8", "replace"), int(is_spam), "spam" if is_spam else "ham",
                               "spamassassin", "email", group="sa:" + _sender_domain(raw)))
    return out


def load_nazario() -> list[dict]:
    out = []
    for f in sorted((RAW / "nazario").glob("*")) if (RAW / "nazario").exists() else []:
        if f.is_dir():
            continue
        try:
            box = mailbox.mbox(str(f), create=False)
            for msg in box:
                raw = msg.as_bytes()[:MAX_CONTENT]
                out.append(rec(raw.decode("utf-8", "replace"), 1, "phishing", "nazario", "email",
                               group="nz:" + _sender_domain(raw)))
        except Exception as exc:
            print(f"  skip {f.name}: {type(exc).__name__}")
    return out


def load_enron(limit: int = 20_000, seed: int = 0) -> list[dict]:
    base = RAW / "enron" / "extracted"
    files = [p for p in base.rglob("*") if p.is_file()] if base.exists() else []
    random.Random(seed).shuffle(files)
    out = []
    for f in files[:limit]:
        raw = f.read_bytes()[:MAX_CONTENT]
        out.append(rec(raw.decode("utf-8", "replace"), 0, "ham", "enron", "email", group="en:" + _sender_domain(raw)))
    return out


def _url_rec(url: str, label: int, source: str, ts: str | None = None) -> dict | None:
    p = parse_url(url)
    if not p:
        return None
    return rec(url, label, "phishing" if label else "ham", source, "url", group="dom:" + p.registered_domain, timestamp=ts)


def load_openphish() -> list[dict]:
    f = RAW / "openphish" / "feed.txt"
    lines = f.read_text(encoding="utf-8", errors="ignore").splitlines() if f.exists() else []
    return [r for r in (_url_rec(u.strip(), 1, "openphish") for u in lines if u.strip()) if r]


def load_phishtank() -> list[dict]:
    import csv
    import gzip
    out = []
    for f in (RAW / "phishtank").glob("*.csv.gz") if (RAW / "phishtank").exists() else []:
        with gzip.open(f, "rt", encoding="utf-8", errors="ignore") as fh:
            for row in csv.DictReader(fh):
                r = _url_rec(row.get("url", ""), 1, "phishtank", row.get("submission_time"))
                if r:
                    out.append(r)
    return out


def load_tranco(top: int = 30_000) -> list[dict]:
    f = next((RAW / "tranco").rglob("top-1m.csv"), None)
    if not f:
        return []
    out = []
    for i, line in enumerate(f.read_text().splitlines()[:top]):
        dom = line.split(",")[-1].strip()
        # Benign *URLs* need paths too, or the model learns "has path => phishing".
        path = random.Random(i).choice(["", "/", "/login", "/account", "/about", "/search?q=help", "/products/item-123"])
        r = _url_rec(f"https://{dom}{path}", 0, "tranco")
        if r:
            out.append(r)
    return out


def load_seed() -> list[dict]:
    out = []
    for line in (ROOT / "seed" / "samples.jsonl").read_text(encoding="utf-8").splitlines():
        if line.strip():
            d = json.loads(line)
            out.append(rec(d["text"], d["label"], "scam" if d["label"] else "ham", "seed", "text",
                           group="seed:" + d["group"], lang=d.get("lang", "en")))
    return out


LOADERS = {"sms_spam": load_sms_spam, "spamassassin": load_spamassassin, "nazario": load_nazario,
           "enron": load_enron, "openphish": load_openphish, "phishtank": load_phishtank,
           "tranco": load_tranco, "seed": load_seed}


# ----------------------------------------------------------------- pipeline
def dedupe(records: list[dict]) -> list[dict]:
    seen: dict[str, dict] = {}
    conflicts = 0
    for r in records:
        k = norm_key(r["content"])
        if k in seen:
            if seen[k]["label"] != r["label"]:
                conflicts += 1
                seen[k]["_conflict"] = True
            continue
        seen[k] = r
    kept = [r for r in seen.values() if not r.pop("_conflict", False)]  # drop label-conflicting dupes
    print(f"dedupe: {len(records)} -> {len(kept)} ({conflicts} label conflicts dropped)")
    return kept


def split(records: list[dict], val: float = 0.15, test: float = 0.15, by_time: bool = False) -> dict[str, list[dict]]:
    if by_time and all(r.get("timestamp") for r in records):
        records = sorted(records, key=lambda r: r["timestamp"])
        n = len(records)
        a, b = int(n * (1 - val - test)), int(n * (1 - test))
        return {"train": records[:a], "val": records[a:b], "test": records[b:]}
    parts: dict[str, list[dict]] = {"train": [], "val": [], "test": []}
    for r in records:
        h = int(hashlib.sha1(r["group"].encode()).hexdigest(), 16) % 10_000 / 10_000
        parts["test" if h < test else "val" if h < test + val else "train"].append(r)
    return parts


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--sources", nargs="+", default=["seed"], choices=sorted(LOADERS))
    ap.add_argument("--by-time", action="store_true", help="time-based split when all records have timestamps")
    ap.add_argument("--out", type=Path, default=OUT)
    args = ap.parse_args()

    records: list[dict] = []
    for s in args.sources:
        got = LOADERS[s]()
        print(f"{s}: {len(got)} records")
        records += got
    records = [r for r in records if r["content"].strip()]
    records = dedupe(records)
    parts = split(records, by_time=args.by_time)

    # sanity: no group may appear in two splits
    groups = {k: {r["group"] for r in v} for k, v in parts.items()}
    assert not (groups["train"] & groups["test"]) or args.by_time, "group leakage between train and test"

    args.out.mkdir(parents=True, exist_ok=True)
    stats = {}
    for name, rows in parts.items():
        with (args.out / f"{name}.jsonl").open("w", encoding="utf-8") as fh:
            for r in rows:
                fh.write(json.dumps(r, ensure_ascii=False) + "\n")
        stats[name] = {"n": len(rows), "by_label": dict(Counter(r["label"] for r in rows)),
                       "by_type": dict(Counter(r["input_type"] for r in rows)),
                       "by_source": dict(Counter(r["source"] for r in rows))}
    (args.out / "stats.json").write_text(json.dumps(stats, indent=2))
    print(json.dumps(stats, indent=2))


if __name__ == "__main__":
    main()
