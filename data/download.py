"""Download public datasets into data/raw/<name>/ (safely).

    python data/download.py --list
    python data/download.py sms_spam spamassassin nazario tranco
    python data/download.py openphish            # community feed, see terms
    PHISHTANK_APP_KEY=... python data/download.py phishtank

ALWAYS read each dataset's licence/terms before use - several are
research/non-commercial only. Summary in data/README.md.

Safety: downloads are streamed with a size cap, never executed, and archives
are extracted with path-traversal protection into their own directory.
Downloaded files are untrusted data (they *are* phishing samples!): open
them only with the parsers in this repo, never in a mail client or browser.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import sys
import tarfile
import zipfile
from dataclasses import dataclass
from pathlib import Path

import httpx

RAW = Path(__file__).resolve().parent / "raw"
MAX_BYTES = 1_500_000_000  # 1.5 GB hard cap per file


@dataclass(frozen=True)
class Dataset:
    name: str
    urls: tuple[str, ...]
    license: str
    kind: str
    notes: str = ""
    needs_env: str | None = None


DATASETS: dict[str, Dataset] = {d.name: d for d in [
    Dataset("sms_spam", ("https://archive.ics.uci.edu/static/public/228/sms+spam+collection.zip",),
            "CC BY 4.0 (UCI ML Repository)", "text",
            "5,574 English SMS (ham/spam). Spam is mostly promotional/prize scams; no Hindi."),
    Dataset("spamassassin", tuple(f"https://spamassassin.apache.org/old/publiccorpus/{f}" for f in (
        "20030228_easy_ham.tar.bz2", "20030228_easy_ham_2.tar.bz2", "20030228_hard_ham.tar.bz2",
        "20030228_spam.tar.bz2", "20050311_spam_2.tar.bz2")),
            "Free for research; see corpus readme (Apache SpamAssassin project)", "email",
            "Full RFC822 ham/spam (2002-2005). Spam != phishing: use as weak positives or for header features."),
    Dataset("nazario", tuple(f"https://monkey.org/~jose/phishing/{f}" for f in (
        "phishing0.mbox", "phishing1.mbox", "phishing2.mbox", "phishing3.mbox",
        "phishing-2020", "phishing-2021", "phishing-2022", "phishing-2023", "phishing-2024")),
            "Research use; credit Jose Nazario. Check site for current terms.", "email",
            "Real phishing emails (mbox), 2005-present. File list changes yearly - update if 404."),
    Dataset("enron", ("https://www.cs.cmu.edu/~enron/enron_mail_20150507.tar.gz",),
            "Public record (FERC release); CMU distribution. Contains real PII - handle accordingly.", "email",
            "~500k legitimate corporate emails (1.7 GB uncompressed). Sample, don't use all."),
    Dataset("tranco", ("https://tranco-list.eu/top-1m.csv.zip",),
            "Free for research and commercial use (cite Le Pochat et al., NDSS 2019)", "url",
            "Top-1M domains: benign URL source and a better TRUSTED_DOMAINS allowlist (use top 10k-50k)."),
    Dataset("openphish", ("https://openphish.com/feed.txt",),
            "OpenPhish Community feed: free, non-commercial; commercial use needs a licence.", "url",
            "Live phishing URLs (~500, updated every 12h). Also usable as local blocklist (PG_OPENPHISH_FEED_FILE)."),
    Dataset("phishtank", ("http://data.phishtank.com/data/{key}/online-valid.csv.gz",),
            "Free with registration; attribution required; see phishtank.org terms.", "url",
            "Verified phishing URLs with submission timestamps (good for time-based splits).",
            needs_env="PHISHTANK_APP_KEY"),
    Dataset("uci_phishing_websites", ("https://archive.ics.uci.edu/static/public/327/phishing+websites.zip",),
            "CC BY 4.0 (UCI ML Repository)", "features",
            "11k sites as 30 pre-computed features (no raw URLs). Only for a feature-level baseline comparison."),
]}

OTHER_SOURCES = """
Not auto-downloaded (manual / registration / licence review needed):
  * Hindi & Hinglish scam SMS: no large open licensed corpus exists today. Options: Kaggle
    community sets (check licence per dataset), partner data via TRAI/bank fraud teams, and
    careful translation + transliteration augmentation of English scams (keep a human-verified test set).
  * CEAS-08, Ling-Spam, TREC 2007 spam: email corpora for extra ham/spam diversity.
  * PhishStorm / ISCX-URL-2016 / Mendeley "Phishing URL dataset": labelled URL corpora (academic licences).
  * Your own user feedback (data/feedback/feedback.jsonl) - features only by default.
"""


def _safe_extract(archive: Path, dest: Path) -> None:
    dest = dest.resolve()
    if zipfile.is_zipfile(archive):
        with zipfile.ZipFile(archive) as zf:
            for member in zf.infolist():
                target = (dest / member.filename).resolve()
                if not str(target).startswith(str(dest)):
                    raise RuntimeError(f"unsafe path in archive: {member.filename}")
            zf.extractall(dest)
    elif tarfile.is_tarfile(archive):
        with tarfile.open(archive) as tf:
            if sys.version_info >= (3, 12):
                tf.extractall(dest, filter="data")  # blocks traversal, links, devices
            else:
                for m in tf.getmembers():
                    target = (dest / m.name).resolve()
                    if not str(target).startswith(str(dest)) or m.issym() or m.islnk() or m.isdev():
                        raise RuntimeError(f"unsafe member in archive: {m.name}")
                tf.extractall(dest)


def fetch(url: str, dest: Path) -> Path:
    dest.parent.mkdir(parents=True, exist_ok=True)
    if dest.exists():
        print(f"  exists, skipping: {dest.name}")
        return dest
    sha = hashlib.sha256()
    total = 0
    tmp = dest.with_suffix(dest.suffix + ".part")
    with httpx.stream("GET", url, follow_redirects=True, timeout=60, headers={"User-Agent": "phishguard-dataset-fetch/1.0"}) as r:
        r.raise_for_status()
        with tmp.open("wb") as fh:
            for chunk in r.iter_bytes(1 << 20):
                total += len(chunk)
                if total > MAX_BYTES:
                    tmp.unlink(missing_ok=True)
                    raise RuntimeError(f"{url} exceeds size cap")
                sha.update(chunk)
                fh.write(chunk)
    tmp.rename(dest)
    print(f"  saved {dest.name} ({total / 1e6:.1f} MB) sha256={sha.hexdigest()[:16]}…")
    return dest


def download(name: str) -> None:
    ds = DATASETS[name]
    print(f"[{name}] licence: {ds.license}")
    key = ""
    if ds.needs_env:
        key = os.getenv(ds.needs_env, "")
        if not key:
            print(f"  skipped: set {ds.needs_env}")
            return
    out = RAW / name
    for url in ds.urls:
        url = url.format(key=key)
        fname = url.rstrip("/").split("/")[-1].replace(key, "KEY") if key else url.rstrip("/").split("/")[-1]
        try:
            path = fetch(url, out / fname)
        except httpx.HTTPError as exc:
            print(f"  failed {fname}: {type(exc).__name__} (URL may have moved - check source site)")
            continue
        if path.suffix in (".zip",) or path.name.endswith((".tar.gz", ".tar.bz2", ".tgz")):
            _safe_extract(path, out / "extracted")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("datasets", nargs="*")
    ap.add_argument("--list", action="store_true")
    args = ap.parse_args()
    if args.list or not args.datasets:
        for d in DATASETS.values():
            print(f"{d.name:24s} [{d.kind:8s}] {d.license}\n{'':24s} {d.notes}")
        print(OTHER_SOURCES)
        return
    for name in args.datasets:
        if name not in DATASETS:
            sys.exit(f"unknown dataset {name}; use --list")
        download(name)


if __name__ == "__main__":
    main()
