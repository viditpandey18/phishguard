"""Command-line scanner.

    python -m phishguard.cli "Your KYC is pending, click bit.ly/x"
    python -m phishguard.cli --url "http://paypa1.com/login"
    python -m phishguard.cli --email suspicious.eml --json
    echo "some text" | python -m phishguard.cli -
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from phishguard.analyzer import Analyzer
from phishguard.logging_utils import configure_logging

_COLORS = {"safe": "\033[32m", "suspicious": "\033[33m", "phishing": "\033[31m", "scam": "\033[31m"}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="phishguard", description="Scan a message, email or URL for scams/phishing.")
    ap.add_argument("content", nargs="?", help="text to scan, or '-' for stdin")
    ap.add_argument("--url", help="scan a URL (never fetched)")
    ap.add_argument("--email", type=Path, help="path to an .eml file")
    ap.add_argument("--json", action="store_true", help="print the raw JSON response")
    args = ap.parse_args(argv)
    configure_logging("WARNING", json_format=False)

    an = Analyzer()
    if args.url:
        resp = an.analyze(args.url, "url")
    elif args.email:
        resp = an.analyze(args.email.read_bytes(), "email")
    elif args.content == "-":
        resp = an.analyze(sys.stdin.read(), "auto")
    elif args.content:
        resp = an.analyze(args.content, "auto")
    else:
        ap.print_help()
        return 2

    if args.json:
        print(resp.model_dump_json(indent=2))
    else:
        color = _COLORS.get(resp.label, "") if sys.stdout.isatty() else ""
        reset = "\033[0m" if color else ""
        print(f"{color}{resp.label.upper()}{reset}  risk {resp.risk_score}/100  "
              f"confidence {resp.confidence:.2f} ({resp.confidence_level})  [{resp.input_type}]")
        print(resp.explanation)
        for f in resp.red_flags:
            print(f"  ! [{f.severity:6s}] {f.description}  ({f.evidence})")
        for f in resp.mitigating_factors:
            print(f"  + {f.description}  ({f.evidence})")
        print(f"Advice: {resp.recommended_action}")
    return 0 if resp.label == "safe" else 1


if __name__ == "__main__":
    sys.exit(main())
