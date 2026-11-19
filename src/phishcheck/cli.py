"""phishcheck command line."""

from __future__ import annotations

import argparse
import glob
import json
import sys
from collections.abc import Sequence
from pathlib import Path

from . import __version__
from .checks import analyse
from .intel import IntelClient
from .lookalike import BrandCatalog
from .models import Analysis
from .parser import iter_file
from .report import render_html, render_summary, render_text, to_dict

_RANK = {"clean": 0, "suspicious": 1, "phishing": 2}


def _expand(paths: Sequence[str]) -> list[Path]:
    files: list[Path] = []
    for pattern in paths:
        matches = glob.glob(pattern) if any(c in pattern for c in "*?[") else [pattern]
        if not matches:
            raise FileNotFoundError(f"no files match {pattern!r}")
        for match in matches:
            path = Path(match)
            if path.is_dir():
                files.extend(
                    sorted(p for p in path.rglob("*") if p.is_file() and p.suffix.lower() in (".eml", ".mbox"))
                )
            elif path.is_file():
                files.append(path)
            else:
                raise FileNotFoundError(f"{match} does not exist")
    return files


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="phishcheck",
        description="Analyse emails (.eml files or Gmail Takeout .mbox archives) for signs of phishing.",
    )
    parser.add_argument("paths", nargs="*", help=".eml / .mbox files, folders or glob patterns")
    parser.add_argument("--gui", action="store_true", help="open the drag-and-drop window in your browser")
    parser.add_argument("--port", type=int, default=8765, help="port for --gui (default 8765)")
    parser.add_argument("--no-browser", action="store_true", help="with --gui: don't open the browser automatically")
    parser.add_argument(
        "--vscode",
        action="store_true",
        help="with --gui: show the window inside VS Code's Simple Browser instead of your web browser",
    )
    parser.add_argument("--html", metavar="FILE", help="also write an HTML report")
    parser.add_argument("--json", action="store_true", help="print JSON instead of text")
    parser.add_argument("--details", action="store_true", help="always print the full report for every email")
    parser.add_argument("--brands", metavar="FILE", help="extra brands JSON (e.g. your bank) to protect")
    parser.add_argument(
        "--online",
        action="store_true",
        help="look up domains, attachment hashes and the sender IP on VirusTotal/AbuseIPDB "
        "(needs VT_API_KEY and/or ABUSEIPDB_API_KEY environment variables)",
    )
    parser.add_argument("--max-lookups", type=int, default=4, help="VirusTotal lookups per email (default 4)")
    parser.add_argument(
        "--fail-on", choices=("suspicious", "phishing"), help="exit with status 2 at or above this verdict"
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(errors="replace")  # emoji in subjects must not crash a cp1252 console
    parser = build_parser()
    args = parser.parse_args(argv)
    if not args.paths and not args.gui:
        parser.error("give one or more .eml/.mbox files, or use --gui for the drag-and-drop window")

    try:
        catalog = BrandCatalog.load(args.brands)
        files = _expand(args.paths) if args.paths else []
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    intel: IntelClient | None = None
    if args.online:
        intel = IntelClient.from_env(args.max_lookups)
        if not intel.enabled:
            print("error: --online needs VT_API_KEY and/or ABUSEIPDB_API_KEY to be set", file=sys.stderr)
            return 1

    if args.gui:
        from .web import AppState, serve

        state = AppState(catalog, intel, args.max_lookups, allow_vscode=args.vscode)
        return serve(state, args.port, open_browser=not (args.no_browser or args.vscode))

    if not files:
        print("error: no .eml or .mbox files found", file=sys.stderr)
        return 1

    analyses: list[Analysis] = []
    errors = 0
    for file in files:
        try:
            for email in iter_file(file):
                extra = []
                if intel:
                    intel.remaining = args.max_lookups
                    extra = intel.lookup(email, catalog)
                analyses.append(analyse(email, catalog, extra))
        except (OSError, ValueError) as exc:
            errors += 1
            print(f"error: could not read {file}: {exc}", file=sys.stderr)

    if args.json:
        print(json.dumps([to_dict(a) for a in analyses], indent=2, ensure_ascii=False))
    else:
        show_details = args.details or len(analyses) <= 5
        if show_details:
            for analysis in analyses:
                print(render_text(analysis))
                print()
        if len(analyses) > 1:
            print(render_summary(analyses))
        if not show_details:
            print("\nShowing the summary only. Use --details or --html report.html for full reports.")

    if args.html:
        Path(args.html).write_text(render_html(analyses), encoding="utf-8")
        if not args.json:
            print(f"\nHTML report written to {Path(args.html).resolve()}")

    if errors and not analyses:
        return 1
    if args.fail_on and any(_RANK[a.verdict] >= _RANK[args.fail_on] for a in analyses):
        return 2
    return 0
