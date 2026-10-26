"""Command-line interface for Universalsecure."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Sequence

from universalsecure.report import to_json, to_markdown
from universalsecure.scanner import scan_directory


SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="universalsecure",
        description="Read-only, offline source review for a local project folder.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    scan_parser = subparsers.add_parser(
        "scan",
        help="inspect source files in a local directory without executing them",
    )
    scan_parser.add_argument("directory", type=Path, help="local directory to review")
    scan_parser.add_argument(
        "--format",
        choices=("markdown", "json"),
        default="markdown",
        help="report format (default: markdown)",
    )
    scan_parser.add_argument(
        "--output",
        type=Path,
        help="write the report to a file instead of standard output",
    )
    scan_parser.add_argument(
        "--force",
        action="store_true",
        help="allow replacing an existing report file",
    )
    scan_parser.add_argument(
        "--fail-on",
        choices=("critical", "high", "medium", "low", "never"),
        default="high",
        help="return exit code 1 at this severity or above (default: high)",
    )
    return parser


def _write_report(destination: Path, content: str, force: bool) -> None:
    expanded_destination = destination.expanduser()
    mode = "w" if force else "x"
    with expanded_destination.open(mode, encoding="utf-8", newline="\n") as report_file:
        report_file.write(content)


def _has_failing_findings(report: dict[str, object], fail_on: str) -> bool:
    if fail_on == "never":
        return False
    threshold = SEVERITY_ORDER[fail_on]
    findings = report["findings"]
    return any(
        SEVERITY_ORDER.get(str(finding["severity"]), 99) <= threshold
        for finding in findings  # type: ignore[union-attr]
    )


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        report = scan_directory(args.directory)
        content = (
            to_json(report)
            if args.format == "json"
            else to_markdown(report)
        )
        if args.output:
            _write_report(args.output, content, args.force)
            print(f"Report written to {args.output}")
        else:
            sys.stdout.write(content)
        return 1 if _has_failing_findings(report, args.fail_on) else 0
    except (OSError, ValueError) as error:
        print(f"Universalsecure: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
