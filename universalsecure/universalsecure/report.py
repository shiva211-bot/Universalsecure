"""Formatting helpers for local scan reports."""

from __future__ import annotations

import json
from typing import Any


def to_json(report: dict[str, Any]) -> str:
    return json.dumps(report, indent=2, ensure_ascii=False) + "\n"


def to_markdown(report: dict[str, Any]) -> str:
    summary = report["summary"]
    total = sum(summary.values())
    lines = [
        "# Universalsecure local review",
        "",
        f"- Folder: `{report['root_name']}`",
        f"- Source files read: {report['scanned_files']}",
        f"- Files that could not be read: {report['unreadable_files']}",
        f"- Findings: {total}",
        (
            f"- Severity counts: critical {summary['critical']}, "
            f"high {summary['high']}, medium {summary['medium']}, low {summary['low']}"
        ),
        "",
        "> Heuristic results for human review. A finding is not proof of a vulnerability.",
        "",
    ]
    findings = report["findings"]
    if not findings:
        lines.extend(["No matching patterns were found.", ""])
        return "\n".join(lines)

    lines.extend(
        [
            "| Severity | Check | Location | Confidence | Evidence |",
            "| --- | --- | --- | --- | --- |",
        ]
    )
    for finding in findings:
        evidence = str(finding["evidence"]).replace("|", "\\|")
        title = str(finding["title"]).replace("|", "\\|")
        location = f"`{finding['path']}:{finding['line']}`"
        lines.append(
            f"| {finding['severity'].upper()} | {title} "
            f"({finding['rule_id']}) | {location} | {finding['confidence']} | {evidence} |"
        )
    lines.append("")
    lines.extend(["## Recommended next step", ""])
    lines.append(
        "Review each result in its source context, confirm whether it is reachable, "
        "and record any fix or reason for dismissal."
    )
    lines.append("")
    return "\n".join(lines)
