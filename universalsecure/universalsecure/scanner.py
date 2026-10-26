"""Read-only, offline source checks for a user-selected local directory."""

from __future__ import annotations

import os
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterator


MAX_FILE_BYTES = 1_000_000
IGNORED_DIRS = {
    ".git",
    ".hg",
    ".svn",
    ".venv",
    "venv",
    "__pycache__",
    "node_modules",
    "vendor",
    "dist",
    "build",
    "target",
    "coverage",
    ".next",
    ".turbo",
}
SUPPORTED_EXTENSIONS = {
    ".bash",
    ".c",
    ".cc",
    ".cfg",
    ".cjs",
    ".conf",
    ".cpp",
    ".cs",
    ".go",
    ".h",
    ".hpp",
    ".ini",
    ".java",
    ".js",
    ".json",
    ".jsx",
    ".kt",
    ".kts",
    ".mjs",
    ".php",
    ".properties",
    ".py",
    ".rb",
    ".rs",
    ".scala",
    ".sh",
    ".swift",
    ".toml",
    ".ts",
    ".tsx",
    ".yaml",
    ".yml",
}
SENSITIVE_FILENAMES = {
    ".npmrc",
    ".pypirc",
    "credentials",
    "credentials.json",
    "id_rsa",
    "id_ed25519",
    "secrets",
    "secrets.json",
    "secrets.yaml",
    "secrets.yml",
    "terraform.tfstate",
}
PLACEHOLDER_VALUES = re.compile(
    r"(?i)(?:example|sample|placeholder|changeme|change_me|your[_ -]|dummy|fake|test)"
)


@dataclass(frozen=True)
class Rule:
    rule_id: str
    title: str
    severity: str
    confidence: str
    message: str
    pattern: re.Pattern[str]
    redact_evidence: bool = False


RULES = (
    Rule(
        "US001",
        "Possible embedded credential",
        "high",
        "medium",
        "A credential-shaped value may be embedded in source. Rotate it if it is real, and load secrets from a secure runtime source instead.",
        re.compile(
            r"""(?ix)
            \b(?:AKIA|ASIA)[A-Z0-9]{16}\b
            |
            \bgithub_pat_[A-Za-z0-9_]{20,}\b
            |
            \bgh[pousr]_[A-Za-z0-9_]{20,}\b
            |
            \b(?:api[_-]?key|client[_-]?secret|password|passwd|secret|token)
            \b\s*[:=]\s*["'][^"'\r\n]{8,}["']
            """
        ),
        redact_evidence=True,
    ),
    Rule(
        "US002",
        "Dynamic code execution",
        "medium",
        "low",
        "Review dynamic eval/exec use and ensure untrusted input cannot control the evaluated code.",
        re.compile(r"\b(?:eval|exec)\s*\("),
    ),
    Rule(
        "US003",
        "Shell-enabled subprocess",
        "medium",
        "medium",
        "Review shell=True calls. Prefer argument arrays and avoid composing commands from untrusted values.",
        re.compile(
            r"\bsubprocess\.(?:run|Popen|call|check_output|check_call)\s*\(.*\bshell\s*=\s*True\b"
        ),
    ),
    Rule(
        "US004",
        "TLS certificate verification disabled",
        "medium",
        "high",
        "TLS verification appears to be disabled. Keep certificate verification enabled outside controlled tests.",
        re.compile(r"\b(?:verify|cert_reqs)\s*=\s*(?:False|0|['\"]CERT_NONE['\"])\b"),
    ),
    Rule(
        "US005",
        "Possible dynamically constructed SQL",
        "medium",
        "low",
        "SQL may be assembled dynamically. Prefer parameterized queries and verify values are passed separately from the query.",
        re.compile(
            r"""(?ix)
            \.(?:execute|executemany)\s*\(\s*f["']
            |
            \.(?:execute|executemany)\s*\([^)\n]{0,240}
            (?:\+\s*(?:user|request|params|input)|%\s*(?:user|request|params|input))
            """
        ),
    ),
    Rule(
        "US006",
        "Dynamic HTML insertion",
        "low",
        "low",
        "Review whether untrusted content can reach this HTML insertion point; use contextual escaping or safer rendering APIs.",
        re.compile(r"\b(?:dangerouslySetInnerHTML|innerHTML)\s*(?:=|:)"),
    ),
)


@dataclass(frozen=True)
class Finding:
    rule_id: str
    title: str
    severity: str
    confidence: str
    path: str
    line: int
    message: str
    evidence: str


def _is_sensitive_filename(filename: str) -> bool:
    lower_name = filename.lower()
    return (
        lower_name in SENSITIVE_FILENAMES
        or lower_name == ".env"
        or lower_name.startswith(".env.")
        or lower_name.endswith(".pem")
        or lower_name.endswith(".key")
    )


def _iter_source_files(root: Path) -> Iterator[Path]:
    for current, dirnames, filenames in os.walk(root, followlinks=False):
        current_path = Path(current)
        dirnames[:] = sorted(
            dirname
            for dirname in dirnames
            if dirname not in IGNORED_DIRS
            and not (current_path / dirname).is_symlink()
        )
        for filename in sorted(filenames):
            path = current_path / filename
            if path.is_symlink() or _is_sensitive_filename(filename):
                continue
            if path.suffix.lower() not in SUPPORTED_EXTENSIONS:
                continue
            try:
                if path.stat().st_size > MAX_FILE_BYTES:
                    continue
            except OSError:
                continue
            yield path


def _evidence(line: str, redact: bool) -> str:
    if redact:
        return "[credential-like value redacted]"
    normalized = " ".join(line.strip().split())
    return normalized[:180] + ("…" if len(normalized) > 180 else "")


def scan_directory(directory: str | Path) -> dict[str, object]:
    """Scan supported text files below ``directory`` without executing them."""
    requested_root = Path(directory).expanduser()
    if not requested_root.exists():
        raise ValueError(f"Directory does not exist: {requested_root}")
    if not requested_root.is_dir():
        raise ValueError(f"Path is not a directory: {requested_root}")

    root = requested_root.resolve()
    findings: list[Finding] = []
    scanned_files = 0
    unreadable_files = 0

    for path in _iter_source_files(root):
        try:
            content = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            unreadable_files += 1
            continue

        scanned_files += 1
        relative_path = path.relative_to(root).as_posix()
        for line_number, line in enumerate(content.splitlines(), start=1):
            for rule in RULES:
                if not rule.pattern.search(line):
                    continue
                if rule.rule_id == "US001" and PLACEHOLDER_VALUES.search(line):
                    continue
                findings.append(
                    Finding(
                        rule_id=rule.rule_id,
                        title=rule.title,
                        severity=rule.severity,
                        confidence=rule.confidence,
                        path=relative_path,
                        line=line_number,
                        message=rule.message,
                        evidence=_evidence(line, rule.redact_evidence),
                    )
                )

    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    findings.sort(
        key=lambda finding: (
            severity_order.get(finding.severity, 99),
            finding.path,
            finding.line,
            finding.rule_id,
        )
    )
    counts = {
        severity: sum(f.severity == severity for f in findings)
        for severity in ("critical", "high", "medium", "low")
    }
    return {
        "tool": "Universalsecure",
        "version": "0.1.0",
        "root_name": root.name or "selected-directory",
        "scanned_files": scanned_files,
        "unreadable_files": unreadable_files,
        "summary": counts,
        "findings": [asdict(finding) for finding in findings],
    }
