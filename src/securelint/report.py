"""Turn a scan result into a report: text for people, JSON for programs."""

import json
from collections import Counter
from typing import Any

from securelint import __version__
from securelint.engine import ScanResult
from securelint.model import Severity

JSON_FORMAT_VERSION = 1
"""Raised when the JSON report changes in a way that could break a program
reading it (a field removed or renamed). Adding a field does not count."""


def format_text(result: ScanResult) -> str:
    """Return one line per finding, then a one-line summary.

    Each finding starts with ``path:line:column``, a form that editors and
    terminals recognise and turn into a link to the exact place.
    """
    lines = [
        f"{finding.path}:{finding.line}:{finding.column}"
        f"  {finding.severity.name.lower():<8}"
        f"  {finding.rule_id}  {finding.message}"
        for finding in result.findings
    ]
    if lines:
        lines.append("")
    lines.append(_summary(result))
    return "\n".join(lines)


def format_json(result: ScanResult) -> str:
    """Return the whole scan result as a JSON document.

    It holds the same information as the text report, plus each finding's
    confidence and the files that could not be scanned, so a program
    reading it never has to parse sentences.
    """
    counts = Counter(finding.severity for finding in result.findings)
    document: dict[str, Any] = {
        "format_version": JSON_FORMAT_VERSION,
        "tool": {"name": "securelint", "version": __version__},
        "summary": {
            "files_scanned": result.files_scanned,
            "findings": len(result.findings),
            # Every severity is listed, also with a count of zero, so a
            # reader can use any of them without checking it is there.
            "by_severity": {
                severity.name.lower(): counts[severity]
                for severity in sorted(Severity, reverse=True)
            },
            "failures": len(result.failures),
        },
        "findings": [
            {
                "rule_id": finding.rule_id,
                "severity": finding.severity.name.lower(),
                "confidence": finding.confidence.name.lower(),
                "path": finding.path,
                "line": finding.line,
                "column": finding.column,
                "message": finding.message,
            }
            for finding in result.findings
        ],
        "failures": [
            {
                "path": failure.relative_path,
                "line": failure.line,
                "message": failure.message,
            }
            for failure in result.failures
        ],
    }
    # Characters outside ASCII are written as \u escapes (the default), so
    # the report prints on any terminal whatever its encoding.
    return json.dumps(document, indent=2)


def _summary(result: ScanResult) -> str:
    files = _count(result.files_scanned, "file")
    if not result.findings:
        return f"No problems found in {files}."

    counts = Counter(finding.severity for finding in result.findings)
    # Most serious first: "1 critical, 2 high", never "2 high, 1 critical".
    by_severity = ", ".join(
        f"{counts[severity]} {severity.name.lower()}"
        for severity in sorted(Severity, reverse=True)
        if counts[severity]
    )
    problems = _count(len(result.findings), "problem")
    return f"{problems} found in {files} ({by_severity})."


def _count(number: int, noun: str) -> str:
    """Return e.g. ``1 file`` or ``3 files``."""
    return f"{number} {noun}" if number == 1 else f"{number} {noun}s"
