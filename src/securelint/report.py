"""Turn a scan result into a report: text for people, JSON for programs."""

import json
from collections import Counter
from typing import Any

from securelint import __version__
from securelint.engine import ScanResult
from securelint.model import Finding, Severity

JSON_FORMAT_VERSION = 1
"""Raised when the JSON report changes in a way that could break a program
reading it (a field removed or renamed). Adding a field does not count."""


def format_text(result: ScanResult) -> str:
    """Return one line per finding, then a one-line summary.

    Each finding starts with ``path:line:column``, a form that editors and
    terminals recognise and turn into a link to the exact place. A finding
    that the policy does not block is marked ``(warning)``.
    """
    # Blocking findings and warnings are listed together in file order, so
    # everything about one place in the code is read in one go.
    marked = [(finding, "") for finding in result.findings]
    marked += [(finding, "(warning) ") for finding in result.warnings]
    marked.sort(key=lambda item: _position(item[0]))
    lines = [
        f"{finding.path}:{finding.line}:{finding.column}"
        f"  {finding.severity.name.lower():<8}"
        f"  {finding.rule_id}  {mark}{finding.message}"
        for finding, mark in marked
    ]
    if lines:
        lines.append("")
    lines.append(summary_line(result))
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
            "warnings": len(result.warnings),
            "silenced": len(result.silenced),
            "known": len(result.known),
        },
        # The findings that block. Without a policy, that is all of them.
        "findings": [_finding_fields(finding) for finding in result.findings],
        # Findings that the project's policy reports without blocking.
        "warnings": [_finding_fields(finding) for finding in result.warnings],
        # Findings hidden by a comment in the code, with the reason given.
        "silenced": [
            {**_finding_fields(item.finding), "reason": item.reason}
            for item in result.silenced
        ],
        # Findings listed in the project's baseline file.
        "known": [_finding_fields(finding) for finding in result.known],
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


def _finding_fields(finding: Finding) -> dict[str, Any]:
    return {
        "rule_id": finding.rule_id,
        "severity": finding.severity.name.lower(),
        "confidence": finding.confidence.name.lower(),
        "path": finding.path,
        "line": finding.line,
        "column": finding.column,
        "message": finding.message,
        "fingerprint": finding.fingerprint,
    }


def summary_line(result: ScanResult) -> str:
    """Return the result in words, e.g. ``2 problems found in 1 file (2 high).``

    When comments in the code silenced some findings, their number follows:
    ``No problems found in 3 files. Silenced by a comment: 2.`` The number
    of findings listed in the baseline file is given the same way, and so
    is the number of warnings when the project has a policy.
    """
    summary = _findings_summary(result)
    if result.warnings:
        summary += f" Warnings: {len(result.warnings)}."
    if result.silenced:
        summary += f" Silenced by a comment: {len(result.silenced)}."
    if result.known:
        summary += f" Known problems not shown: {len(result.known)}."
    return summary


def _findings_summary(result: ScanResult) -> str:
    files = _count(result.files_scanned, "file")
    if not result.findings:
        # "No problems" would be untrue next to a list of warnings.
        nothing = "No blocking problems" if result.warnings else "No problems"
        return f"{nothing} found in {files}."

    counts = Counter(finding.severity for finding in result.findings)
    # Most serious first: "1 critical, 2 high", never "2 high, 1 critical".
    by_severity = ", ".join(
        f"{counts[severity]} {severity.name.lower()}"
        for severity in sorted(Severity, reverse=True)
        if counts[severity]
    )
    problems = _count(len(result.findings), "problem")
    return f"{problems} found in {files} ({by_severity})."


def _position(finding: Finding) -> tuple[str, int, int, str]:
    return (finding.path, finding.line, finding.column, finding.rule_id)


def _count(number: int, noun: str) -> str:
    """Return e.g. ``1 file`` or ``3 files``."""
    return f"{number} {noun}" if number == 1 else f"{number} {noun}s"
