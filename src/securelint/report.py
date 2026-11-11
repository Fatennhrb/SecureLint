"""Turn a scan result into text for the terminal."""

from collections import Counter

from securelint.engine import ScanResult
from securelint.model import Severity


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
