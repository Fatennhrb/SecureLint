"""Tests for the terminal report."""

from securelint.engine import ScanResult
from securelint.model import Confidence, Finding, Severity
from securelint.report import format_text


def finding(severity: Severity, line: int = 1) -> Finding:
    return Finding(
        rule_id="T001",
        message="Example problem.",
        severity=severity,
        confidence=Confidence.HIGH,
        path="pkg/app.py",
        line=line,
        column=5,
    )


def result(*findings: Finding, files_scanned: int = 3) -> ScanResult:
    return ScanResult(findings=findings, failures=(), files_scanned=files_scanned)


def test_no_findings() -> None:
    assert format_text(result()) == "No problems found in 3 files."


def test_one_file_is_singular() -> None:
    assert format_text(result(files_scanned=1)) == "No problems found in 1 file."


def test_one_finding() -> None:
    report = format_text(result(finding(Severity.HIGH, line=12), files_scanned=1))

    assert report.splitlines() == [
        "pkg/app.py:12:5  high      T001  Example problem.",
        "",
        "1 problem found in 1 file (1 high).",
    ]


def test_summary_counts_each_severity_most_serious_first() -> None:
    report = format_text(
        result(
            finding(Severity.LOW, line=1),
            finding(Severity.CRITICAL, line=2),
            finding(Severity.LOW, line=3),
            finding(Severity.MEDIUM, line=4),
        )
    )

    assert report.splitlines()[-1] == (
        "4 problems found in 3 files (1 critical, 1 medium, 2 low)."
    )


def test_findings_keep_the_order_of_the_result() -> None:
    report = format_text(
        result(finding(Severity.LOW, line=2), finding(Severity.HIGH, line=9))
    )

    assert [line.split("  ")[0] for line in report.splitlines()[:2]] == [
        "pkg/app.py:2:5",
        "pkg/app.py:9:5",
    ]
