"""Tests for the text and JSON reports."""

import json

from securelint import __version__
from securelint.engine import ScanResult
from securelint.model import Confidence, Finding, Severity
from securelint.parsing import ParseFailure
from securelint.report import format_json, format_text


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


def test_json_report_of_a_clean_scan() -> None:
    assert json.loads(format_json(result())) == {
        "format_version": 1,
        "tool": {"name": "securelint", "version": __version__},
        "summary": {
            "files_scanned": 3,
            "findings": 0,
            "by_severity": {"critical": 0, "high": 0, "medium": 0, "low": 0},
            "failures": 0,
            "silenced": 0,
        },
        "findings": [],
        "silenced": [],
        "failures": [],
    }


def test_json_report_holds_every_field_of_a_finding() -> None:
    document = json.loads(format_json(result(finding(Severity.HIGH, line=12))))

    assert document["findings"] == [
        {
            "rule_id": "T001",
            "severity": "high",
            "confidence": "high",
            "path": "pkg/app.py",
            "line": 12,
            "column": 5,
            "message": "Example problem.",
        }
    ]


def test_json_summary_counts_each_severity() -> None:
    document = json.loads(
        format_json(
            result(
                finding(Severity.LOW, line=1),
                finding(Severity.CRITICAL, line=2),
                finding(Severity.LOW, line=3),
            )
        )
    )

    assert document["summary"]["findings"] == 3
    assert document["summary"]["by_severity"] == {
        "critical": 1,
        "high": 0,
        "medium": 0,
        "low": 2,
    }
    assert [item["line"] for item in document["findings"]] == [1, 2, 3]


def test_json_report_lists_files_that_could_not_be_scanned() -> None:
    failures = (
        ParseFailure("broken.py", "invalid syntax", line=4),
        ParseFailure("locked.py", "permission denied"),
    )
    scan_result = ScanResult(findings=(), failures=failures, files_scanned=1)

    document = json.loads(format_json(scan_result))

    assert document["summary"]["failures"] == 2
    assert document["failures"] == [
        {"path": "broken.py", "line": 4, "message": "invalid syntax"},
        {"path": "locked.py", "line": None, "message": "permission denied"},
    ]


def test_json_report_uses_only_ascii_characters() -> None:
    odd = Finding(
        rule_id="T001",
        message='Quote " and accent é.',
        severity=Severity.LOW,
        confidence=Confidence.LOW,
        path="café/app.py",
        line=1,
        column=1,
    )

    report = format_json(result(odd))

    assert report.isascii()
    assert json.loads(report)["findings"][0]["path"] == "café/app.py"
    assert json.loads(report)["findings"][0]["message"] == 'Quote " and accent é.'
