"""Tests for the notes GitHub Actions shows on a pull request."""

from dataclasses import replace
from pathlib import Path

import pytest

from securelint.cli import main
from securelint.engine import ScanResult, scan
from securelint.github_report import format_github, format_step_summary
from securelint.model import Confidence, Finding, Severity
from securelint.parsing import ParseFailure
from securelint.policy import Policy, apply_policy
from securelint.rules import ALL_RULES

# Line 1: SL102, high severity, high confidence (the value is typed in).
# Line 2: SL104, medium severity, medium confidence.
CODE = 'os.system("ping " + input())\nDB_PASSWORD = "hunter2"\n'


def write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def scanned(tmp_path: Path, code: str = CODE) -> ScanResult:
    write(tmp_path / "app.py", code)
    return scan(tmp_path, ALL_RULES)


def finding(path: str = "app.py", message: str = "Example problem.") -> Finding:
    return Finding(
        rule_id="T001",
        message=message,
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        path=path,
        line=3,
        column=7,
    )


def result_with(*findings: Finding) -> ScanResult:
    return ScanResult(findings=findings, failures=(), files_scanned=1)


def notes(report: str) -> list[str]:
    return [line for line in report.splitlines() if line.startswith("::")]


def test_one_note_in_full() -> None:
    report = format_github(result_with(finding()))

    assert report.splitlines() == [
        "::error file=app.py,line=3,col=7,title=T001 (high%2C confidence medium)"
        "::Example problem.",
        "1 problem found in 1 file (1 high).",
    ]


def test_clean_scan_prints_only_the_summary(tmp_path: Path) -> None:
    assert format_github(scanned(tmp_path, "print('safe')\n")) == (
        "No problems found in 1 file."
    )


def test_policy_decides_error_or_warning(tmp_path: Path) -> None:
    result = apply_policy(
        scanned(tmp_path),
        Policy(block_severity=Severity.HIGH, block_confidence=Confidence.HIGH),
    )

    report = notes(format_github(result))

    assert [note.split(" ")[0] for note in report] == ["::error", "::warning"]
    assert "line=1," in report[0]
    assert "line=2," in report[1]


def test_known_silenced_and_out_of_change_findings_are_only_counted() -> None:
    hidden = finding()
    result = replace(
        result_with(),
        known=(hidden,),
        outside_change=(hidden,),
    )

    report = format_github(result)

    assert notes(report) == []
    assert report == (
        "No problems found in 1 file. Known problems not shown: 1. "
        "Outside the changed lines: 1."
    )


def test_paths_start_at_the_top_of_the_project() -> None:
    result = replace(result_with(finding(path="pkg/app.py")), base="src")

    (note,) = notes(format_github(result))

    assert note.startswith("::error file=src/pkg/app.py,line=3,")


def test_files_that_cannot_be_scanned_are_error_notes() -> None:
    failures = (
        ParseFailure("broken.py", "invalid syntax", line=4),
        ParseFailure("locked.py", "cannot read file"),
    )
    result = ScanResult(findings=(), failures=failures, files_scanned=0)

    assert notes(format_github(result)) == [
        "::error file=broken.py,line=4::SecureLint cannot scan this file: "
        "invalid syntax",
        "::error file=locked.py::SecureLint cannot scan this file: cannot read file",
    ]


def test_a_new_line_in_a_message_cannot_start_a_fake_note() -> None:
    message = "Bad value.\n::notice file=fake.py::Everything is fine\r\nmore"

    report = format_github(result_with(finding(message=message)))

    # Still exactly one note, holding the whole message.
    assert len(notes(report)) == 1
    assert notes(report)[0].endswith(
        "::Bad value.%0A::notice file=fake.py::Everything is fine%0D%0Amore"
    )


def test_percent_signs_are_escaped_first() -> None:
    (note,) = notes(format_github(result_with(finding(message="100%0A done"))))

    # Escaped as "%25" first, so GitHub shows "%0A" as written, not a new line.
    assert note.endswith("::100%250A done")


@pytest.mark.parametrize(
    ("path", "written"),
    [
        # A comma could add a property, a colon could end the list early.
        ("a,line=999.py", "a%2Cline=999.py"),
        ("odd::name.py", "odd%3A%3Aname.py"),
        ("100%.py", "100%25.py"),
        ("café/app.py", "café/app.py"),
    ],
)
def test_file_names_cannot_change_the_note(path: str, written: str) -> None:
    (note,) = notes(format_github(result_with(finding(path=path))))

    assert note.startswith(f"::error file={written},line=3,col=7,")


def test_step_summary_of_a_clean_scan() -> None:
    summary = format_step_summary(result_with())

    assert summary.splitlines()[:3] == [
        "## SecureLint",
        "",
        "**Passed:** nothing blocks.",
    ]
    assert "| Files scanned | 1 |" in summary
    assert "| Blocking problems | 0 |" in summary
    assert summary.endswith("\n")


def test_step_summary_when_something_blocks(tmp_path: Path) -> None:
    result = apply_policy(scanned(tmp_path), Policy(block_severity=Severity.HIGH))

    summary = format_step_summary(result)

    assert "**Blocked:** 1 problem must be fixed." in summary
    assert "| Blocking problems | 1 |" in summary
    assert "| &nbsp;&nbsp;high | 1 |" in summary
    assert "| &nbsp;&nbsp;medium | 0 |" in summary
    assert "| Warnings | 1 |" in summary


def test_step_summary_of_an_incomplete_scan() -> None:
    failures = (ParseFailure("broken.py", "invalid syntax", line=4),)
    result = ScanResult(findings=(finding(),), failures=failures, files_scanned=1)

    summary = format_step_summary(result)

    # An incomplete scan is never called "passed", even with nothing found.
    assert "**Incomplete:** 1 file could not be scanned" in summary
    assert "| Files that could not be scanned | 1 |" in summary


def test_step_summary_holds_no_text_from_the_scanned_code() -> None:
    odd = finding(path="<script>.py", message="<img src=x> | table breaker")

    summary = format_step_summary(result_with(odd))

    assert "<script>" not in summary
    assert "<img" not in summary
    assert "table breaker" not in summary


def test_command_writes_the_step_summary_inside_github_actions(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    write(tmp_path / "project" / "app.py", CODE)
    summary_file = tmp_path / "summary.md"
    summary_file.write_text("Earlier step.\n", encoding="utf-8")
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary_file))

    assert main(["scan", str(tmp_path / "project"), "--format", "github"]) == 1

    out = capsys.readouterr().out
    assert len(notes(out)) == 2
    written = summary_file.read_text(encoding="utf-8")
    # Added after what earlier steps wrote, not instead of it.
    assert written.startswith("Earlier step.\n## SecureLint\n")
    assert "**Blocked:** 2 problems must be fixed." in written


def test_command_writes_no_summary_outside_github_actions(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    write(tmp_path / "app.py", CODE)
    monkeypatch.delenv("GITHUB_STEP_SUMMARY", raising=False)

    assert main(["scan", str(tmp_path), "--format", "github"]) == 1
    assert capsys.readouterr().err == ""


def test_other_formats_write_no_summary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    write(tmp_path / "project" / "app.py", CODE)
    summary_file = tmp_path / "summary.md"
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary_file))

    main(["scan", str(tmp_path / "project"), "--format", "sarif"])
    capsys.readouterr()

    assert not summary_file.exists()


def test_a_summary_that_cannot_be_written_does_not_change_the_result(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    write(tmp_path / "project" / "app.py", "print('safe')\n")
    # A folder, not a file: opening it for writing fails.
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(tmp_path))

    assert main(["scan", str(tmp_path / "project"), "--format", "github"]) == 0

    captured = capsys.readouterr()
    assert captured.out == "No problems found in 1 file.\n"
    assert "securelint: cannot write the job summary:" in captured.err
