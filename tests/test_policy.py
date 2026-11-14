"""Tests for the policy that decides what blocks and what is a warning."""

import json
from pathlib import Path

import pytest

from securelint.cli import main
from securelint.config import ConfigError, load_config
from securelint.engine import ScanResult, scan
from securelint.html_report import format_html
from securelint.model import Confidence, Finding, Severity
from securelint.policy import Policy, apply_policy
from securelint.report import format_json, format_text
from securelint.rules import ALL_RULES

RULE_IDS = ["SL101", "SL102"]

# One file with findings at three different levels:
#   line 1: SL102, high severity, high confidence (the value is typed in)
#   line 2: SL102, high severity, medium confidence (a parameter)
#   line 3: SL104, medium severity, medium confidence
CODE = (
    'os.system("ping " + input())\n'
    "def f(host): os.system(host)\n"
    'DB_PASSWORD = "hunter2"\n'
)


def finding(severity: Severity, confidence: Confidence, line: int = 1) -> Finding:
    return Finding(
        rule_id="T001",
        message="Example problem.",
        severity=severity,
        confidence=confidence,
        path="app.py",
        line=line,
        column=1,
    )


def write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def project_with(tmp_path: Path, policy: str) -> Path:
    write(tmp_path / "app.py", CODE)
    if policy:
        write(tmp_path / "pyproject.toml", f"[tool.securelint.policy]\n{policy}\n")
    return tmp_path


def sorted_result(tmp_path: Path, policy: Policy) -> ScanResult:
    write(tmp_path / "app.py", CODE)
    return apply_policy(scan(tmp_path, ALL_RULES), policy)


def lines_of(findings: tuple[Finding, ...]) -> list[int]:
    return [item.line for item in findings]


def test_default_policy_blocks_everything() -> None:
    policy = Policy()

    assert all(
        policy.blocks(finding(severity, confidence))
        for severity in Severity
        for confidence in Confidence
    )


@pytest.mark.parametrize(
    ("severity", "confidence", "blocks"),
    [
        (Severity.CRITICAL, Confidence.HIGH, True),
        (Severity.HIGH, Confidence.HIGH, True),
        (Severity.HIGH, Confidence.MEDIUM, True),
        # Severe, but the rule is not sure enough.
        (Severity.HIGH, Confidence.LOW, False),
        (Severity.CRITICAL, Confidence.LOW, False),
        # The rule is sure, but the problem is not severe enough.
        (Severity.MEDIUM, Confidence.HIGH, False),
        (Severity.LOW, Confidence.HIGH, False),
        (Severity.LOW, Confidence.LOW, False),
    ],
)
def test_a_finding_blocks_when_both_levels_are_reached(
    severity: Severity, confidence: Confidence, blocks: bool
) -> None:
    policy = Policy(block_severity=Severity.HIGH, block_confidence=Confidence.MEDIUM)

    assert policy.blocks(finding(severity, confidence)) is blocks


def test_apply_policy_sorts_findings_without_losing_any(tmp_path: Path) -> None:
    policy = Policy(block_severity=Severity.HIGH, block_confidence=Confidence.HIGH)

    result = sorted_result(tmp_path, policy)

    assert lines_of(result.findings) == [1]
    assert lines_of(result.warnings) == [2, 3]


def test_apply_policy_with_the_defaults_changes_nothing(tmp_path: Path) -> None:
    result = sorted_result(tmp_path, Policy())

    assert lines_of(result.findings) == [1, 2, 3]
    assert result.warnings == ()


def test_settings_without_a_policy_give_the_default(tmp_path: Path) -> None:
    write(tmp_path / "pyproject.toml", "[tool.securelint]\n")

    assert load_config(tmp_path, RULE_IDS).policy == Policy()


def test_policy_is_read_from_the_settings(tmp_path: Path) -> None:
    write(
        tmp_path / "pyproject.toml",
        "[tool.securelint.policy]\n"
        'block-severity = "high"\nblock-confidence = "medium"\n',
    )

    assert load_config(tmp_path, RULE_IDS).policy == Policy(
        block_severity=Severity.HIGH, block_confidence=Confidence.MEDIUM
    )


def test_one_policy_setting_leaves_the_other_at_its_default(tmp_path: Path) -> None:
    write(
        tmp_path / "pyproject.toml",
        '[tool.securelint.policy]\nblock-severity = "critical"\n',
    )

    assert load_config(tmp_path, RULE_IDS).policy == Policy(
        block_severity=Severity.CRITICAL, block_confidence=Confidence.LOW
    )


@pytest.mark.parametrize(
    ("text", "message"),
    [
        (
            '[tool.securelint]\npolicy = "strict"\n',
            "[tool.securelint.policy] must be a table",
        ),
        (
            '[tool.securelint.policy]\nblock-severty = "high"\n',
            "unknown setting 'block-severty' in [tool.securelint.policy]",
        ),
        (
            '[tool.securelint.policy]\nblock-severity = "severe"\n',
            'block-severity must be one of "low", "medium", "high", "critical"',
        ),
        (
            '[tool.securelint.policy]\nblock-severity = "High"\n',
            "block-severity must be one of",
        ),
        (
            "[tool.securelint.policy]\nblock-severity = 3\n",
            "block-severity must be one of",
        ),
        (
            '[tool.securelint.policy]\nblock-confidence = "critical"\n',
            'block-confidence must be one of "low", "medium", "high"',
        ),
    ],
)
def test_a_mistake_in_the_policy_is_an_error(
    tmp_path: Path, text: str, message: str
) -> None:
    write(tmp_path / "pyproject.toml", text)

    with pytest.raises(ConfigError) as error:
        load_config(tmp_path, RULE_IDS)

    assert message in str(error.value)


def test_scan_without_a_policy_blocks_on_every_finding(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    project = project_with(tmp_path, "")

    assert main(["scan", str(project)]) == 1

    out = capsys.readouterr().out
    assert "(warning)" not in out
    assert out.splitlines()[-1] == "3 problems found in 1 file (2 high, 1 medium)."


def test_scan_with_a_policy_blocks_only_above_the_line(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    project = project_with(tmp_path, 'block-severity = "high"')

    assert main(["scan", str(project)]) == 1

    lines = capsys.readouterr().out.splitlines()
    assert lines[0].startswith("app.py:1:1  high      SL102  os.system()")
    assert lines[1].startswith("app.py:2:14  high      SL102  os.system()")
    assert lines[2].startswith("app.py:3:1  medium    SL104  (warning) A password")
    assert lines[-1] == "2 problems found in 1 file (2 high). Warnings: 1."


def test_scan_with_only_warnings_exits_0(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    project = project_with(tmp_path, 'block-severity = "critical"')

    assert main(["scan", str(project)]) == 0

    lines = capsys.readouterr().out.splitlines()
    # Everything is still shown.
    assert len([line for line in lines if "(warning)" in line]) == 3
    assert lines[-1] == "No blocking problems found in 1 file. Warnings: 3."


def test_confidence_decides_between_two_findings_of_the_same_rule(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    project = project_with(
        tmp_path, 'block-severity = "high"\nblock-confidence = "high"'
    )

    assert main(["scan", str(project), "--format", "json"]) == 1

    document = json.loads(capsys.readouterr().out)
    # The value typed by a user blocks; the parameter is a warning.
    assert [item["line"] for item in document["findings"]] == [1]
    assert [item["line"] for item in document["warnings"]] == [2, 3]
    assert document["summary"]["findings"] == 1
    assert document["summary"]["warnings"] == 2
    assert document["summary"]["by_severity"]["high"] == 1


def test_a_mistake_in_the_policy_stops_the_scan(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    project = project_with(tmp_path, 'block-severity = "severe"')

    assert main(["scan", str(project)]) == 2

    captured = capsys.readouterr()
    assert captured.out == ""
    assert "block-severity must be one of" in captured.err


def test_known_problems_are_neither_blocking_nor_warnings(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    project = project_with(tmp_path, 'block-severity = "high"')
    main(["baseline", str(project)])
    write(project / "new.py", 'API_KEY = "sk-live-123"\neval(data)\n')
    capsys.readouterr()

    assert main(["scan", str(project)]) == 1

    out = capsys.readouterr().out
    assert out.splitlines()[-1] == (
        "1 problem found in 2 files (1 high). Warnings: 1. Known problems not shown: 3."
    )


def test_baseline_records_warnings_as_well(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    project = project_with(tmp_path, 'block-severity = "critical"')

    main(["baseline", str(project)])

    # The baseline holds what exists, whatever the policy says about it
    # today; a stricter policy tomorrow must not make old problems "new".
    assert "Saved 3 known problems" in capsys.readouterr().out


def test_text_report_lists_warnings_in_file_order(tmp_path: Path) -> None:
    policy = Policy(block_severity=Severity.HIGH, block_confidence=Confidence.HIGH)

    lines = format_text(sorted_result(tmp_path, policy)).splitlines()

    assert [line.split("  ")[0] for line in lines[:3]] == [
        "app.py:1:1",
        "app.py:2:14",
        "app.py:3:1",
    ]
    assert ["(warning)" in line for line in lines[:3]] == [False, True, True]


def test_json_report_keeps_warnings_apart(tmp_path: Path) -> None:
    policy = Policy(block_severity=Severity.HIGH)

    document = json.loads(format_json(sorted_result(tmp_path, policy)))

    assert [item["rule_id"] for item in document["findings"]] == ["SL102", "SL102"]
    assert [item["rule_id"] for item in document["warnings"]] == ["SL104"]
    assert document["warnings"][0]["severity"] == "medium"


def test_html_report_has_a_warnings_section(tmp_path: Path) -> None:
    policy = Policy(block_severity=Severity.HIGH)

    page = format_html(sorted_result(tmp_path, policy))

    assert "<h2>Problems</h2>" in page
    assert "<h2>Warnings</h2>" in page
    assert page.index("<h2>Problems</h2>") < page.index("<h2>Warnings</h2>")
    assert (
        '<p class="status bad">2 problems found in 1 file (2 high). Warnings: 1.</p>'
        in page
    )


def test_html_report_with_only_warnings_is_not_shown_as_failed(tmp_path: Path) -> None:
    policy = Policy(block_severity=Severity.CRITICAL)

    page = format_html(sorted_result(tmp_path, policy))

    assert '<p class="status warn">No blocking problems found in 1 file.' in page
    assert "<h2>Problems</h2>" not in page
    assert "<h2>Warnings</h2>" in page


def test_html_report_without_warnings_has_no_warnings_section(tmp_path: Path) -> None:
    page = format_html(sorted_result(tmp_path, Policy()))

    assert "<h2>Warnings</h2>" not in page
