"""Tests for the SARIF report."""

import json
from pathlib import Path
from typing import Any

import pytest

from securelint import __version__
from securelint.cli import main
from securelint.engine import ScanResult, scan
from securelint.model import Confidence, Severity
from securelint.parsing import ParseFailure
from securelint.policy import Policy, apply_policy
from securelint.rules import ALL_RULES
from securelint.sarif_report import format_sarif

# Line 1: SL102, high severity, high confidence (the value is typed in).
# Line 2: SL104, medium severity, medium confidence.
CODE = 'os.system("ping " + input())\nDB_PASSWORD = "hunter2"\n'


def write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def sarif_of(result: ScanResult) -> dict[str, Any]:
    document: dict[str, Any] = json.loads(format_sarif(result))
    return document


def run_of(result: ScanResult) -> dict[str, Any]:
    run: dict[str, Any] = sarif_of(result)["runs"][0]
    return run


def scanned(tmp_path: Path, code: str = CODE) -> ScanResult:
    write(tmp_path / "app.py", code)
    return scan(tmp_path, ALL_RULES)


def test_document_header(tmp_path: Path) -> None:
    document = sarif_of(scanned(tmp_path))

    assert document["version"] == "2.1.0"
    assert document["$schema"] == "https://json.schemastore.org/sarif-2.1.0.json"
    assert len(document["runs"]) == 1


def test_tool_description(tmp_path: Path) -> None:
    driver = run_of(scanned(tmp_path))["tool"]["driver"]

    assert driver["name"] == "SecureLint"
    assert driver["version"] == __version__
    assert driver["informationUri"] == "https://github.com/Fatennhrb/SecureLint"


def test_a_clean_scan_has_no_results_and_no_rules(tmp_path: Path) -> None:
    run = run_of(scanned(tmp_path, "print('safe')\n"))

    assert run["results"] == []
    assert run["tool"]["driver"]["rules"] == []
    assert run["invocations"] == [
        {"executionSuccessful": True, "toolExecutionNotifications": []}
    ]


def test_one_result_in_full(tmp_path: Path) -> None:
    result = scanned(tmp_path, "def f(host):\n    os.system(host)\n")

    (item,) = run_of(result)["results"]

    assert item == {
        "ruleId": "SL102",
        "ruleIndex": 0,
        "level": "error",
        "message": {"text": result.findings[0].message},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": "app.py", "uriBaseId": "%SRCROOT%"},
                    "region": {"startLine": 2, "startColumn": 5},
                }
            }
        ],
        "partialFingerprints": {"securelint/v1": result.findings[0].fingerprint},
        "properties": {"severity": "high", "confidence": "medium"},
    }


def test_rules_list_only_the_rules_with_results(tmp_path: Path) -> None:
    rules = run_of(scanned(tmp_path))["tool"]["driver"]["rules"]

    assert [rule["id"] for rule in rules] == ["SL102", "SL104"]
    assert rules[0] == {
        "id": "SL102",
        "name": "SL102",
        "shortDescription": {"text": "Shell command built at run time"},
        "helpUri": "https://github.com/Fatennhrb/SecureLint#rules",
        "properties": {"tags": ["security"], "security-severity": "8.0"},
    }
    assert rules[1]["properties"]["security-severity"] == "5.5"


def test_rule_index_points_at_the_rule(tmp_path: Path) -> None:
    run = run_of(scanned(tmp_path))
    rules = run["tool"]["driver"]["rules"]

    for item in run["results"]:
        assert rules[item["ruleIndex"]]["id"] == item["ruleId"]


def test_every_real_rule_has_a_title() -> None:
    assert all(rule.title for rule in ALL_RULES)


def test_the_comment_rule_has_a_title(tmp_path: Path) -> None:
    rules = run_of(scanned(tmp_path, "x = 1  # securelint: ignore[SL101]\n"))["tool"][
        "driver"
    ]["rules"]

    assert rules[0]["id"] == "SL001"
    assert rules[0]["shortDescription"]["text"] == "Comment that silences nothing"
    assert rules[0]["properties"]["security-severity"] == "2.0"


@pytest.mark.parametrize(
    ("severity", "score"),
    [
        (Severity.CRITICAL, "9.5"),
        (Severity.HIGH, "8.0"),
        (Severity.MEDIUM, "5.5"),
        (Severity.LOW, "2.0"),
    ],
)
def test_security_severity_falls_in_githubs_bands(
    severity: Severity, score: str
) -> None:
    # GitHub: 9.0 and above is critical, 7.0 to 8.9 high, 4.0 to 6.9 medium,
    # 0.1 to 3.9 low.
    bands = {
        Severity.CRITICAL: (9.0, 10.0),
        Severity.HIGH: (7.0, 8.9),
        Severity.MEDIUM: (4.0, 6.9),
        Severity.LOW: (0.1, 3.9),
    }
    low, high = bands[severity]

    assert low <= float(score) <= high


def test_policy_decides_the_level(tmp_path: Path) -> None:
    result = apply_policy(
        scanned(tmp_path),
        Policy(block_severity=Severity.HIGH, block_confidence=Confidence.HIGH),
    )

    results = run_of(result)["results"]

    assert [(item["ruleId"], item["level"]) for item in results] == [
        ("SL102", "error"),
        ("SL104", "warning"),
    ]


def test_silenced_finding_is_a_suppressed_warning(tmp_path: Path) -> None:
    code = "os.system(command)  # securelint: ignore[SL102] our own setting\n"

    (item,) = run_of(scanned(tmp_path, code))["results"]

    assert item["level"] == "warning"
    assert item["suppressions"] == [
        {"kind": "inSource", "justification": "our own setting"}
    ]


def test_silenced_finding_without_a_reason_has_no_justification(
    tmp_path: Path,
) -> None:
    code = "os.system(command)  # securelint: ignore[SL102]\n"

    (item,) = run_of(scanned(tmp_path, code))["results"]

    assert item["suppressions"] == [{"kind": "inSource"}]


def test_results_are_sorted_by_place_whatever_their_kind(tmp_path: Path) -> None:
    code = (
        'API_KEY = "sk-live-123"\n'
        "os.system(a)  # securelint: ignore[SL102]\n"
        "os.system(b)\n"
    )
    result = apply_policy(scanned(tmp_path, code), Policy(block_severity=Severity.HIGH))

    lines = [
        item["locations"][0]["physicalLocation"]["region"]["startLine"]
        for item in run_of(result)["results"]
    ]

    assert lines == [1, 2, 3]


def test_failures_make_the_run_unsuccessful(tmp_path: Path) -> None:
    failures = (
        ParseFailure("broken.py", "invalid syntax", line=4),
        ParseFailure("locked.py", "cannot read file"),
    )
    result = ScanResult(findings=(), failures=failures, files_scanned=0)

    (invocation,) = run_of(result)["invocations"]

    assert invocation["executionSuccessful"] is False
    notes = invocation["toolExecutionNotifications"]
    assert [note["level"] for note in notes] == ["error", "error"]
    assert notes[0]["message"]["text"] == "cannot scan this file: invalid syntax"
    location = notes[0]["locations"][0]["physicalLocation"]
    assert location["artifactLocation"]["uri"] == "broken.py"
    assert location["region"] == {"startLine": 4, "startColumn": 1}
    # Without a known line, the start of the file.
    assert notes[1]["locations"][0]["physicalLocation"]["region"]["startLine"] == 1


def test_same_scan_gives_the_same_file(tmp_path: Path) -> None:
    assert format_sarif(scanned(tmp_path)) == format_sarif(scanned(tmp_path))


def test_report_uses_only_ascii_characters(tmp_path: Path) -> None:
    write(tmp_path / "café" / "app.py", "eval(données)\n")

    report = format_sarif(scan(tmp_path, ALL_RULES))

    assert report.isascii()
    item = json.loads(report)["runs"][0]["results"][0]
    assert item["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == (
        "café/app.py"
    )


@pytest.fixture
def project(tmp_path: Path) -> Path:
    root = tmp_path / "project"
    (root / ".git").mkdir(parents=True)
    write(root / "src" / "pkg" / "app.py", CODE)
    return root


def sarif_from_command(
    capsys: pytest.CaptureFixture[str], *arguments: str
) -> tuple[int, dict[str, Any]]:
    code = main(["scan", *arguments, "--format", "sarif"])
    document: dict[str, Any] = json.loads(capsys.readouterr().out)
    return code, document


def uris(document: dict[str, Any]) -> list[str]:
    return [
        item["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        for item in document["runs"][0]["results"]
    ]


@pytest.mark.parametrize(
    "scanned_part",
    [".", "src", "src/pkg", "src/pkg/app.py"],
)
def test_paths_are_from_the_top_of_the_project_whatever_is_scanned(
    project: Path, capsys: pytest.CaptureFixture[str], scanned_part: str
) -> None:
    code, document = sarif_from_command(capsys, str(project / scanned_part))

    assert code == 1
    assert uris(document) == ["src/pkg/app.py", "src/pkg/app.py"]


def test_known_findings_are_notes(
    project: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    main(["baseline", str(project)])
    capsys.readouterr()

    code, document = sarif_from_command(capsys, str(project))

    assert code == 0
    results = document["runs"][0]["results"]
    assert [item["level"] for item in results] == ["note", "note"]
    assert all(item["baselineState"] == "unchanged" for item in results)


def test_sarif_format_keeps_the_exit_codes(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    write(tmp_path / "app.py", "print('safe')\n")
    assert sarif_from_command(capsys, str(tmp_path))[0] == 0

    write(tmp_path / "app.py", "eval(x)\n")
    assert sarif_from_command(capsys, str(tmp_path))[0] == 1

    write(tmp_path / "broken.py", "def oops(:\n")
    code, document = sarif_from_command(capsys, str(tmp_path))
    assert code == 2
    assert document["runs"][0]["invocations"][0]["executionSuccessful"] is False
