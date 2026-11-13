"""Tests for silencing a finding with a comment on its line."""

import json
from pathlib import Path

import pytest

from securelint.cli import main
from securelint.engine import ScanResult, scan
from securelint.html_report import format_html
from securelint.model import Confidence, Severity
from securelint.report import format_json, format_text
from securelint.rules import ALL_RULES

IGNORE = "# securelint: ignore"


def scan_code(tmp_path: Path, code: str) -> ScanResult:
    (tmp_path / "app.py").write_text(code, encoding="utf-8")
    return scan(tmp_path, ALL_RULES)


def reported(result: ScanResult) -> list[tuple[int, str]]:
    return [(finding.line, finding.rule_id) for finding in result.findings]


def silenced(result: ScanResult) -> list[tuple[int, str, str]]:
    return [
        (item.finding.line, item.finding.rule_id, item.reason)
        for item in result.silenced
    ]


def test_comment_silences_the_finding_on_its_line(tmp_path: Path) -> None:
    code = f"os.system(command)  {IGNORE}[SL102] command is our own setting\n"

    result = scan_code(tmp_path, code)

    assert reported(result) == []
    assert silenced(result) == [(1, "SL102", "command is our own setting")]


def test_the_silenced_finding_is_kept_whole(tmp_path: Path) -> None:
    result = scan_code(tmp_path, f"os.system(command)  {IGNORE}[SL102]\n")

    (item,) = result.silenced
    assert item.finding.path == "app.py"
    assert (item.finding.line, item.finding.column) == (1, 1)
    assert item.finding.severity is Severity.HIGH
    assert item.finding.message.startswith("os.system() runs its command")
    assert item.reason == ""


@pytest.mark.parametrize(
    "comment",
    [
        "# securelint: ignore[SL102]",
        "#securelint:ignore[SL102]",
        "#   securelint:   ignore[SL102]   ",
        "# securelint: ignore[ SL102 ]",
        "# securelint: ignore[SL102]: checked",
        "# securelint: ignore[SL102] - checked",
        # After another tool's comment.
        "# noqa: S605  # securelint: ignore[SL102]",
    ],
)
def test_ways_of_writing_the_comment(tmp_path: Path, comment: str) -> None:
    result = scan_code(tmp_path, f"os.system(command)  {comment}\n")

    assert reported(result) == []
    assert len(result.silenced) == 1


@pytest.mark.parametrize(
    ("comment", "reason"),
    [
        ("# securelint: ignore[SL102] checked by the team", "checked by the team"),
        ("# securelint: ignore[SL102]: checked", "checked"),
        ("# securelint: ignore[SL102] - checked", "checked"),
        ("# securelint: ignore[SL102]", ""),
    ],
)
def test_the_reason_is_the_text_after_the_brackets(
    tmp_path: Path, comment: str, reason: str
) -> None:
    result = scan_code(tmp_path, f"os.system(command)  {comment}\n")

    assert silenced(result) == [(1, "SL102", reason)]


def test_only_the_named_rule_is_silenced(tmp_path: Path) -> None:
    # Two different problems on one line; the comment names one of them.
    code = f"os.system(eval(text))  {IGNORE}[SL102]\n"

    result = scan_code(tmp_path, code)

    assert reported(result) == [(1, "SL101")]
    assert silenced(result) == [(1, "SL102", "")]


def test_several_rules_can_be_named(tmp_path: Path) -> None:
    code = f"os.system(eval(text))  {IGNORE}[SL101, SL102] both checked\n"

    result = scan_code(tmp_path, code)

    assert reported(result) == []
    assert silenced(result) == [
        (1, "SL102", "both checked"),
        (1, "SL101", "both checked"),
    ]


def test_only_the_line_with_the_comment_is_silenced(tmp_path: Path) -> None:
    code = f"os.system(first)\nos.system(second)  {IGNORE}[SL102]\nos.system(third)\n"

    result = scan_code(tmp_path, code)

    assert reported(result) == [(1, "SL102"), (3, "SL102")]
    assert silenced(result) == [(2, "SL102", "")]


def test_a_call_on_several_lines_is_silenced_on_its_first_line(tmp_path: Path) -> None:
    code = (
        f"subprocess.run(  {IGNORE}[SL102] checked\n"
        '    "git clone " + url,\n'
        "    shell=True,\n"
        ")\n"
    )

    assert reported(scan_code(tmp_path, code)) == []


def test_a_comment_on_another_line_of_the_call_silences_nothing(tmp_path: Path) -> None:
    code = (
        "subprocess.run(\n"
        '    "git clone " + url,\n'
        f"    shell=True,  {IGNORE}[SL102]\n"
        ")\n"
    )

    # The problem is still reported, and so is the comment that missed it.
    assert reported(scan_code(tmp_path, code)) == [(1, "SL102"), (3, "SL001")]


def test_the_same_text_inside_a_string_is_not_a_comment(tmp_path: Path) -> None:
    code = (
        'note = "# securelint: ignore[SL102]"; os.system(command)\n'
        'help_text = """\n'
        "    # securelint: ignore[SL101]\n"
        '"""\n'
    )

    result = scan_code(tmp_path, code)

    assert reported(result) == [(1, "SL102")]
    assert result.silenced == ()


def test_a_comment_that_silences_nothing_is_reported(tmp_path: Path) -> None:
    result = scan_code(tmp_path, f"print(value)  {IGNORE}[SL102] left behind\n")

    (finding,) = result.findings
    assert finding.rule_id == "SL001"
    assert (finding.line, finding.column) == (1, 15)
    assert finding.severity is Severity.LOW
    assert finding.confidence is Confidence.HIGH
    assert finding.message == (
        "This comment silences SL102, but SL102 reports nothing on this line; "
        "remove it."
    )


def test_a_comment_naming_the_wrong_rule_is_reported(tmp_path: Path) -> None:
    code = f"os.system(command)  {IGNORE}[SL101]\n"

    result = scan_code(tmp_path, code)

    # The real problem stays, and the comment is flagged.
    assert reported(result) == [(1, "SL102"), (1, "SL001")]
    assert result.silenced == ()


def test_one_used_rule_and_one_unused_rule_in_the_same_comment(tmp_path: Path) -> None:
    code = f"os.system(command)  {IGNORE}[SL102, SL105]\n"

    result = scan_code(tmp_path, code)

    assert silenced(result) == [(1, "SL102", "")]
    (finding,) = result.findings
    assert finding.rule_id == "SL001"
    assert "SL105 reports nothing on this line" in finding.message


def test_a_rule_that_does_not_exist_is_reported(tmp_path: Path) -> None:
    result = scan_code(tmp_path, f"os.system(command)  {IGNORE}[SL999]\n")

    assert reported(result) == [(1, "SL102"), (1, "SL001")]
    assert result.findings[-1].message == (
        "This comment silences SL999, which does not exist or is turned off; remove it."
    )


@pytest.mark.parametrize(
    "comment",
    [
        # No rule named: silencing everything is not allowed.
        "# securelint: ignore",
        "# securelint: ignore[]",
        "# securelint: ignore-all",
        # Mistakes.
        "# securelint: ignroe[SL102]",
        "# securelint: ignore SL102",
        "# securelint: ignore(SL102)",
        "# securelint: ignore[SL102",
        "# securelint: ignore[sl102]",
        "# securelint: ignore[SL102 SL101]",
        "# securelint: ignore[SL102,]",
        "# securelint:",
    ],
)
def test_a_comment_that_is_not_understood_silences_nothing(
    tmp_path: Path, comment: str
) -> None:
    result = scan_code(tmp_path, f"os.system(command)  {comment}\n")

    assert reported(result) == [(1, "SL102"), (1, "SL001")]
    assert result.silenced == ()
    assert result.findings[-1].message.startswith("This comment is not understood")


def test_the_comment_finding_cannot_silence_itself(tmp_path: Path) -> None:
    result = scan_code(tmp_path, f"print(value)  {IGNORE}[SL001, SL102]\n")

    assert [rule_id for _, rule_id in reported(result)] == ["SL001", "SL001"]


def test_other_comments_are_left_alone(tmp_path: Path) -> None:
    code = (
        "# A normal comment about securelint.\n"
        "os.system(command)  # noqa: S605\n"
        "x = 1  # type: ignore[assignment]\n"
    )

    result = scan_code(tmp_path, code)

    assert reported(result) == [(2, "SL102")]
    assert result.silenced == ()


def test_a_rule_that_is_not_running_counts_as_turned_off(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        f"os.system(command)  {IGNORE}[SL102]\n", encoding="utf-8"
    )
    without_shell_rule = [rule for rule in ALL_RULES if rule.rule_id != "SL102"]

    result = scan(tmp_path, without_shell_rule)

    assert reported(result) == [(1, "SL001")]
    assert "does not exist or is turned off" in result.findings[0].message


def test_silenced_findings_are_sorted_across_files(tmp_path: Path) -> None:
    (tmp_path / "b.py").write_text(f"eval(x)  {IGNORE}[SL101]\n", encoding="utf-8")
    (tmp_path / "a.py").write_text(
        f"x = 1\neval(y)  {IGNORE}[SL101]\neval(z)  {IGNORE}[SL101]\n",
        encoding="utf-8",
    )

    result = scan(tmp_path, ALL_RULES)

    assert [(item.finding.path, item.finding.line) for item in result.silenced] == [
        ("a.py", 2),
        ("a.py", 3),
        ("b.py", 1),
    ]


def test_text_report_counts_the_silenced_findings(tmp_path: Path) -> None:
    clean = scan_code(tmp_path, f"eval(x)  {IGNORE}[SL101]\n")
    assert format_text(clean) == (
        "No problems found in 1 file. Silenced by a comment: 1."
    )

    mixed = scan_code(tmp_path, f"eval(x)  {IGNORE}[SL101]\nos.system(command)\n")
    assert format_text(mixed).splitlines()[-1] == (
        "1 problem found in 1 file (1 high). Silenced by a comment: 1."
    )


def test_json_report_lists_the_silenced_findings(tmp_path: Path) -> None:
    result = scan_code(tmp_path, f"eval(x)  {IGNORE}[SL101] checked\n")

    document = json.loads(format_json(result))

    assert document["summary"]["findings"] == 0
    assert document["summary"]["silenced"] == 1
    assert document["findings"] == []
    (item,) = document["silenced"]
    assert item["rule_id"] == "SL101"
    assert (item["path"], item["line"], item["column"]) == ("app.py", 1, 1)
    assert item["reason"] == "checked"


def test_html_report_lists_the_silenced_findings(tmp_path: Path) -> None:
    code = (
        f"eval(x)  {IGNORE}[SL101] <b>checked</b>\n"
        f"os.system(command)  {IGNORE}[SL102]\n"
    )

    page = format_html(scan_code(tmp_path, code))

    assert "Silenced by a comment: 2." in page
    assert "<h2>Silenced by a comment</h2>" in page
    assert "app.py:1 SL101</span> &lt;b&gt;checked&lt;/b&gt;" in page
    assert "app.py:2 SL102</span> No reason given." in page
    # The reason comes from the scanned code, so it is escaped like the rest.
    assert "<b>checked</b>" not in page


def test_html_report_has_no_silenced_section_without_silenced_findings(
    tmp_path: Path,
) -> None:
    page = format_html(scan_code(tmp_path, "eval(x)\n"))

    assert "Silenced by a comment" not in page


def test_scan_with_everything_silenced_exits_0(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    (tmp_path / "app.py").write_text(
        f"eval(x)  {IGNORE}[SL101] checked\n", encoding="utf-8"
    )

    assert main(["scan", str(tmp_path)]) == 0
    assert capsys.readouterr().out == (
        "No problems found in 1 file. Silenced by a comment: 1.\n"
    )


def test_scan_with_a_useless_comment_exits_1(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    (tmp_path / "app.py").write_text(f"x = 1  {IGNORE}[SL101]\n", encoding="utf-8")

    assert main(["scan", str(tmp_path)]) == 1
    assert "app.py:1:8  low       SL001" in capsys.readouterr().out
