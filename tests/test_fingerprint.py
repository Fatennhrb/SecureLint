"""Tests for the identity given to each finding."""

import hashlib
import json
import re
from pathlib import Path

from securelint.engine import scan
from securelint.report import format_json
from securelint.rules import ALL_RULES

CORPUS = Path(__file__).parent / "corpus"


def fingerprints(tmp_path: Path, code: str, name: str = "app.py") -> list[str]:
    """Return the fingerprints of the findings in ``code``, in report order."""
    (tmp_path / name).write_text(code, encoding="utf-8", newline="")
    return [
        finding.fingerprint for finding in scan(tmp_path / name, ALL_RULES).findings
    ]


def test_fingerprint_is_sixteen_hexadecimal_characters(tmp_path: Path) -> None:
    (fingerprint,) = fingerprints(tmp_path, "os.system(command)\n")

    assert re.fullmatch(r"[0-9a-f]{16}", fingerprint)


def test_fingerprint_is_the_same_on_every_scan(tmp_path: Path) -> None:
    code = "os.system(command)\neval(text)\n"

    assert fingerprints(tmp_path, code) == fingerprints(tmp_path, code)


def test_fingerprint_is_built_from_rule_path_line_text_and_occurrence(
    tmp_path: Path,
) -> None:
    (fingerprint,) = fingerprints(tmp_path, "def f():\n    os.system(command)\n")

    # Written out here on purpose. If the recipe ever changes, every
    # fingerprint already saved by a project stops matching; this test makes
    # sure such a change is a decision and not an accident.
    recipe = b"\0".join([b"SL102", b"app.py", b"os.system(command)", b"0"])
    assert fingerprint == hashlib.sha256(recipe).hexdigest()[:16]


def test_adding_lines_above_does_not_change_the_fingerprint(tmp_path: Path) -> None:
    before = fingerprints(tmp_path, "os.system(command)\n")
    after = fingerprints(
        tmp_path, "import os\n\n# A new comment.\nos.system(command)\n"
    )

    assert before == after


def test_adding_lines_below_does_not_change_the_fingerprint(tmp_path: Path) -> None:
    before = fingerprints(tmp_path, "os.system(command)\n")
    after = fingerprints(tmp_path, "os.system(command)\nprint('done')\n")

    assert before == after


def test_changing_the_indentation_does_not_change_the_fingerprint(
    tmp_path: Path,
) -> None:
    before = fingerprints(tmp_path, "os.system(command)\n")
    after = fingerprints(tmp_path, "if ready:\n    os.system(command)   \n")

    assert before == after


def test_line_endings_do_not_change_the_fingerprint(tmp_path: Path) -> None:
    unix = fingerprints(tmp_path, "x = 1\nos.system(command)\n")
    windows = fingerprints(tmp_path, "x = 1\r\nos.system(command)\r\n")

    assert unix == windows


def test_editing_the_reported_line_changes_the_fingerprint(tmp_path: Path) -> None:
    before = fingerprints(tmp_path, "os.system(command)\n")
    after = fingerprints(tmp_path, "os.system(other_command)\n")

    assert before != after


def test_two_rules_on_one_line_have_different_fingerprints(tmp_path: Path) -> None:
    first, second = fingerprints(tmp_path, "os.system(eval(text))\n")

    assert first != second


def test_the_same_line_in_two_files_has_different_fingerprints(tmp_path: Path) -> None:
    in_app = fingerprints(tmp_path, "os.system(command)\n", name="app.py")
    in_tool = fingerprints(tmp_path, "os.system(command)\n", name="tool.py")

    assert in_app != in_tool


def test_identical_lines_in_one_file_have_different_fingerprints(
    tmp_path: Path,
) -> None:
    first, second = fingerprints(tmp_path, "os.system(command)\nos.system(command)\n")

    assert first != second


def test_identical_lines_are_numbered_from_the_top(tmp_path: Path) -> None:
    two = fingerprints(tmp_path, "os.system(command)\nos.system(command)\n")
    # A third identical line at the end leaves the first two as they were.
    three = fingerprints(
        tmp_path, "os.system(command)\nx = 1\nos.system(command)\nos.system(command)\n"
    )

    assert three[:2] == two
    assert len(set(three)) == 3


def test_two_identical_calls_on_one_line_have_different_fingerprints(
    tmp_path: Path,
) -> None:
    first, second = fingerprints(tmp_path, "eval(a); eval(a)\n")

    assert first != second


def test_silenced_findings_have_fingerprints_too(tmp_path: Path) -> None:
    code = "os.system(command)  # securelint: ignore[SL102] checked\nos.system(other)\n"
    (tmp_path / "app.py").write_text(code, encoding="utf-8")

    result = scan(tmp_path, ALL_RULES)

    (kept,) = result.findings
    (hidden,) = result.silenced
    assert re.fullmatch(r"[0-9a-f]{16}", kept.fingerprint)
    assert re.fullmatch(r"[0-9a-f]{16}", hidden.finding.fingerprint)
    assert kept.fingerprint != hidden.finding.fingerprint


def test_silencing_one_of_two_identical_lines_keeps_the_others_identity(
    tmp_path: Path,
) -> None:
    # The comment makes the first line's text different, so here the two
    # lines are told apart by their text; the second keeps number 0.
    alone = fingerprints(tmp_path, "x = 1\nos.system(command)\n")
    code = "os.system(command)  # securelint: ignore[SL102]\nos.system(command)\n"

    assert fingerprints(tmp_path, code) == alone


def test_json_report_gives_each_fingerprint(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("os.system(command)\n", encoding="utf-8")
    result = scan(tmp_path, ALL_RULES)

    document = json.loads(format_json(result))

    assert document["findings"][0]["fingerprint"] == result.findings[0].fingerprint
    assert len(document["findings"][0]["fingerprint"]) == 16


def test_every_finding_in_the_corpus_has_its_own_fingerprint() -> None:
    findings = scan(CORPUS, ALL_RULES).findings

    assert len(findings) > 50
    assert all(finding.fingerprint for finding in findings)
    assert len({finding.fingerprint for finding in findings}) == len(findings)


def test_an_invisible_mark_at_the_start_of_the_file_is_not_part_of_line_one(
    tmp_path: Path,
) -> None:
    # Some Windows tools start a file with a byte order mark. Found by a
    # real run: the finding on line 1 changed identity when lines were
    # added above it, because the mark had been counted as code.
    plain = fingerprints(tmp_path, "os.system(command)\n")

    (tmp_path / "app.py").write_bytes(b"\xef\xbb\xbfos.system(command)\n")
    with_mark = [f.fingerprint for f in scan(tmp_path / "app.py", ALL_RULES).findings]

    (tmp_path / "app.py").write_bytes(b"\xef\xbb\xbfimport os\n\nos.system(command)\n")
    moved = [f.fingerprint for f in scan(tmp_path / "app.py", ALL_RULES).findings]

    assert plain == with_mark == moved
