"""Tests for the scan engine, using small fake rules."""

import ast
from collections.abc import Iterable
from pathlib import Path

import pytest

from securelint.engine import Rule, scan
from securelint.model import Confidence, Finding, Severity


def make_finding(rule_id: str, node: ast.expr | ast.stmt, path: str) -> Finding:
    return Finding(
        rule_id=rule_id,
        message=f"{rule_id} matched",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        path=path,
        line=node.lineno,
        column=node.col_offset + 1,
    )


class EvalRule(Rule):
    """Reports every call to a function named ``eval``."""

    node_types = (ast.Call,)

    def __init__(self) -> None:
        self.seen: list[ast.AST] = []

    def check(self, node: ast.AST, path: str) -> Iterable[Finding]:
        self.seen.append(node)
        assert isinstance(node, ast.Call)
        if isinstance(node.func, ast.Name) and node.func.id == "eval":
            yield make_finding("T001", node, path)


class AssertRule(Rule):
    """Reports every ``assert`` statement."""

    node_types = (ast.Assert,)

    def check(self, node: ast.AST, path: str) -> Iterable[Finding]:
        assert isinstance(node, ast.Assert)
        yield make_finding("T002", node, path)


def write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def locations(findings: Iterable[Finding]) -> list[tuple[str, int, int, str]]:
    return [(f.path, f.line, f.column, f.rule_id) for f in findings]


def test_reports_a_finding_with_its_location(tmp_path: Path) -> None:
    write(tmp_path / "app.py", "x = 1\nresult = eval(data)\n")

    result = scan(tmp_path, [EvalRule()])

    assert locations(result.findings) == [("app.py", 2, 10, "T001")]
    assert result.files_scanned == 1
    assert result.failures == ()


def test_clean_code_gives_no_findings(tmp_path: Path) -> None:
    write(tmp_path / "app.py", "print(len('safe'))\n")

    result = scan(tmp_path, [EvalRule(), AssertRule()])

    assert result.findings == ()
    assert result.files_scanned == 1


def test_no_rules_gives_no_findings(tmp_path: Path) -> None:
    write(tmp_path / "app.py", "eval(data)\n")

    result = scan(tmp_path, [])

    assert result.findings == ()
    assert result.files_scanned == 1


def test_findings_are_sorted_across_files_and_rules(tmp_path: Path) -> None:
    write(tmp_path / "b.py", "eval(x)\n")
    write(tmp_path / "a.py", "assert ok\neval(x); eval(y)\nassert eval(z)\n")

    result = scan(tmp_path, [EvalRule(), AssertRule()])

    assert locations(result.findings) == [
        ("a.py", 1, 1, "T002"),
        ("a.py", 2, 1, "T001"),
        ("a.py", 2, 10, "T001"),
        ("a.py", 3, 1, "T002"),
        ("a.py", 3, 8, "T001"),
        ("b.py", 1, 1, "T001"),
    ]


def test_finds_code_nested_inside_functions_and_classes(tmp_path: Path) -> None:
    code = "class A:\n    def run(self):\n        return [eval(x) for x in data]\n"
    write(tmp_path / "app.py", code)

    result = scan(tmp_path, [EvalRule()])

    assert locations(result.findings) == [("app.py", 3, 17, "T001")]


def test_a_rule_only_sees_the_node_types_it_asked_for(tmp_path: Path) -> None:
    write(tmp_path / "app.py", "import os\nx = 1\nassert x\nprint(x)\n")
    rule = EvalRule()

    scan(tmp_path, [rule])

    assert len(rule.seen) == 1
    assert isinstance(rule.seen[0], ast.Call)


def test_each_node_is_checked_exactly_once(tmp_path: Path) -> None:
    write(tmp_path / "app.py", "eval(a)\neval(eval(b))\n")
    rule = EvalRule()

    scan(tmp_path, [rule, AssertRule()])

    assert len(rule.seen) == 3
    assert len({id(node) for node in rule.seen}) == 3


def test_tree_is_walked_once_per_file_whatever_the_number_of_rules(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    write(tmp_path / "a.py", "eval(x)\n")
    write(tmp_path / "b.py", "assert y\n")
    walks = 0
    real_walk = ast.walk

    def counting_walk(node: ast.AST) -> Iterable[ast.AST]:
        nonlocal walks
        walks += 1
        return real_walk(node)

    monkeypatch.setattr(ast, "walk", counting_walk)

    scan(tmp_path, [EvalRule(), AssertRule(), EvalRule()])

    assert walks == 2


def test_broken_file_is_reported_and_the_scan_continues(tmp_path: Path) -> None:
    write(tmp_path / "broken.py", "def oops(:\n")
    write(tmp_path / "good.py", "eval(x)\n")

    result = scan(tmp_path, [EvalRule()])

    assert locations(result.findings) == [("good.py", 1, 1, "T001")]
    assert [failure.relative_path for failure in result.failures] == ["broken.py"]
    assert result.files_scanned == 1


def test_single_file_target(tmp_path: Path) -> None:
    write(tmp_path / "pkg" / "app.py", "eval(x)\n")

    result = scan(tmp_path / "pkg" / "app.py", [EvalRule()])

    assert locations(result.findings) == [("app.py", 1, 1, "T001")]


def test_empty_directory(tmp_path: Path) -> None:
    result = scan(tmp_path, [EvalRule()])

    assert (result.findings, result.failures, result.files_scanned) == ((), (), 0)


def test_missing_target_is_an_error(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        scan(tmp_path / "does-not-exist", [EvalRule()])
