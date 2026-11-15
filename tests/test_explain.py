"""Tests for explanations: they are added after the decision and change nothing.

No test here talks to an AI. A fake explainer stands in for one.
"""

import json
from dataclasses import replace
from pathlib import Path

import pytest

from securelint import cli
from securelint.cli import main
from securelint.config import Config
from securelint.engine import ScanResult
from securelint.explain import Explainer, add_explanations
from securelint.model import Confidence, Finding, Severity
from securelint.prompt import Prompt

# Line 1: SL102 (high). Line 2: SL104 (medium).
CODE = 'os.system("ping " + input())\nDB_PASSWORD = "hunter2"\n'


class FakeExplainer:
    """Answers like a real AI, in the JSON format the prompt asks for, and
    remembers what it was asked. ``{rule}`` in the explanation becomes the
    rule asked about."""

    def __init__(self, explanation: str = "Because {rule}.", fail_on: str = "") -> None:
        self.explanation = explanation
        self.fail_on = fail_on
        self.asked: list[Prompt] = []

    def explain(self, prompt: Prompt) -> str:
        self.asked.append(prompt)
        rule = prompt.user.splitlines()[0].removeprefix("Rule: ")
        if rule == self.fail_on:
            raise TimeoutError("the AI took too long")
        return json.dumps({"explanation": self.explanation.replace("{rule}", rule)})


def no_lines(path: str) -> tuple[str, ...]:
    return ()


def rules_asked(explainer: FakeExplainer) -> list[str]:
    return [prompt.user.splitlines()[0] for prompt in explainer.asked]


def finding(rule_id: str = "T001", line: int = 1) -> Finding:
    return Finding(
        rule_id=rule_id,
        message="Example problem.",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        path="app.py",
        line=line,
        column=1,
    )


def test_blocking_findings_are_explained_before_warnings() -> None:
    result = ScanResult(
        findings=(finding("T001"),),
        failures=(),
        files_scanned=1,
        warnings=(finding("T002", line=2),),
        known=(finding("T003", line=3),),
    )
    explainer = FakeExplainer()

    explained, problems = add_explanations(result, explainer, no_lines)

    # Known findings are not shown, so they are not explained either.
    assert rules_asked(explainer) == ["Rule: T001", "Rule: T002"]
    assert explained.explanations == (
        (finding("T001"), "Because T001."),
        (finding("T002", line=2), "Because T002."),
    )
    assert problems == []
    # Everything else is exactly as it was.
    assert replace(explained, explanations=()) == result


def test_only_the_first_findings_are_explained() -> None:
    findings = tuple(finding(line=line) for line in range(1, 6))
    result = ScanResult(findings=findings, failures=(), files_scanned=1)
    explainer = FakeExplainer()

    explained, problems = add_explanations(result, explainer, no_lines, limit=3)

    assert len(explainer.asked) == 3
    assert len(explained.explanations) == 3
    assert problems == [
        "explained the first 3 of 5 findings; the others have no explanation"
    ]


def test_a_failure_costs_only_its_own_explanation() -> None:
    result = ScanResult(
        findings=(finding("T001"), finding("T002", line=2)),
        failures=(),
        files_scanned=1,
    )

    explained, problems = add_explanations(
        result, FakeExplainer(fail_on="T001"), no_lines
    )

    assert [item.rule_id for item, _ in explained.explanations] == ["T002"]
    assert problems == ["cannot explain T001 at app.py:1: the AI took too long"]


def test_answers_are_one_line_and_empty_ones_are_dropped() -> None:
    result = ScanResult(findings=(finding(),), failures=(), files_scanned=1)

    spread, _ = add_explanations(
        result, FakeExplainer("First.\n\n  Second.\t"), no_lines
    )
    empty, _ = add_explanations(result, FakeExplainer(" \n "), no_lines)

    assert spread.explanations == ((finding(), "First. Second."),)
    assert empty.explanations == ()


# The command line, with the fake in place of the project's AI provider.


@pytest.fixture
def project(tmp_path: Path) -> Path:
    (tmp_path / "app.py").write_text(CODE, encoding="utf-8")
    return tmp_path


def use(monkeypatch: pytest.MonkeyPatch, explainer: Explainer | None) -> None:
    def make(config: Config) -> Explainer | None:
        return explainer

    monkeypatch.setattr(cli, "make_explainer", make)


def test_the_text_report_shows_each_explanation_under_its_finding(
    project: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    use(monkeypatch, FakeExplainer())

    assert main(["scan", str(project), "--explain"]) == 1

    lines = capsys.readouterr().out.splitlines()
    assert lines[0].startswith("app.py:1:1  high      SL102")
    assert lines[1] == "    AI explanation (may be wrong): Because SL102."
    assert lines[2].startswith("app.py:2:1  medium    SL104")
    assert lines[3] == "    AI explanation (may be wrong): Because SL104."


def test_the_json_report_has_an_explanation_field(
    project: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    use(monkeypatch, FakeExplainer(fail_on="SL104"))

    main(["scan", str(project), "--explain", "--format", "json"])

    findings = json.loads(capsys.readouterr().out)["findings"]
    assert [item["explanation"] for item in findings] == ["Because SL102.", None]


@pytest.mark.parametrize(
    "explainer",
    [FakeExplainer(), FakeExplainer(fail_on="SL102"), FakeExplainer("")],
    ids=["answers", "fails", "says nothing"],
)
@pytest.mark.parametrize("code", [CODE, "print('safe')\n"], ids=["problems", "clean"])
def test_explanations_never_change_the_exit_code(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    explainer: FakeExplainer,
    code: str,
) -> None:
    (tmp_path / "app.py").write_text(code, encoding="utf-8")
    without = main(["scan", str(tmp_path)])
    use(monkeypatch, explainer)

    assert main(["scan", str(tmp_path), "--explain"]) == without


def test_the_policy_decides_before_any_explanation(
    project: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    (project / "pyproject.toml").write_text(
        '[tool.securelint.policy]\nblock-severity = "critical"\n', encoding="utf-8"
    )
    use(monkeypatch, FakeExplainer("This is critical, block the merge!"))

    # Nothing is critical: both findings are warnings, whatever the AI says.
    assert main(["scan", str(project), "--explain"]) == 0
    assert "No blocking problems found" in capsys.readouterr().out


def test_a_failed_explanation_is_said_on_standard_error(
    project: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    use(monkeypatch, FakeExplainer(fail_on="SL102"))

    main(["scan", str(project), "--explain"])

    captured = capsys.readouterr()
    assert "cannot explain SL102 at app.py:1: the AI took too long" in captured.err
    assert "AI explanation (may be wrong): Because SL104." in captured.out


def test_without_a_provider_the_scan_goes_on(
    project: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    use(monkeypatch, None)

    assert main(["scan", str(project), "--explain"]) == 1

    captured = capsys.readouterr()
    assert "no explanations were added" in captured.err
    assert "AI explanation" not in captured.out


def test_without_the_option_nothing_is_asked(
    project: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    explainer = FakeExplainer()
    use(monkeypatch, explainer)

    main(["scan", str(project)])

    assert explainer.asked == []
    assert "AI explanation" not in capsys.readouterr().out


def test_no_provider_can_be_set_up_yet() -> None:
    assert cli.make_explainer(Config()) is None
