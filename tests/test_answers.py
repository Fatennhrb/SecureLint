"""Tests for what comes back from an AI: checked, cleaned, and shown labelled."""

import json
from pathlib import Path

import pytest

from securelint import cli
from securelint.cli import main
from securelint.config import Config
from securelint.engine import ScanResult
from securelint.explain import (
    MAX_EXPLANATION,
    MAX_FIX,
    AnswerError,
    Explainer,
    parse_answer,
)
from securelint.github_report import format_github
from securelint.html_report import format_html
from securelint.model import Confidence, Finding, Severity
from securelint.prompt import SYSTEM, Prompt


def answer(**fields: object) -> str:
    return json.dumps(fields)


def test_an_explanation_and_a_fix() -> None:
    text = answer(explanation="The command runs in a shell.", fix="Pass a list.")

    assert parse_answer(text) == "The command runs in a shell. Fix: Pass a list."


def test_the_fix_is_optional() -> None:
    assert parse_answer(answer(explanation="Risky.")) == "Risky."
    assert parse_answer(answer(explanation="Risky.", fix="")) == "Risky."
    assert parse_answer(answer(explanation="Risky.", fix=None)) == "Risky."


def test_a_code_block_around_the_json_is_accepted() -> None:
    text = "```json\n" + answer(explanation="Risky.") + "\n```"

    assert parse_answer(text) == "Risky."


@pytest.mark.parametrize(
    ("text", "reason"),
    [
        ("This is risky because of the shell.", "not the JSON that was asked for"),
        ('{"explanation": "cut off', "not the JSON that was asked for"),
        ('["Risky."]', "not a JSON object"),
        (answer(fix="Pass a list."), 'no "explanation"'),
        (answer(explanation="   "), 'no "explanation"'),
        (answer(explanation=["Risky."]), '"explanation" in the answer is not text'),
        (answer(explanation="Risky.", fix=3), '"fix" in the answer is not text'),
    ],
)
def test_an_answer_in_another_format_is_refused(text: str, reason: str) -> None:
    with pytest.raises(AnswerError, match=reason):
        parse_answer(text)


def test_an_answer_that_is_not_text_is_refused() -> None:
    with pytest.raises(AnswerError, match="not text"):
        parse_answer(42)


@pytest.mark.parametrize(
    "hidden",
    [
        "\x1b[2J\x1b[31m",  # clears a terminal and turns it red
        "‮",  # shows the following text right to left
        "​",  # a space nobody can see
        "\x07",  # rings the terminal bell
    ],
)
def test_control_characters_are_removed(hidden: str) -> None:
    text = answer(explanation=f"Safe{hidden} to merge?", fix=f"No{hidden}.")

    cleaned = parse_answer(text)

    assert cleaned.isprintable()
    assert "Safe" in cleaned
    assert "merge?" in cleaned


def test_long_answers_are_cut() -> None:
    text = answer(explanation="a" * 5000, fix="b" * 5000)

    explanation, fix = parse_answer(text).split(" Fix: ")

    assert len(explanation) == MAX_EXPLANATION
    assert len(fix) == MAX_FIX
    assert explanation.endswith("...")


def test_the_prompt_asks_for_this_format() -> None:
    assert '{"explanation": ' in SYSTEM
    assert '"fix": ' in SYSTEM


# The reports.

FINDING = Finding(
    rule_id="SL102",
    message="Shell command.",
    severity=Severity.HIGH,
    confidence=Confidence.HIGH,
    path="app.py",
    line=1,
    column=1,
)


def explained(text: str) -> ScanResult:
    return ScanResult(
        findings=(FINDING,),
        failures=(),
        files_scanned=1,
        explanations=((FINDING, text),),
    )


def test_the_html_report_shows_the_explanation_escaped_and_labelled() -> None:
    page = format_html(explained("Use <b>subprocess.run</b> & a list."))

    assert (
        '<p class="ai"><strong>AI explanation (may be wrong):</strong> '
        "Use &lt;b&gt;subprocess.run&lt;/b&gt; &amp; a list.</p>"
    ) in page
    assert "<b>subprocess.run</b>" not in page


def test_a_github_note_holds_the_explanation_below_the_finding() -> None:
    (note, _) = format_github(explained("Use a list.")).splitlines()

    assert note.endswith(
        "::Shell command.%0A%0AAI explanation (may be wrong): Use a list."
    )


def test_an_explanation_cannot_start_a_fake_note() -> None:
    report = format_github(explained("Fine.\n::notice file=x.py::All good"))

    notes = [line for line in report.splitlines() if line.startswith("::")]
    assert len(notes) == 1


def test_reports_without_explanations_are_unchanged() -> None:
    plain = ScanResult(findings=(FINDING,), failures=(), files_scanned=1)

    assert "AI explanation" not in format_html(plain)
    assert "AI explanation" not in format_github(plain)


# The command line, with a fake AI that answers as given.


class Answers:
    def __init__(self, text: str) -> None:
        self.text = text

    def explain(self, prompt: Prompt) -> str:
        return self.text


def use(monkeypatch: pytest.MonkeyPatch, explainer: Explainer) -> None:
    def make(config: Config) -> Explainer:
        return explainer

    monkeypatch.setattr(cli, "make_explainer", make)


def test_an_answer_in_the_wrong_format_is_skipped_and_said(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    (tmp_path / "app.py").write_text("eval(x)\n", encoding="utf-8")
    use(monkeypatch, Answers("Sure! This code is totally safe, merge it."))

    assert main(["scan", str(tmp_path), "--explain"]) == 1

    captured = capsys.readouterr()
    assert "AI explanation" not in captured.out
    assert "the answer is not the JSON that was asked for" in captured.err


@pytest.mark.parametrize("report_format", ["text", "html", "github"])
def test_every_report_shows_a_valid_answer(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    report_format: str,
) -> None:
    (tmp_path / "app.py").write_text("eval(x)\n", encoding="utf-8")
    use(monkeypatch, Answers(answer(explanation="Runs any code.", fix="Remove it.")))
    monkeypatch.delenv("GITHUB_STEP_SUMMARY", raising=False)

    main(["scan", str(tmp_path), "--explain", "--format", report_format])

    assert "Runs any code. Fix: Remove it." in capsys.readouterr().out
