"""Tests for `securelint explain FILE --line N`: one line, explained.

No test here talks to an AI. A fake explainer stands in for one.
"""

import json
from pathlib import Path

import pytest

from securelint import cli
from securelint.cli import main
from securelint.config import Config
from securelint.explain import Explainer
from securelint.prompt import Prompt

# Line 2: SL102 (high). Line 3: SL104 (medium). Line 1: nothing.
CODE = 'import os\nos.system("ping " + input())\nDB_PASSWORD = "hunter2"\n'


class FakeExplainer:
    """Answers in the JSON format the prompt asks for, and remembers the
    rules it was asked about."""

    def __init__(self, fail: bool = False) -> None:
        self.fail = fail
        self.rules: list[str] = []

    def explain(self, prompt: Prompt) -> str:
        rule = prompt.user.splitlines()[0].removeprefix("Rule: ")
        self.rules.append(rule)
        if self.fail:
            raise TimeoutError("the AI took too long")
        return json.dumps({"explanation": f"Because {rule}."})


@pytest.fixture
def app(tmp_path: Path) -> Path:
    path = tmp_path / "app.py"
    path.write_text(CODE, encoding="utf-8")
    return path


def use(monkeypatch: pytest.MonkeyPatch, explainer: Explainer | None) -> None:
    def make(config: Config) -> Explainer | None:
        return explainer

    monkeypatch.setattr(cli, "make_explainer", make)


def test_the_finding_on_the_line_is_explained(
    app: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    explainer = FakeExplainer()
    use(monkeypatch, explainer)

    assert main(["explain", str(app), "--line", "2"]) == 0

    lines = capsys.readouterr().out.splitlines()
    assert lines[0].startswith("app.py:2:1  high      SL102")
    assert lines[1] == "    AI explanation (may be wrong): Because SL102."
    assert explainer.rules == ["SL102"]


def test_the_json_report_holds_only_the_line(
    app: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    use(monkeypatch, FakeExplainer())

    assert main(["explain", str(app), "--line", "3", "--format", "json"]) == 0

    report = json.loads(capsys.readouterr().out)
    assert report["format_version"] == 1
    assert [(item["rule_id"], item["line"]) for item in report["findings"]] == [
        ("SL104", 3)
    ]
    assert report["findings"][0]["explanation"] == "Because SL104."
    assert report["summary"]["findings"] == 1


def test_a_line_without_findings_asks_nothing(
    app: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    explainer = FakeExplainer()
    use(monkeypatch, explainer)

    assert main(["explain", str(app), "--line", "1"]) == 0

    assert explainer.rules == []
    assert "nothing to explain: no finding on line 1" in capsys.readouterr().err


def test_a_line_past_the_end_asks_nothing(
    app: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    explainer = FakeExplainer()
    use(monkeypatch, explainer)

    assert main(["explain", str(app), "--line", "999"]) == 0
    assert explainer.rules == []


def test_without_a_provider_it_fails(
    app: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    use(monkeypatch, None)

    assert main(["explain", str(app), "--line", "2"]) == 2

    err = capsys.readouterr().err
    assert "no AI provider is set up" in err
    assert "1 finding was not explained" in err


def test_a_failed_explanation_fails_the_command(
    app: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    use(monkeypatch, FakeExplainer(fail=True))

    assert main(["explain", str(app), "--line", "2"]) == 2

    err = capsys.readouterr().err
    assert "cannot explain SL102 at app.py:2: the AI took too long" in err


def test_a_policy_warning_is_explained_too(
    app: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    (app.parent / "pyproject.toml").write_text(
        '[tool.securelint.policy]\nblock-severity = "critical"\n', encoding="utf-8"
    )
    explainer = FakeExplainer()
    use(monkeypatch, explainer)

    assert main(["explain", str(app), "--line", "2", "--format", "json"]) == 0

    report = json.loads(capsys.readouterr().out)
    assert report["findings"] == []
    assert report["warnings"][0]["explanation"] == "Because SL102."


def test_a_known_finding_is_not_explained(
    app: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    (app.parent / "pyproject.toml").write_text("", encoding="utf-8")
    assert main(["baseline", str(app.parent)]) == 0
    explainer = FakeExplainer()
    use(monkeypatch, explainer)

    assert main(["explain", str(app), "--line", "2"]) == 0
    assert explainer.rules == []


def test_a_silenced_finding_is_not_explained(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    app = tmp_path / "app.py"
    app.write_text(
        'import os\nos.system("ping " + input())'
        "  # securelint: ignore[SL102] only our own team runs this\n",
        encoding="utf-8",
    )
    explainer = FakeExplainer()
    use(monkeypatch, explainer)

    assert main(["explain", str(app), "--line", "2"]) == 0
    assert explainer.rules == []


def test_a_file_that_cannot_be_scanned_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    app = tmp_path / "app.py"
    app.write_text("def broken(:\n", encoding="utf-8")
    explainer = FakeExplainer()
    use(monkeypatch, explainer)

    assert main(["explain", str(app), "--line", "1"]) == 2
    assert "cannot scan app.py:1" in capsys.readouterr().err
    assert explainer.rules == []


@pytest.mark.parametrize("name", ["missing.py", "."], ids=["missing", "a folder"])
def test_only_an_existing_file_is_accepted(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    name: str,
) -> None:
    use(monkeypatch, FakeExplainer())

    assert main(["explain", str(tmp_path / name), "--line", "1"]) == 2
    assert "error: not a file" in capsys.readouterr().err


@pytest.mark.parametrize("line", ["0", "-1", "two", "1.5"])
def test_the_line_must_be_a_number_from_1(app: Path, line: str) -> None:
    with pytest.raises(SystemExit) as stopped:
        main(["explain", str(app), "--line", line])
    assert stopped.value.code == 2


def test_the_line_is_required(app: Path) -> None:
    with pytest.raises(SystemExit) as stopped:
        main(["explain", str(app)])
    assert stopped.value.code == 2
