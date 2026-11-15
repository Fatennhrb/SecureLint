"""Tests for the explanation cache: the same question is not paid for twice."""

import json
from pathlib import Path

import pytest

from securelint import cli
from securelint.cache import CACHE_FOLDER, MAX_ENTRIES, ExplanationCache
from securelint.cli import main
from securelint.config import Config
from securelint.explain import Explainer
from securelint.prompt import Prompt

ANSWER = json.dumps({"explanation": "eval runs any code."})


def prompt(user: str = "Rule: SL101") -> Prompt:
    return Prompt(system="Explain.", user=user)


def test_an_explanation_is_found_again_after_saving(tmp_path: Path) -> None:
    cache = ExplanationCache(tmp_path, "anthropic\0claude-opus-5-5")
    cache.put(prompt(), "Risky.")
    assert cache.save() is None

    reopened = ExplanationCache(tmp_path, "anthropic\0claude-opus-5-5")

    assert reopened.get(prompt()) == "Risky."
    assert reopened.hits == 1
    assert reopened.get(prompt("Rule: SL102")) is None


def test_another_model_does_not_share_explanations(tmp_path: Path) -> None:
    cache = ExplanationCache(tmp_path, "anthropic\0claude-opus-5-5")
    cache.put(prompt(), "Risky.")
    cache.save()

    other = ExplanationCache(tmp_path, "anthropic\0claude-haiku-5-5")

    assert other.get(prompt()) is None


def test_the_cache_holds_no_code_and_is_never_committed(tmp_path: Path) -> None:
    cache = ExplanationCache(tmp_path, "scope")
    cache.put(prompt("<code>\n> 1 | eval(user_input)\n</code>"), "Risky.")
    cache.save()

    saved = (tmp_path / "explanations.json").read_text(encoding="utf-8")
    assert "eval(user_input)" not in saved
    assert "Risky." in saved
    assert (tmp_path / ".gitignore").read_text(encoding="utf-8").endswith("*\n")


def test_the_oldest_explanations_go_first(tmp_path: Path) -> None:
    cache = ExplanationCache(tmp_path, "scope")
    for number in range(MAX_ENTRIES + 5):
        cache.put(prompt(f"Rule: {number}"), f"Answer {number}.")

    assert len(cache.entries) == MAX_ENTRIES
    assert cache.get(prompt("Rule: 0")) is None
    assert cache.get(prompt(f"Rule: {MAX_ENTRIES + 4}")) is not None


def test_an_unchanged_cache_is_not_written(tmp_path: Path) -> None:
    ExplanationCache(tmp_path / "cache", "scope").save()

    assert not (tmp_path / "cache").exists()


@pytest.mark.parametrize(
    "content",
    [
        "not json",
        "[]",
        '{"format_version": 99, "entries": {}}',
        '{"format_version": 1, "entries": {"key": 3}}',
        '{"format_version": 1}',
    ],
)
def test_a_damaged_cache_starts_empty(tmp_path: Path, content: str) -> None:
    (tmp_path / "explanations.json").write_text(content, encoding="utf-8")

    cache = ExplanationCache(tmp_path, "scope")

    assert cache.entries == {}
    assert cache.problem is not None
    assert cache.problem.startswith("the explanation cache was not used")


def test_a_cache_that_cannot_be_written_says_so(tmp_path: Path) -> None:
    blocked = tmp_path / "cache"
    blocked.write_text("a file, not a folder", encoding="utf-8")
    cache = ExplanationCache(blocked, "scope")
    cache.put(prompt(), "Risky.")

    failure = cache.save()

    assert failure is not None
    assert failure.startswith("cannot save the explanation cache")


# The scan command: a second scan asks the AI nothing new.


class CountingExplainer:
    def __init__(self, answer: str = ANSWER) -> None:
        self.answer = answer
        self.calls = 0

    def explain(self, prompt: Prompt) -> str:
        self.calls += 1
        return self.answer


def project(tmp_path: Path, model: str = "llama3") -> Path:
    (tmp_path / "app.py").write_text("eval(x)\n", encoding="utf-8")
    (tmp_path / "pyproject.toml").write_text(
        "[tool.securelint.ai]\n"
        f'provider = "openai-compatible"\nmodel = "{model}"\n'
        'base-url = "http://localhost:1"\n',
        encoding="utf-8",
    )
    return tmp_path


def use(monkeypatch: pytest.MonkeyPatch, explainer: Explainer) -> None:
    def make(config: Config) -> Explainer:
        return explainer

    monkeypatch.setattr(cli, "make_explainer", make)


def test_a_second_scan_uses_the_cache(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    explainer = CountingExplainer()
    use(monkeypatch, explainer)
    folder = project(tmp_path)

    main(["scan", str(folder), "--explain"])
    first = capsys.readouterr()
    main(["scan", str(folder), "--explain"])
    second = capsys.readouterr()

    assert explainer.calls == 1
    assert second.out == first.out
    assert "AI explanation (may be wrong): eval runs any code." in second.out
    assert "explanations used again from the cache: 1" in second.err
    assert (folder / CACHE_FOLDER / ".gitignore").exists()


def test_an_edited_line_is_explained_again(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    explainer = CountingExplainer()
    use(monkeypatch, explainer)
    folder = project(tmp_path)

    main(["scan", str(folder), "--explain"])
    (folder / "app.py").write_text("eval(user_input)\n", encoding="utf-8")
    main(["scan", str(folder), "--explain"])

    assert explainer.calls == 2


def test_an_answer_that_failed_the_checks_is_not_kept(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    explainer = CountingExplainer("Not the JSON that was asked for.")
    use(monkeypatch, explainer)
    folder = project(tmp_path)

    main(["scan", str(folder), "--explain"])
    main(["scan", str(folder), "--explain"])

    # Asked again the second time: nothing wrong was remembered.
    assert explainer.calls == 2
    assert not (folder / CACHE_FOLDER).exists()


def test_a_broken_cache_does_not_change_the_scan(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    use(monkeypatch, CountingExplainer())
    folder = project(tmp_path)
    # A file where the cache folder should be: nothing can be saved there.
    (folder / CACHE_FOLDER).write_text("in the way", encoding="utf-8")

    assert main(["scan", str(folder), "--explain"]) == 1

    captured = capsys.readouterr()
    assert "AI explanation (may be wrong): eval runs any code." in captured.out
    assert "cannot save the explanation cache" in captured.err


def test_the_cache_is_used_only_with_ai_settings(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    use(monkeypatch, CountingExplainer())
    (tmp_path / "app.py").write_text("eval(x)\n", encoding="utf-8")

    main(["scan", str(tmp_path), "--explain"])

    assert not (tmp_path / CACHE_FOLDER).exists()
