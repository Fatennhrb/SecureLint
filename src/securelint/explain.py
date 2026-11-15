"""Explain findings in plain words, with an AI the project chooses.

The rest of SecureLint only knows the ``Explainer`` interface below. Which
AI answers is decided by the project's settings, so no provider is built
into the scanner, and tests use a fake that never leaves the machine.

What an explainer receives is built by ``securelint.prompt``: a few lines
around the finding, with secrets hidden. It never gets the file itself.

Explanations are added after the policy has decided what blocks, and
nothing here can change that decision: an explainer that fails, answers
nonsense or takes too long costs an explanation, never a different result.
"""

import json
import unicodedata
from collections.abc import Callable, Sequence
from dataclasses import replace
from functools import cache
from pathlib import Path
from typing import Any, Protocol

from securelint.engine import ScanResult
from securelint.model import Finding
from securelint.prompt import Prompt, build_prompt

MAX_EXPLAINED = 10
"""Findings explained in one scan at most. Each explanation can cost money
and time, and a long list of explanations is not read anyway."""

MAX_EXPLANATION = 600
"""Characters kept from the explanation the AI gives."""

MAX_FIX = 400
"""Characters kept from the fix the AI suggests."""

LineReader = Callable[[str], Sequence[str]]
"""Returns the lines of a file, from its path as shown in the findings."""


class AnswerError(ValueError):
    """The AI's answer is not in the format it was asked for."""


class Explainer(Protocol):
    """Something that can explain one finding in a few sentences."""

    def explain(self, prompt: Prompt) -> str:
        """Return the answer to ``prompt``.

        May raise any exception: the caller treats it as "no explanation".
        """
        ...


def add_explanations(
    result: ScanResult,
    explainer: Explainer,
    read_lines: LineReader,
    limit: int = MAX_EXPLAINED,
) -> tuple[ScanResult, list[str]]:
    """Return ``result`` with explanations, and the problems met on the way.

    The findings that block are explained first, then the warnings, up to
    ``limit`` in all. Known, silenced and out-of-change findings are not
    explained: they are not shown either. The findings themselves, and so
    the exit code, are left exactly as they were.
    """
    wanted: Sequence[Finding] = [*result.findings, *result.warnings]
    problems: list[str] = []
    explained: list[tuple[Finding, str]] = []
    for finding in wanted[:limit]:
        try:
            answer = explainer.explain(build_prompt(finding, read_lines(finding.path)))
            explained.append((finding, parse_answer(answer)))
        except Exception as error:
            # Any failure, whatever its kind, costs this one explanation and
            # nothing more: the scan's result is already decided.
            place = f"{finding.path}:{finding.line}"
            problems.append(f"cannot explain {finding.rule_id} at {place}: {error}")
    if len(wanted) > limit:
        problems.append(
            f"explained the first {limit} of {len(wanted)} findings; "
            "the others have no explanation"
        )
    return replace(result, explanations=tuple(explained)), problems


def file_lines(folder: Path) -> LineReader:
    """Return a reader of the files in ``folder``, the folder that was scanned.

    A file that cannot be read gives no lines: the finding is then
    explained without its code, not skipped.
    """

    @cache
    def read(path: str) -> Sequence[str]:
        try:
            text = (folder / path).read_text(encoding="utf-8", errors="replace")
        except OSError:
            return ()
        return tuple(text.splitlines())

    return read


def parse_answer(answer: object) -> str:
    """Return the explanation in the AI's answer, as one line of plain text.

    The answer must be the JSON object the prompt asks for, with a
    non-empty ``"explanation"`` and, if there is one, a ``"fix"``, both
    text. Anything else raises ``AnswerError``: an answer that does not
    follow the format cannot be trusted to follow the rest of the prompt
    either. A code block around the JSON is accepted, since models often
    add one.

    Control characters are removed, so an answer cannot move the cursor
    of a terminal, change its colours, or turn text around unseen.
    """
    if not isinstance(answer, str):
        raise AnswerError("the answer is not text")
    text = answer.strip()
    lines = text.splitlines()
    if len(lines) >= 2 and lines[0].startswith("```") and lines[-1].strip() == "```":
        text = "\n".join(lines[1:-1])
    try:
        document = json.loads(text)
    except json.JSONDecodeError:
        raise AnswerError("the answer is not the JSON that was asked for") from None
    if not isinstance(document, dict):
        raise AnswerError("the answer is not a JSON object")

    explanation = _field(document, "explanation", MAX_EXPLANATION)
    if not explanation:
        raise AnswerError('the answer has no "explanation"')
    fix = _field(document, "fix", MAX_FIX)
    return f"{explanation} Fix: {fix}" if fix else explanation


def _field(document: dict[str, Any], key: str, limit: int) -> str:
    value = document.get(key)
    if value is None:
        return ""
    if not isinstance(value, str):
        raise AnswerError(f'"{key}" in the answer is not text')
    # Unicode categories starting with "C" are control and format
    # characters: escape codes, invisible marks, text-direction overrides.
    visible = "".join(
        " " if unicodedata.category(char).startswith("C") else char for char in value
    )
    text = " ".join(visible.split())
    if len(text) > limit:
        text = text[: limit - 3] + "..."
    return text
