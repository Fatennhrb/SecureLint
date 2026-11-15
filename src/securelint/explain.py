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

from collections.abc import Callable, Sequence
from dataclasses import replace
from functools import cache
from pathlib import Path
from typing import Protocol

from securelint.engine import ScanResult
from securelint.model import Finding
from securelint.prompt import Prompt, build_prompt

MAX_EXPLAINED = 10
"""Findings explained in one scan at most. Each explanation can cost money
and time, and a long list of explanations is not read anyway."""

LineReader = Callable[[str], Sequence[str]]
"""Returns the lines of a file, from its path as shown in the findings."""


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
        except Exception as error:
            # Any failure, whatever its kind, costs this one explanation and
            # nothing more: the scan's result is already decided.
            place = f"{finding.path}:{finding.line}"
            problems.append(f"cannot explain {finding.rule_id} at {place}: {error}")
            continue
        text = " ".join(str(answer).split())
        if text:
            explained.append((finding, text))
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
