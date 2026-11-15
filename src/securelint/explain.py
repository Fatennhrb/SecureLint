"""Explain findings in plain words, with an AI the project chooses.

The rest of SecureLint only knows the ``Explainer`` interface below. Which
AI answers is decided by the project's settings, so no provider is built
into the scanner, and tests use a fake that never leaves the machine.

Explanations are added after the policy has decided what blocks, and
nothing here can change that decision: an explainer that fails, answers
nonsense or takes too long costs an explanation, never a different result.
"""

from collections.abc import Sequence
from dataclasses import replace
from typing import Protocol

from securelint.engine import ScanResult
from securelint.model import Finding

MAX_EXPLAINED = 10
"""Findings explained in one scan at most. Each explanation can cost money
and time, and a long list of explanations is not read anyway."""


class Explainer(Protocol):
    """Something that can explain one finding in a few sentences."""

    def explain(self, finding: Finding) -> str:
        """Return the explanation of ``finding``.

        May raise any exception: the caller treats it as "no explanation".
        """
        ...


def add_explanations(
    result: ScanResult, explainer: Explainer, limit: int = MAX_EXPLAINED
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
            answer = explainer.explain(finding)
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
