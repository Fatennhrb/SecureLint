"""Silence one finding with a comment on its line.

A person who has checked a reported line and knows it is fine can say so,
on that line::

    os.system(command)  # securelint: ignore[SL102] command is our own setting

The rule must be named. There is no way to silence "everything on this
line": that would also hide problems nobody has looked at.

Silencing is never invisible. A silenced finding is kept and counted in
every report, and a comment that silences nothing is itself reported
(``SL001``), so comments left behind after a fix do not pile up.
"""

import io
import re
import tokenize
from collections.abc import Collection
from dataclasses import dataclass

from securelint.model import Confidence, Finding, Severity

COMMENT_RULE_ID = "SL001"
"""The id under which a useless or unreadable silencing comment is reported."""

# Looked for in the raw file first, so the comments of a file are only
# read when there is something to find. Most files have none.
_MARKER = b"securelint:"

_DIRECTIVE = re.compile(r"#\s*securelint:(.*)", re.DOTALL)
_IGNORE = re.compile(r"ignore\[([^\]]*)\](.*)", re.DOTALL)
_RULE_ID = re.compile(r"[A-Z]+[0-9]+")


@dataclass(frozen=True, slots=True)
class Silenced:
    """A finding hidden by a comment, with the reason the comment gives."""

    finding: Finding
    reason: str
    """The text after the brackets; empty when none was written."""


@dataclass(frozen=True, slots=True)
class _Comment:
    """One ``securelint:`` comment found in a file."""

    line: int
    column: int
    rule_ids: tuple[str, ...] | None
    """The rules it names; ``None`` when the comment could not be understood."""
    reason: str


def apply_comments(
    findings: list[Finding], source: bytes, path: str, running: Collection[str]
) -> tuple[list[Finding], list[Silenced]]:
    """Split the findings of one file into those kept and those silenced.

    ``running`` holds the ids of the rules the scan runs. The kept list
    also receives one ``SL001`` finding for each comment, or each rule
    named in a comment, that silenced nothing.
    """
    if _MARKER not in source:
        return findings, []
    comments = _read_comments(source)
    # A line can hold only one comment, so the line number is enough.
    by_line = {comment.line: comment for comment in comments}

    kept: list[Finding] = []
    silenced: list[Silenced] = []
    used: set[tuple[int, str]] = set()
    for finding in findings:
        comment = by_line.get(finding.line)
        if (
            comment is not None
            and comment.rule_ids is not None
            and finding.rule_id in comment.rule_ids
        ):
            silenced.append(Silenced(finding, comment.reason))
            used.add((finding.line, finding.rule_id))
        else:
            kept.append(finding)

    for comment in comments:
        if comment.rule_ids is None:
            kept.append(
                _comment_problem(
                    path,
                    comment,
                    "This comment is not understood, so it silences nothing; "
                    "write it as: # securelint: ignore[SL102] reason.",
                )
            )
            continue
        for rule_id in comment.rule_ids:
            if (comment.line, rule_id) in used:
                continue
            if rule_id in running:
                problem = f"but {rule_id} reports nothing on this line"
            else:
                problem = "which does not exist or is turned off"
            kept.append(
                _comment_problem(
                    path,
                    comment,
                    f"This comment silences {rule_id}, {problem}; remove it.",
                )
            )
    return kept, silenced


def _read_comments(source: bytes) -> list[_Comment]:
    """Return the ``securelint:`` comments of a file.

    The file is read token by token, the way Python reads it, so the same
    text inside a string is not mistaken for a comment.
    """
    comments: list[_Comment] = []
    try:
        for token in tokenize.tokenize(io.BytesIO(source).readline):
            if token.type != tokenize.COMMENT:
                continue
            # The directive may come after another tool's comment on the
            # same line, so it is looked for anywhere in the comment.
            match = _DIRECTIVE.search(token.string)
            if match is None:
                continue
            rule_ids, reason = _read_directive(match.group(1))
            comments.append(
                _Comment(
                    line=token.start[0],
                    column=token.start[1] + match.start() + 1,
                    rule_ids=rule_ids,
                    reason=reason,
                )
            )
    except (tokenize.TokenError, SyntaxError, ValueError):
        # The file parsed, so this is not expected. If it happens, the
        # comments read so far are used and the rest silence nothing:
        # findings are then shown, which is the safe direction.
        pass
    return comments


def _read_directive(text: str) -> tuple[tuple[str, ...] | None, str]:
    """Read what follows ``securelint:``; return the rule ids and the reason."""
    match = _IGNORE.fullmatch(text.strip())
    if match is None:
        return None, ""
    rule_ids = tuple(part.strip() for part in match.group(1).split(","))
    if not all(_RULE_ID.fullmatch(rule_id) for rule_id in rule_ids):
        return None, ""
    return rule_ids, match.group(2).strip(" \t:-")


def _comment_problem(path: str, comment: _Comment, message: str) -> Finding:
    return Finding(
        rule_id=COMMENT_RULE_ID,
        message=message,
        # Not a danger in itself, but it shows a silencing that no longer
        # matches the code, and SecureLint is sure of that.
        severity=Severity.LOW,
        confidence=Confidence.HIGH,
        path=path,
        line=comment.line,
        column=comment.column,
    )
