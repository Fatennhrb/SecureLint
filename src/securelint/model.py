"""The data model shared by every part of SecureLint.

Detection rules produce ``Finding`` objects, and everything after them
(filtering, the pass/fail decision, the reports) only reads them.
"""

import enum
from dataclasses import dataclass


class Severity(enum.IntEnum):
    """How much damage the issue could cause if it is real.

    The numbers give the levels an order, so a policy can ask for
    "everything at HIGH or above" with ``severity >= Severity.HIGH``.
    """

    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


class Confidence(enum.IntEnum):
    """How sure the rule is that the issue is real and not a false alarm."""

    LOW = 1
    MEDIUM = 2
    HIGH = 3


@dataclass(frozen=True, slots=True)
class Finding:
    """One security issue reported at one place in one file.

    A finding is immutable: later stages decide what to do with it, but they
    cannot change what the rule reported.
    """

    rule_id: str
    """Stable identifier of the rule that reported the issue, e.g. ``SL101``."""

    message: str
    """One-sentence description of the issue, written for the developer."""

    severity: Severity
    confidence: Confidence

    path: str
    """File path relative to the scanned directory, with forward slashes.

    The same project must give the same report on Windows and Linux, so a
    path never contains a backslash or a drive letter.
    """

    line: int
    """Line number, starting at 1."""

    column: int
    """Column number, starting at 1.

    Python's ``ast`` module counts columns from 0, so rules add 1.
    """

    fingerprint: str = ""
    """A short code that identifies this finding even after the lines around
    it have moved (see ``securelint.fingerprint``). Rules leave it empty;
    the engine fills it in once the whole file has been checked."""

    def __post_init__(self) -> None:
        # A broken finding should fail where it is created, not later as a
        # confusing line in a report.
        if not self.rule_id:
            raise ValueError("rule_id must not be empty")
        if not self.message:
            raise ValueError("message must not be empty")
        if not self.path:
            raise ValueError("path must not be empty")
        if "\\" in self.path:
            raise ValueError(f"path must use forward slashes: {self.path!r}")
        if self.line < 1:
            raise ValueError(f"line must be 1 or greater, got {self.line}")
        if self.column < 1:
            raise ValueError(f"column must be 1 or greater, got {self.column}")
