"""Tell the problems a project already knows about from new ones.

A project that starts using SecureLint may have many findings it cannot
fix at once. If every scan failed because of them, the tool would simply
be turned off. The baseline lets the project accept what exists today
and still stop anything new::

    securelint baseline     # remember today's findings in a file
    securelint scan         # from now on, only new findings count

The baseline is a small JSON file kept at the top of the project and
committed with the code, so the whole team shares it and every change to
it is visible in code review. It holds the fingerprint of each known
finding (see ``securelint.fingerprint``), which is why a known finding
stays known when the lines around it move.
"""

import json
from collections.abc import Sequence
from dataclasses import replace
from pathlib import Path
from typing import Any

from securelint.engine import ScanResult
from securelint.model import Finding

BASELINE_FILE_NAME = ".securelint-baseline.json"

BASELINE_FORMAT_VERSION = 1
"""Raised if the file's layout changes in a way older versions cannot read."""


class BaselineError(Exception):
    """The baseline file cannot be used; the message says why."""


def find_project_root(target: Path) -> Path:
    """Return the top directory of the project that ``target`` belongs to.

    That is the nearest directory, starting at ``target`` and going up,
    that holds a baseline file or is the top of a Git repository. Without
    either, it is the scanned directory itself.
    """
    start = target.resolve()
    if not start.is_dir():
        start = start.parent
    for directory in (start, *start.parents):
        if (directory / BASELINE_FILE_NAME).is_file():
            return directory
        if (directory / ".git").exists():
            return directory
    return start


def save_baseline(path: Path, findings: Sequence[Finding]) -> None:
    """Write the baseline file listing ``findings`` as known."""
    entries = sorted(
        (
            {
                "fingerprint": finding.fingerprint,
                # The rule and the file are for the person reading the
                # file or its diff; only the fingerprint is used to match.
                # The line number is left out on purpose: it would be
                # wrong as soon as the code above it changed.
                "rule_id": finding.rule_id,
                "path": finding.path,
            }
            for finding in findings
        ),
        key=lambda entry: (entry["path"], entry["rule_id"], entry["fingerprint"]),
    )
    document = {
        "format_version": BASELINE_FORMAT_VERSION,
        "tool": "securelint",
        "findings": entries,
    }
    # One entry per line and a fixed order, so adding or removing a finding
    # changes only its own lines in a diff.
    path.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")


def load_baseline(path: Path) -> frozenset[str] | None:
    """Return the fingerprints listed in a baseline file.

    Returns ``None`` when the file does not exist. Raises ``BaselineError``
    when it exists but cannot be read or understood: guessing would either
    hide new problems or bring back all the old ones.
    """
    if not path.is_file():
        return None
    try:
        document: Any = json.loads(path.read_text(encoding="utf-8"))
    except OSError as error:
        raise BaselineError(f"{path}: cannot be read: {error}") from error
    except ValueError as error:
        raise BaselineError(f"{path}: not valid JSON: {error}") from error

    if not isinstance(document, dict):
        raise BaselineError(f"{path}: not a SecureLint baseline file")
    if document.get("format_version") != BASELINE_FORMAT_VERSION:
        raise BaselineError(
            f"{path}: written in a format this version of SecureLint does not "
            "read; run `securelint baseline` to write it again"
        )
    entries = document.get("findings")
    if not isinstance(entries, list):
        raise BaselineError(f"{path}: not a SecureLint baseline file")

    fingerprints = set()
    for entry in entries:
        fingerprint = entry.get("fingerprint") if isinstance(entry, dict) else None
        if not isinstance(fingerprint, str) or not fingerprint:
            raise BaselineError(f"{path}: an entry has no fingerprint")
        fingerprints.add(fingerprint)
    return frozenset(fingerprints)


def split_known(result: ScanResult, known: frozenset[str]) -> ScanResult:
    """Move the findings listed in the baseline out of ``result.findings``.

    They are kept in ``result.known``, so reports can still show them.
    """
    return replace(
        result,
        findings=tuple(f for f in result.findings if f.fingerprint not in known),
        known=tuple(f for f in result.findings if f.fingerprint in known),
    )


def count_no_longer_found(result: ScanResult, known: frozenset[str]) -> int:
    """Return how many baseline entries match nothing in a scan result.

    Each one is a known problem that was fixed, or whose line was edited.
    Only meaningful for a scan of the whole project.
    """
    present = {finding.fingerprint for finding in result.findings}
    present.update(finding.fingerprint for finding in result.known)
    present.update(item.finding.fingerprint for item in result.silenced)
    return len(known - present)
