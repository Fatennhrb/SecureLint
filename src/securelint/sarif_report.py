"""Write a scan result in SARIF, the format GitHub reads for security tools.

SARIF (Static Analysis Results Interchange Format, version 2.1.0) is a
standard JSON layout. Once a SARIF file is uploaded to GitHub, its results
appear in the repository's Security tab and next to the changed lines of a
pull request.

Every finding of the scan is written, each with a level that says how the
project's policy treats it:

* ``error``: the finding blocks;
* ``warning``: the policy reports it without blocking, or a comment in the
  code silenced it (it then also carries a SARIF ``suppressions`` entry);
* ``note``: the finding is listed in the project's baseline file (it then
  also carries ``"baselineState": "unchanged"``).

Paths are written from the top of the project, the way GitHub expects
them, whatever folder the scan was started on.
"""

import json
from collections.abc import Iterable
from typing import Any

from securelint import __version__
from securelint.engine import ScanResult
from securelint.model import Finding, Severity
from securelint.rules import ALL_RULES
from securelint.suppressions import COMMENT_RULE_ID

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"

_HOME = "https://github.com/Fatennhrb/SecureLint"

# The name under which SecureLint's own fingerprint is given to GitHub, so a
# finding keeps its identity between two uploads even when lines move.
_FINGERPRINT_KEY = "securelint/v1"

# GitHub sorts security results by this number, from 0 to 10: 9.0 and above
# is "critical", 7.0 to 8.9 "high", 4.0 to 6.9 "medium", below that "low".
_SECURITY_SEVERITY = {
    Severity.CRITICAL: "9.5",
    Severity.HIGH: "8.0",
    Severity.MEDIUM: "5.5",
    Severity.LOW: "2.0",
}

_TITLES = {rule.rule_id: rule.title for rule in ALL_RULES} | {
    COMMENT_RULE_ID: "Comment that silences nothing"
}


def format_sarif(result: ScanResult) -> str:
    """Return the scan result as a SARIF 2.1.0 document."""
    entries: list[tuple[Finding, dict[str, Any]]] = []
    entries += [(finding, {"level": "error"}) for finding in result.findings]
    entries += [(finding, {"level": "warning"}) for finding in result.warnings]
    entries += [
        (finding, {"level": "note", "baselineState": "unchanged"})
        for finding in result.known
    ]
    for item in result.silenced:
        suppression: dict[str, Any] = {"kind": "inSource"}
        if item.reason:
            suppression["justification"] = item.reason
        entries.append(
            (item.finding, {"level": "warning", "suppressions": [suppression]})
        )
    # One order for every kind of result, so the same scan always gives the
    # same file.
    entries.sort(key=lambda entry: _position(entry[0]))

    rule_ids = sorted({finding.rule_id for finding, _ in entries})
    rule_index = {rule_id: index for index, rule_id in enumerate(rule_ids)}

    run: dict[str, Any] = {
        "tool": {
            "driver": {
                "name": "SecureLint",
                "version": __version__,
                "semanticVersion": __version__,
                "informationUri": _HOME,
                "rules": [
                    _rule(rule_id, (f for f, _ in entries if f.rule_id == rule_id))
                    for rule_id in rule_ids
                ],
            }
        },
        # Columns count characters. SecureLint counts bytes, which is the
        # same on every line written only with ASCII characters.
        "columnKind": "unicodeCodePoints",
        "invocations": [_invocation(result)],
        "results": [
            {
                "ruleId": finding.rule_id,
                "ruleIndex": rule_index[finding.rule_id],
                **fields,
                "message": {"text": finding.message},
                "locations": [
                    _location(
                        _uri(result.base, finding.path), finding.line, finding.column
                    )
                ],
                **(
                    {"partialFingerprints": {_FINGERPRINT_KEY: finding.fingerprint}}
                    if finding.fingerprint
                    else {}
                ),
                "properties": {
                    "severity": finding.severity.name.lower(),
                    "confidence": finding.confidence.name.lower(),
                },
            }
            for finding, fields in entries
        ],
    }
    document = {"$schema": SARIF_SCHEMA, "version": SARIF_VERSION, "runs": [run]}
    return json.dumps(document, indent=2)


def _rule(rule_id: str, findings: Iterable[Finding]) -> dict[str, Any]:
    """Describe one rule, for the rules that have results in this run."""
    # A rule's findings can differ in severity; GitHub takes one number per
    # rule, so the most serious one is used.
    severity = max(finding.severity for finding in findings)
    title = _TITLES.get(rule_id) or rule_id
    return {
        "id": rule_id,
        "name": rule_id,
        "shortDescription": {"text": title},
        "helpUri": f"{_HOME}#rules",
        "properties": {
            # GitHub only uses "security-severity" on rules tagged "security".
            "tags": ["security"],
            "security-severity": _SECURITY_SEVERITY[severity],
        },
    }


def _invocation(result: ScanResult) -> dict[str, Any]:
    """Say whether the scan completed, and list the files it could not read."""
    notifications = []
    for failure in result.failures:
        line = failure.line if failure.line is not None else 1
        notifications.append(
            {
                "level": "error",
                "message": {"text": f"cannot scan this file: {failure.message}"},
                "locations": [
                    _location(_uri(result.base, failure.relative_path), line, 1)
                ],
            }
        )
    return {
        # A file nobody could read is not a clean file.
        "executionSuccessful": not result.failures,
        "toolExecutionNotifications": notifications,
    }


def _location(uri: str, line: int, column: int) -> dict[str, Any]:
    return {
        "physicalLocation": {
            "artifactLocation": {"uri": uri, "uriBaseId": "%SRCROOT%"},
            "region": {"startLine": line, "startColumn": column},
        }
    }


def _uri(base: str, path: str) -> str:
    """Return a path from the top of the project, as GitHub expects."""
    return f"{base}/{path}" if base else path


def _position(finding: Finding) -> tuple[str, int, int, str]:
    return (finding.path, finding.line, finding.column, finding.rule_id)
