"""Read the dependency problems Trivy found, as SecureLint findings.

SecureLint does not run Trivy. Trivy is run first, on the same folder, and
writes a JSON report::

    trivy fs --format json --output trivy.json .
    securelint scan . --trivy-report trivy.json

Each known vulnerability in a dependency becomes a finding of rule SL201,
so the baseline, the policy, the changed lines and every report work for
them as for the problems in the code.

The report is data written by another program, so nothing in it is
trusted: its shape is checked, its paths must stay inside the scanned
folder, and its text only ever reaches the reports as a message, which
every report already escapes.
"""

import json
import re
from collections.abc import Collection
from pathlib import Path, PurePosixPath
from typing import Any

from securelint.fingerprint import fingerprint_for
from securelint.model import Confidence, Finding, Severity

RULE_ID = "SL201"
TITLE = "Dependency with a known vulnerability"

_SEVERITIES = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
    # Trivy has no severity for this one yet. It is not taken as harmless.
    "UNKNOWN": Severity.MEDIUM,
}

_MAX_TITLE = 200
"""Characters kept from Trivy's title, so one finding stays one line."""

# The name at the start of a requirement such as "Django[argon2]>=4.2".
_REQUIREMENT_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*")


class TrivyReportError(Exception):
    """The Trivy report cannot be read or does not fit the scanned folder."""


def read_trivy_report(
    report: Path, folder: Path, root: Path, ignore: Collection[str] = ()
) -> list[Finding]:
    """Return the findings in the Trivy report ``report``.

    ``folder`` is the folder Trivy and SecureLint both scanned: the paths
    in the report start there. ``root`` is the top of the project, used
    for fingerprints like everywhere else.

    Raises ``TrivyReportError`` if the report cannot be read, is not a
    Trivy JSON report, or names a file that is not in ``folder``.
    """
    if RULE_ID in ignore:
        return []
    try:
        document = json.loads(report.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise TrivyReportError(
            f"cannot read the Trivy report {report}: {error}"
        ) from error

    # By fingerprint: Trivy can list the same problem twice for one file.
    findings: dict[str, Finding] = {}
    for entry in _list(_object(document, "the report").get("Results"), "Results"):
        result = _object(entry, "a result")
        vulnerabilities = _list(result.get("Vulnerabilities"), "Vulnerabilities")
        if not vulnerabilities:
            continue
        path = _safe_path(_text(result, "Target"))
        file = folder / path
        if not file.is_file():
            raise TrivyReportError(
                f"the Trivy report names {path}, which is not in {folder}; "
                "run Trivy on the folder SecureLint scans"
            )
        lines = file.read_text(encoding="utf-8", errors="replace").splitlines()
        in_project = _path_in_project(file, path, root)
        for item in vulnerabilities:
            vulnerability = _object(item, "a vulnerability")
            finding = _finding(vulnerability, path, lines, in_project)
            findings.setdefault(finding.fingerprint, finding)
    return list(findings.values())


def _finding(
    item: dict[str, Any], path: str, lines: list[str], in_project: str
) -> Finding:
    vulnerability = _text(item, "VulnerabilityID")
    package = _text(item, "PkgName")
    installed = _text(item, "InstalledVersion")
    severity_name = _text(item, "Severity")
    if severity_name not in _SEVERITIES:
        raise TrivyReportError(f"unknown severity {severity_name!r} in the report")

    message = f"{package} {installed} has a known vulnerability, {vulnerability}"
    title = " ".join(str(item.get("Title") or "").split())
    if title:
        if len(title) > _MAX_TITLE:
            title = title[: _MAX_TITLE - 3] + "..."
        message += f": {title}"
    fixed = str(item.get("FixedVersion") or "").strip()
    if fixed:
        message += f". Upgrade to a fixed version ({fixed})."
    else:
        message += ". No fixed version is available yet."

    return Finding(
        rule_id=RULE_ID,
        message=message,
        severity=_SEVERITIES[severity_name],
        # Trivy matched the exact installed version against a list of
        # known vulnerabilities: this is not a guess about the code.
        confidence=Confidence.HIGH,
        path=path,
        line=_line_of(package, lines),
        column=1,
        # The package, its version and the vulnerability, not the line: the
        # finding keeps its identity when other dependencies are added or
        # removed, and becomes new when the package's version changes.
        fingerprint=fingerprint_for(
            RULE_ID, in_project, f"{package}\0{installed}\0{vulnerability}".encode()
        ),
    )


def _line_of(package: str, lines: list[str]) -> int:
    """Return the line where ``package`` is listed; 1 if it cannot be found.

    Trivy gives no line numbers. A requirements file names one package per
    line; other files (lock files, for example) are searched for the name
    as a whole word.
    """
    wanted = _normalise(package)
    for number, line in enumerate(lines, start=1):
        match = _REQUIREMENT_NAME.match(line.strip())
        if match and _normalise(match.group()) == wanted:
            return number
    word = re.compile(rf"(?<![\w.-]){re.escape(package)}(?![\w.-])", re.IGNORECASE)
    for number, line in enumerate(lines, start=1):
        if word.search(line):
            return number
    return 1


def _normalise(name: str) -> str:
    # Python package names ignore case, and treat "-", "_" and "." alike.
    return re.sub(r"[-_.]+", "-", name).lower()


def _safe_path(target: str) -> str:
    """Return the report's path, refusing one that leaves the scanned folder."""
    path = PurePosixPath(target.replace("\\", "/"))
    if not target or path.is_absolute() or ".." in path.parts or ":" in target:
        raise TrivyReportError(
            f"the Trivy report names {target!r}, which is not a file of the "
            "scanned folder; only reports of `trivy fs` on that folder are read"
        )
    return path.as_posix()


def _path_in_project(file: Path, path: str, root: Path) -> str:
    full_path = file.resolve()
    if full_path.is_relative_to(root):
        return full_path.relative_to(root).as_posix()
    return path


def _object(value: object, what: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise TrivyReportError(f"not a Trivy JSON report: {what} is not an object")
    return value


def _list(value: object, what: str) -> list[Any]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise TrivyReportError(f"not a Trivy JSON report: {what} is not a list")
    return value


def _text(item: dict[str, Any], key: str) -> str:
    value = item.get(key)
    if not isinstance(value, str) or not value.strip():
        raise TrivyReportError(f"not a Trivy JSON report: {key} is missing")
    return value.strip()
