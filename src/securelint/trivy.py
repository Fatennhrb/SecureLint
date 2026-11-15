"""Read the problems Trivy found, as SecureLint findings.

SecureLint does not run Trivy. Trivy is run first, on the same folder, and
writes a JSON report::

    trivy fs --scanners vuln,misconfig --format json --output trivy.json .
    securelint scan . --trivy-report trivy.json

Two kinds of problems are read:

* SL201: a dependency with a known vulnerability (Trivy's "vuln" scanner),
* SL202: an unsafe setting in a Dockerfile or another configuration file
  (Trivy's "misconfig" scanner).

They become findings like the problems in the code, so the baseline, the
policy, the changed lines and every report work for them too.

The report is data written by another program, so nothing in it is
trusted: its shape is checked, its paths must stay inside the scanned
folder, and its text only ever reaches the reports as a message, which
every report already escapes.
"""

import json
import re
from collections import Counter
from collections.abc import Collection
from pathlib import Path, PurePosixPath
from typing import Any

from securelint.fingerprint import fingerprint_for
from securelint.model import Confidence, Finding, Severity

DEPENDENCY_RULE_ID = "SL201"
CONFIG_RULE_ID = "SL202"
TITLES = {
    DEPENDENCY_RULE_ID: "Dependency with a known vulnerability",
    CONFIG_RULE_ID: "Unsafe setting in a Dockerfile or configuration file",
}

_SEVERITIES = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
    # Trivy has no severity for this one yet. It is not taken as harmless.
    "UNKNOWN": Severity.MEDIUM,
}

# Trivy can also list the checks a file passed ("PASS") and the ones the
# project chose to accept ("EXCEPTION"). Only failed checks are problems.
_FAILED = "FAIL"

_MAX_TEXT = 200
"""Characters kept from each text of Trivy's, so one finding stays one line."""

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
    for fingerprints like everywhere else. Rules in ``ignore`` are skipped.

    Raises ``TrivyReportError`` if the report cannot be read, is not a
    Trivy JSON report, or names a file that is not in ``folder``.
    """
    if set(TITLES) <= set(ignore):
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
        vulnerabilities = []
        if DEPENDENCY_RULE_ID not in ignore:
            vulnerabilities = _list(result.get("Vulnerabilities"), "Vulnerabilities")
        settings = []
        if CONFIG_RULE_ID not in ignore:
            settings = [
                _object(item, "a misconfiguration")
                for item in _list(result.get("Misconfigurations"), "Misconfigurations")
            ]
            settings = [item for item in settings if _status(item) == _FAILED]
        if not vulnerabilities and not settings:
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
            finding = _dependency(vulnerability, path, lines, in_project)
            findings.setdefault(finding.fingerprint, finding)
        for finding in _settings(settings, path, lines, in_project):
            findings.setdefault(finding.fingerprint, finding)
    return list(findings.values())


def _dependency(
    item: dict[str, Any], path: str, lines: list[str], in_project: str
) -> Finding:
    vulnerability = _text(item, "VulnerabilityID")
    package = _text(item, "PkgName")
    installed = _text(item, "InstalledVersion")

    message = f"{package} {installed} has a known vulnerability, {vulnerability}"
    title = _short(item.get("Title"))
    if title:
        message += f": {title}"
    fixed = _short(item.get("FixedVersion"))
    if fixed:
        message += f". Upgrade to a fixed version ({fixed})."
    else:
        message += ". No fixed version is available yet."

    return Finding(
        rule_id=DEPENDENCY_RULE_ID,
        message=message,
        severity=_severity(item),
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
            DEPENDENCY_RULE_ID,
            in_project,
            f"{package}\0{installed}\0{vulnerability}".encode(),
        ),
    )


def _settings(
    items: list[dict[str, Any]], path: str, lines: list[str], in_project: str
) -> list[Finding]:
    """Turn the failed configuration checks of one file into findings."""
    placed = []
    for item in items:
        line = _start_line(item)
        if line > len(lines):
            # A line the file does not have: the report is of another file.
            raise TrivyReportError(
                f"the Trivy report points to line {line} of {path}, which has "
                f"{len(lines)} lines; run Trivy again on the scanned folder"
            )
        placed.append((line, item))

    # Like the code's findings: the check and the text of its line, so the
    # finding keeps its identity when other lines move. Identical lines are
    # numbered from the top of the file. A check about the whole file (no
    # line) is identified by the check alone.
    seen: Counter[tuple[str, str]] = Counter()
    findings = []
    for line, item in sorted(placed, key=lambda pair: pair[0]):
        check = _text(item, "ID")
        text = lines[line - 1].strip() if line else ""
        occurrence = seen[(check, text)]
        seen[(check, text)] += 1

        message = _short(item.get("Title")) or f"Trivy check {check} failed"
        message = f"{message.rstrip('.')} ({check})"
        detail = _short(item.get("Message"))
        if detail:
            message += f": {detail.rstrip('.')}"
        resolution = _short(item.get("Resolution"))
        message += f". Fix: {resolution.rstrip('.')}." if resolution else "."

        findings.append(
            Finding(
                rule_id=CONFIG_RULE_ID,
                message=message,
                severity=_severity(item),
                # A configuration check sees a risky setting, not whether it
                # can be used in this project (a container may run as root
                # on purpose, for example).
                confidence=Confidence.MEDIUM,
                path=path,
                line=max(line, 1),
                column=1,
                fingerprint=fingerprint_for(
                    CONFIG_RULE_ID,
                    in_project,
                    f"{check}\0{text}\0{occurrence}".encode(),
                ),
            )
        )
    return findings


def _status(item: dict[str, Any]) -> str:
    status = item.get("Status", _FAILED)
    if not isinstance(status, str):
        raise TrivyReportError("not a Trivy JSON report: Status is not text")
    return status


def _start_line(item: dict[str, Any]) -> int:
    """Return the first line of the problem; 0 when it is about the whole file."""
    cause = _object(item.get("CauseMetadata", {}), "CauseMetadata")
    line = cause.get("StartLine", 0)
    if not isinstance(line, int) or isinstance(line, bool) or line < 0:
        raise TrivyReportError("not a Trivy JSON report: StartLine is not a line")
    return line


def _severity(item: dict[str, Any]) -> Severity:
    name = _text(item, "Severity")
    if name not in _SEVERITIES:
        raise TrivyReportError(f"unknown severity {name!r} in the report")
    return _SEVERITIES[name]


def _short(value: object) -> str:
    """Return Trivy's text on one line, cut to a reasonable length."""
    text = " ".join(str(value or "").split())
    if len(text) > _MAX_TEXT:
        text = text[: _MAX_TEXT - 3] + "..."
    return text


def _line_of(package: str, lines: list[str]) -> int:
    """Return the line where ``package`` is listed; 1 if it cannot be found.

    Trivy gives no line numbers for dependencies. A requirements file names
    one package per line; other files (lock files, for example) are
    searched for the name as a whole word.
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
