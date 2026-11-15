"""Write a scan result the way GitHub Actions shows it on a pull request.

Inside a GitHub Actions job, a line printed in this form::

    ::error file=src/app.py,line=12,col=5,title=SL102 (high)::os.system() runs...

is not shown as text: GitHub turns it into a note on line 12 of
``src/app.py``, in the pull request and on the job's page. No upload and
no extra permission are needed.

Findings that block become ``error`` notes, and warnings of the policy
become ``warning`` notes. Known, silenced and out-of-change findings are
only counted, in the last line and in the job summary.

The text comes from the scanned code (file names, names quoted in
messages), and GitHub gives some characters a meaning in this format. All
of it is escaped (see ``_data`` and ``_property``), so a strange file name
or message can neither break a note nor create a fake one.
"""

from collections import Counter

from securelint.engine import ScanResult
from securelint.model import Finding, Severity
from securelint.report import AI_LABEL, summary_line


def format_github(result: ScanResult) -> str:
    """Return one GitHub note per finding to show, then the summary line."""
    explanations = dict(result.explanations)
    lines = [
        _note("error", finding, result.base, explanations.get(finding))
        for finding in result.findings
    ]
    lines += [
        _note("warning", finding, result.base, explanations.get(finding))
        for finding in result.warnings
    ]
    for failure in result.failures:
        properties = f"file={_property(_from_top(result.base, failure.relative_path))}"
        if failure.line is not None:
            properties += f",line={failure.line}"
        message = f"SecureLint cannot scan this file: {failure.message}"
        lines.append(f"::error {properties}::{_data(message)}")
    lines.append(summary_line(result))
    return "\n".join(lines)


def format_step_summary(result: ScanResult) -> str:
    """Return a short Markdown summary for the job's result page.

    It holds only numbers and fixed words, never text from the scanned
    code, so nothing in it needs escaping.
    """
    if result.failures:
        verdict = (
            f"**Incomplete:** {_count(len(result.failures), 'file')} could not be "
            "scanned, so the result cannot be trusted."
        )
    elif result.findings:
        verdict = (
            f"**Blocked:** {_count(len(result.findings), 'problem')} must be fixed."
        )
    else:
        verdict = "**Passed:** nothing blocks."

    by_severity = Counter(finding.severity for finding in result.findings)
    rows = [
        ("Files scanned", result.files_scanned),
        ("Blocking problems", len(result.findings)),
        *(
            (f"&nbsp;&nbsp;{severity.name.lower()}", by_severity[severity])
            for severity in sorted(Severity, reverse=True)
        ),
        ("Warnings", len(result.warnings)),
        ("Silenced by a comment", len(result.silenced)),
        ("Known problems (baseline)", len(result.known)),
        ("Outside the changed lines", len(result.outside_change)),
        ("Files that could not be scanned", len(result.failures)),
    ]
    table = ["| | Count |", "|---|---:|"]
    table += [f"| {label} | {number} |" for label, number in rows]
    return "\n".join(["## SecureLint", "", verdict, "", *table, ""])


def _note(level: str, finding: Finding, base: str, explanation: str | None) -> str:
    title = (
        f"{finding.rule_id} ({finding.severity.name.lower()}, "
        f"confidence {finding.confidence.name.lower()})"
    )
    properties = ",".join(
        [
            f"file={_property(_from_top(base, finding.path))}",
            f"line={finding.line}",
            f"col={finding.column}",
            f"title={_property(title)}",
        ]
    )
    message = finding.message
    if explanation is not None:
        # Below the finding, labelled; escaped with it, so it cannot end the
        # note or start a new one.
        message += f"\n\n{AI_LABEL}: {explanation}"
    return f"::{level} {properties}::{_data(message)}"


def _data(text: str) -> str:
    """Escape the message part of a note.

    ``%`` comes first, so the codes added for the other characters are not
    escaped a second time. A new line would end the note and let the rest
    of the text be read as a new one; escaped, it stays inside.
    """
    return text.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def _property(text: str) -> str:
    """Escape a value such as ``file=...``: also ``:`` and ``,``.

    Those two separate the values and end the list of values, so a file
    name holding them could otherwise set the line, the title or the
    message of the note.
    """
    return _data(text).replace(":", "%3A").replace(",", "%2C")


def _from_top(base: str, path: str) -> str:
    """Return a path from the top of the project, as GitHub expects."""
    return f"{base}/{path}" if base else path


def _count(number: int, noun: str) -> str:
    return f"{number} {noun}" if number == 1 else f"{number} {noun}s"
