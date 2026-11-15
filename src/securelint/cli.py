"""Command-line interface for SecureLint."""

import argparse
import os
import sys
from collections.abc import Sequence
from dataclasses import dataclass, replace
from pathlib import Path

from securelint import __version__
from securelint.baseline import (
    BASELINE_FILE_NAME,
    BaselineError,
    count_no_longer_found,
    find_project_root,
    load_baseline,
    save_baseline,
    split_known,
)
from securelint.changes import (
    ChangesError,
    find_changed_lines,
    split_outside_change,
)
from securelint.config import Config, ConfigError, load_config
from securelint.engine import Rule, ScanResult, scan
from securelint.explain import Explainer, add_explanations
from securelint.github_report import format_github, format_step_summary
from securelint.html_report import format_html
from securelint.model import Finding
from securelint.policy import apply_policy
from securelint.report import format_json, format_text
from securelint.rules import ALL_RULES
from securelint.sarif_report import format_sarif
from securelint.trivy import TITLES as TRIVY_RULES
from securelint.trivy import TrivyReportError, read_trivy_report

# The report formats `scan --format` accepts, and the function behind each.
FORMATS = {
    "text": format_text,
    "json": format_json,
    "html": format_html,
    "sarif": format_sarif,
    "github": format_github,
}

# Exit codes are how a CI job reads the result, so they are part of the
# tool's public behaviour and must stay stable.
EXIT_CLEAN = 0
"""The scan finished and nothing blocks (there may be warnings)."""

EXIT_FINDINGS = 1
"""The scan finished and found at least one problem that blocks."""

EXIT_ERROR = 2
"""The scan could not be completed, so its result cannot be trusted.

This is also the code argparse uses for a wrong command line.
"""

# The rules every scan runs. A module-level name so tests can replace it.
RULES: tuple[Rule, ...] = ALL_RULES


def build_parser() -> argparse.ArgumentParser:
    """Create the argument parser for the ``securelint`` command."""
    parser = argparse.ArgumentParser(
        # Set explicitly so help text says "securelint" even when the tool is
        # started with ``python -m securelint``.
        prog="securelint",
        description="Scan Python projects for security issues.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    commands = parser.add_subparsers(dest="command", title="commands")
    scan_parser = commands.add_parser(
        "scan",
        help="scan a file or directory",
        description="Scan a Python file, or every Python file in a directory.",
    )
    scan_parser.add_argument(
        "path",
        nargs="?",
        type=Path,
        default=Path(),
        help="file or directory to scan (default: the current directory)",
    )
    scan_parser.add_argument(
        "--format",
        choices=sorted(FORMATS),
        default="text",
        help="how to write the report (default: text)",
    )
    scan_parser.add_argument(
        "--no-baseline",
        action="store_true",
        help="report every finding, including those listed in the baseline file",
    )
    scan_parser.add_argument(
        "--explain",
        action="store_true",
        help=(
            "add a short explanation, written by the project's AI provider, "
            "to the findings shown (never changes the result)"
        ),
    )
    scan_parser.add_argument(
        "--changed-since",
        metavar="BRANCH",
        help=(
            "report only findings on lines changed since the current branch "
            "left BRANCH (for example: main)"
        ),
    )
    scan_parser.add_argument(
        "--trivy-report",
        metavar="FILE",
        type=Path,
        help=(
            "also report the problems in this Trivy JSON report "
            "(from `trivy fs --format json` on the same folder)"
        ),
    )
    baseline_parser = commands.add_parser(
        "baseline",
        help="record today's findings as known",
        description=(
            "Scan the whole project and record its findings in "
            f"{BASELINE_FILE_NAME}. Later scans then report only new findings."
        ),
    )
    baseline_parser.add_argument(
        "path",
        nargs="?",
        type=Path,
        default=Path(),
        help="any place inside the project (default: the current directory)",
    )
    baseline_parser.add_argument(
        "--trivy-report",
        metavar="FILE",
        type=Path,
        help=(
            "also report the problems in this Trivy JSON report "
            "(from `trivy fs --format json` on the top of the project)"
        ),
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the command line and return the process exit code.

    ``argv`` defaults to ``sys.argv[1:]``. Tests pass a list instead, so they
    can call this function directly without starting a new process.
    """
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "scan":
        return _run_scan(
            args.path,
            args.format,
            use_baseline=not args.no_baseline,
            changed_since=args.changed_since,
            trivy_report=args.trivy_report,
            explain=args.explain,
        )
    if args.command == "baseline":
        return _run_baseline(args.path, args.trivy_report)
    parser.print_help()
    return EXIT_CLEAN


@dataclass(frozen=True, slots=True)
class _Project:
    """What is known about the project before it is scanned."""

    config: Config
    root: Path
    """The top directory of the project, as a full path."""

    @property
    def baseline_path(self) -> Path:
        return self.root / BASELINE_FILE_NAME


def _run_scan(
    target: Path,
    report_format: str,
    *,
    use_baseline: bool,
    changed_since: str | None = None,
    trivy_report: Path | None = None,
    explain: bool = False,
) -> int:
    project = _find_project(target)
    if project is None:
        return EXIT_ERROR

    known = None
    if use_baseline:
        try:
            known = load_baseline(project.baseline_path)
        except BaselineError as error:
            # A baseline that cannot be trusted stops the scan, like settings
            # that cannot be trusted: it decides what is shown as new.
            _print_error(f"error: {error}")
            return EXIT_ERROR
        if known is not None:
            _print_error(f"using baseline {project.baseline_path}")

    result = _scan_project(target, project, trivy_report)
    if result is None:
        return EXIT_ERROR
    if known is not None:
        result = split_known(result, known)
    if changed_since is not None:
        try:
            changes = find_changed_lines(target, changed_since)
        except ChangesError as error:
            # Reporting nothing here would look like a clean change.
            _print_error(f"error: {error}")
            return EXIT_ERROR
        _print_error(
            f"reporting only lines changed since {changed_since} "
            f"(compared with commit {changes.merge_base[:12]})"
        )
        result = split_outside_change(result, changes, target)
    # Last of all: the policy only sorts what is left into "blocks" and
    # "warning". Known problems are neither.
    result = apply_policy(result, project.config.policy)
    # Only after the decision: an explanation can never change it.
    if explain:
        result = _explain(result, project.config)

    # The report goes to standard output; everything about the scan itself
    # goes to standard error, so `securelint scan > report.txt` stays clean.
    print(FORMATS[report_format](result))
    _print_failures(result)
    if report_format == "github":
        _write_step_summary(result)

    # Whether a known problem was fixed can only be told when the whole
    # project was scanned: after a scan of one folder, the known problems
    # of the other folders are simply not looked at.
    if known is not None and target.resolve() == project.root:
        gone = count_no_longer_found(result, known)
        if gone:
            entries = "1 entry is" if gone == 1 else f"{gone} entries are"
            _print_error(
                f"{entries} in the baseline but no longer found; "
                "run `securelint baseline` to write it again"
            )

    if result.failures:
        # A file nobody could read is not a clean file. Reporting success
        # here would let a problem pass unseen.
        return EXIT_ERROR
    return EXIT_FINDINGS if result.findings else EXIT_CLEAN


def _run_baseline(place: Path, trivy_report: Path | None = None) -> int:
    project = _find_project(place)
    if project is None:
        return EXIT_ERROR
    if not place.exists():
        _print_error(f"error: no such file or directory: {place}")
        return EXIT_ERROR

    # Always the whole project, wherever the command was started: a
    # baseline written from one folder would drop the known problems of
    # all the others.
    result = _scan_project(project.root, project, trivy_report)
    if result is None:
        return EXIT_ERROR
    _print_failures(result)
    if result.failures:
        # Nothing is written: a baseline must not be made from a scan that
        # skipped files.
        _print_error(
            "error: the baseline was not written, because the scan is incomplete"
        )
        return EXIT_ERROR

    save_baseline(project.baseline_path, result.findings)
    number = len(result.findings)
    problems = "1 known problem" if number == 1 else f"{number} known problems"
    print(f"Saved {problems} to {project.baseline_path}")
    return EXIT_CLEAN


def _find_project(target: Path) -> _Project | None:
    """Read the settings and find the top of the project; None after an error."""
    try:
        config = load_config(target, [*(rule.rule_id for rule in RULES), *TRIVY_RULES])
    except ConfigError as error:
        # Settings that cannot be trusted stop the scan: guessing what
        # they meant could leave out files the user wanted checked.
        _print_error(f"error: {error}")
        return None
    if config.source is not None:
        # Settings can make a scan look at less, so their use is never silent.
        _print_error(f"using settings from {config.source}")
        return _Project(config, config.source.parent)
    return _Project(config, find_project_root(target))


def _scan_project(
    target: Path, project: _Project, trivy_report: Path | None = None
) -> ScanResult | None:
    """Scan ``target`` with the project's settings; None after an error.

    With ``trivy_report``, the dependency problems Trivy found in the same
    folder are added to the code's findings.
    """
    config = project.config
    rules = [rule for rule in RULES if rule.rule_id not in config.ignore]
    try:
        result = scan(target, rules, config.exclude, project.root)
    except OSError as error:
        # The target does not exist, or a directory cannot be opened.
        _print_error(f"error: {error}")
        return None
    if trivy_report is None:
        return result
    if not target.is_dir():
        _print_error("error: --trivy-report needs a folder to scan, not a file")
        return None
    try:
        dependencies = read_trivy_report(
            trivy_report, target, project.root, config.ignore
        )
    except TrivyReportError as error:
        # A report that cannot be read is not a report without problems.
        _print_error(f"error: {error}")
        return None
    _print_error(f"using Trivy report {trivy_report}")
    findings = sorted([*result.findings, *dependencies], key=_sort_key)
    # The files the report has problems in were checked too, through
    # Trivy: "3 problems found in 1 file" would be wrong when they are in
    # three files.
    checked_by_trivy = len({finding.path for finding in dependencies})
    return replace(
        result,
        findings=tuple(findings),
        files_scanned=result.files_scanned + checked_by_trivy,
    )


def make_explainer(config: Config) -> Explainer | None:
    """Return the explainer the project's settings ask for; None if none.

    No AI provider can be set up yet, so this always returns None.
    """
    return None


def _explain(result: ScanResult, config: Config) -> ScanResult:
    explainer = make_explainer(config)
    if explainer is None:
        _print_error("no AI provider is set up yet; no explanations were added")
        return result
    result, problems = add_explanations(result, explainer)
    for problem in problems:
        _print_error(problem)
    return result


def _write_step_summary(result: ScanResult) -> None:
    """Add a summary to the job's result page, when GitHub Actions gives one.

    GitHub names the file in the GITHUB_STEP_SUMMARY variable. Outside
    GitHub Actions there is none, and nothing is written.
    """
    path = os.environ.get("GITHUB_STEP_SUMMARY")
    if not path:
        return
    try:
        with Path(path).open("a", encoding="utf-8") as summary:
            summary.write(format_step_summary(result))
    except OSError as error:
        # The report itself was printed; a missing summary does not change
        # the result, so it does not change the exit code either.
        _print_error(f"cannot write the job summary: {error}")


def _print_failures(result: ScanResult) -> None:
    for failure in result.failures:
        place = failure.relative_path
        if failure.line is not None:
            place += f":{failure.line}"
        _print_error(f"cannot scan {place}: {failure.message}")


def _sort_key(finding: Finding) -> tuple[str, int, int, str]:
    return (finding.path, finding.line, finding.column, finding.rule_id)


def _print_error(message: str) -> None:
    print(f"securelint: {message}", file=sys.stderr)
