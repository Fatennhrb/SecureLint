"""Command-line interface for SecureLint."""

import argparse
import sys
from collections.abc import Sequence
from dataclasses import dataclass
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
from securelint.config import Config, ConfigError, load_config
from securelint.engine import Rule, ScanResult, scan
from securelint.html_report import format_html
from securelint.policy import apply_policy
from securelint.report import format_json, format_text
from securelint.rules import ALL_RULES

# The report formats `scan --format` accepts, and the function behind each.
FORMATS = {"text": format_text, "json": format_json, "html": format_html}

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
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the command line and return the process exit code.

    ``argv`` defaults to ``sys.argv[1:]``. Tests pass a list instead, so they
    can call this function directly without starting a new process.
    """
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "scan":
        return _run_scan(args.path, args.format, use_baseline=not args.no_baseline)
    if args.command == "baseline":
        return _run_baseline(args.path)
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


def _run_scan(target: Path, report_format: str, *, use_baseline: bool) -> int:
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

    result = _scan_project(target, project)
    if result is None:
        return EXIT_ERROR
    if known is not None:
        result = split_known(result, known)
    # Last of all: the policy only sorts what is left into "blocks" and
    # "warning". Known problems are neither.
    result = apply_policy(result, project.config.policy)

    # The report goes to standard output; everything about the scan itself
    # goes to standard error, so `securelint scan > report.txt` stays clean.
    print(FORMATS[report_format](result))
    _print_failures(result)

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


def _run_baseline(place: Path) -> int:
    project = _find_project(place)
    if project is None:
        return EXIT_ERROR
    if not place.exists():
        _print_error(f"error: no such file or directory: {place}")
        return EXIT_ERROR

    # Always the whole project, wherever the command was started: a
    # baseline written from one folder would drop the known problems of
    # all the others.
    result = _scan_project(project.root, project)
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
        config = load_config(target, [rule.rule_id for rule in RULES])
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


def _scan_project(target: Path, project: _Project) -> ScanResult | None:
    """Scan ``target`` with the project's settings; None after an error."""
    config = project.config
    rules = [rule for rule in RULES if rule.rule_id not in config.ignore]
    try:
        return scan(target, rules, config.exclude, project.root)
    except OSError as error:
        # The target does not exist, or a directory cannot be opened.
        _print_error(f"error: {error}")
        return None


def _print_failures(result: ScanResult) -> None:
    for failure in result.failures:
        place = failure.relative_path
        if failure.line is not None:
            place += f":{failure.line}"
        _print_error(f"cannot scan {place}: {failure.message}")


def _print_error(message: str) -> None:
    print(f"securelint: {message}", file=sys.stderr)
