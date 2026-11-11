"""Command-line interface for SecureLint."""

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

from securelint import __version__
from securelint.engine import Rule, scan
from securelint.report import format_text

# Exit codes are how a CI job reads the result, so they are part of the
# tool's public behaviour and must stay stable.
EXIT_CLEAN = 0
"""The scan finished and found no problems."""

EXIT_FINDINGS = 1
"""The scan finished and found at least one problem."""

EXIT_ERROR = 2
"""The scan could not be completed, so its result cannot be trusted.

This is also the code argparse uses for a wrong command line.
"""

# The rules every scan runs. Empty for now: the first real rules are the
# next milestone.
RULES: tuple[Rule, ...] = ()


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
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the command line and return the process exit code.

    ``argv`` defaults to ``sys.argv[1:]``. Tests pass a list instead, so they
    can call this function directly without starting a new process.
    """
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "scan":
        return _run_scan(args.path)
    parser.print_help()
    return EXIT_CLEAN


def _run_scan(target: Path) -> int:
    try:
        result = scan(target, RULES)
    except OSError as error:
        # The target does not exist, or a directory cannot be opened.
        _print_error(f"error: {error}")
        return EXIT_ERROR

    # The report goes to standard output; everything about the scan itself
    # goes to standard error, so `securelint scan > report.txt` stays clean.
    print(format_text(result))
    for failure in result.failures:
        place = failure.relative_path
        if failure.line is not None:
            place += f":{failure.line}"
        _print_error(f"cannot scan {place}: {failure.message}")
    if not RULES:
        _print_error("note: no detection rules exist yet, so nothing was checked")

    if result.failures:
        # A file nobody could read is not a clean file. Reporting success
        # here would let a problem pass unseen.
        return EXIT_ERROR
    return EXIT_FINDINGS if result.findings else EXIT_CLEAN


def _print_error(message: str) -> None:
    print(f"securelint: {message}", file=sys.stderr)
