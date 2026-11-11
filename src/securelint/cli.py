"""Command-line interface for SecureLint."""

import argparse
from collections.abc import Sequence

from securelint import __version__


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
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the command line and return the process exit code.

    ``argv`` defaults to ``sys.argv[1:]``. Tests pass a list instead, so they
    can call this function directly without starting a new process.
    """
    parser = build_parser()
    parser.parse_args(argv)
    parser.print_help()
    return 0
