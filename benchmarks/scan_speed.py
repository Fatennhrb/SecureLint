"""Measure how fast SecureLint scans a large amount of real Python code.

Usage::

    python benchmarks/scan_speed.py              # Python's standard library
    python benchmarks/scan_speed.py some/folder  # any other folder
    python benchmarks/scan_speed.py --runs 10

With no folder, the standard library of the Python running the script is
scanned: hundreds of real files that every machine already has.

The scan is repeated and the fastest run is the one reported. Other
programs on the machine can only make a run slower, never faster, so the
fastest run is the closest to what the scanner itself costs.
"""

import argparse
import platform
import sysconfig
import time
from pathlib import Path

from securelint import __version__
from securelint.discovery import discover
from securelint.engine import scan
from securelint.rules import ALL_RULES


def main() -> int:
    parser = argparse.ArgumentParser(description="Measure SecureLint's scan speed.")
    parser.add_argument(
        "path",
        nargs="?",
        type=Path,
        default=Path(sysconfig.get_paths()["stdlib"]),
        help="folder to scan (default: Python's standard library)",
    )
    parser.add_argument(
        "--runs", type=int, default=5, help="number of scans to time (default: 5)"
    )
    args = parser.parse_args()
    if args.runs < 1:
        parser.error("--runs must be at least 1")

    files = discover(args.path)
    megabytes = sum(file.path.stat().st_size for file in files) / 1_000_000

    timings = []
    for _ in range(args.runs):
        start = time.perf_counter()
        result = scan(args.path, ALL_RULES)
        timings.append(time.perf_counter() - start)
    fastest = min(timings)

    print(f"SecureLint {__version__}, {len(ALL_RULES)} rules")
    print(f"Python {platform.python_version()} on {platform.platform()}")
    print(f"Scanned: {args.path}")
    print(f"Files:   {len(files)} ({megabytes:.1f} MB)")
    print(
        f"Parsed:  {result.files_scanned}, could not be parsed: {len(result.failures)}"
    )
    print(
        f"Runs:    {args.runs} (fastest {fastest:.2f} s, slowest {max(timings):.2f} s)"
    )
    print(f"Speed:   {len(files) / fastest:.0f} files per second")
    print(f"         {megabytes / fastest:.1f} MB per second")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
