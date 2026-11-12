"""Check that the benchmark script still runs.

The speed itself is not tested: it depends on the machine, and a test that
fails on a slow day teaches nothing.
"""

import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent


def test_benchmark_script_runs_and_reports_a_speed() -> None:
    result = subprocess.run(
        [sys.executable, "benchmarks/scan_speed.py", "tests/corpus", "--runs", "1"],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert "Files:   7 (" in result.stdout
    assert "Parsed:  7, could not be parsed: 0" in result.stdout
    assert "files per second" in result.stdout


def test_benchmark_script_rejects_zero_runs() -> None:
    result = subprocess.run(
        [sys.executable, "benchmarks/scan_speed.py", "tests/corpus", "--runs", "0"],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 2
    assert "--runs must be at least 1" in result.stderr
