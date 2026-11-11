"""Tests for the command-line entry points."""

import subprocess
import sys

import pytest

from securelint import __version__
from securelint.cli import main


def test_version_flag_prints_version(capsys: pytest.CaptureFixture[str]) -> None:
    # argparse's "version" action prints the version, then raises SystemExit(0).
    with pytest.raises(SystemExit) as exc_info:
        main(["--version"])

    assert exc_info.value.code == 0
    assert capsys.readouterr().out.strip() == f"securelint {__version__}"


def test_no_arguments_prints_usage(capsys: pytest.CaptureFixture[str]) -> None:
    assert main([]) == 0
    assert "usage: securelint" in capsys.readouterr().out


def test_unknown_option_is_rejected(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc_info:
        main(["--no-such-option"])

    assert exc_info.value.code == 2
    assert "unrecognized arguments" in capsys.readouterr().err


def test_package_runs_as_a_module() -> None:
    # Starts a real `python -m securelint` process. This checks the wiring the
    # unit tests above can't: the installed package and its __main__.py.
    result = subprocess.run(
        [sys.executable, "-m", "securelint", "--version"],
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0
    assert result.stdout.strip() == f"securelint {__version__}"
