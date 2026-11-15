"""Tests for the GitHub Action in action.yml.

An Action only truly runs on GitHub. These tests check what can be checked
without it: the safety rules of the file, and the scan script itself, run
with bash as GitHub would run it (on Linux and macOS only: on Windows,
"bash" may not be the bash GitHub uses).
"""

import json
import os
import re
import shutil
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

from securelint.cli import main

ACTION = Path(__file__).parent.parent / "action.yml"
BASH = shutil.which("bash")
GIT = shutil.which("git")

needs_bash = pytest.mark.skipif(
    BASH is None or sys.platform == "win32",
    reason="runs the script with bash, as GitHub does on Linux",
)


def run_scripts() -> dict[str, str]:
    """Return the script of each step, by the step's name."""
    lines = ACTION.read_text(encoding="utf-8").splitlines()
    scripts: dict[str, str] = {}
    name = ""
    index = 0
    while index < len(lines):
        line = lines[index]
        if line.strip().startswith("- name:"):
            name = line.split(":", 1)[1].strip()
        if line.strip() == "run: |":
            indent = len(line) - len(line.lstrip())
            body = []
            index += 1
            while index < len(lines) and (
                not lines[index].strip()
                or len(lines[index]) - len(lines[index].lstrip()) > indent
            ):
                body.append(lines[index])
                index += 1
            scripts[name] = textwrap.dedent("\n".join(body))
            continue
        index += 1
    return scripts


def test_the_action_has_both_scripts() -> None:
    assert set(run_scripts()) == {"Install SecureLint", "Scan with SecureLint"}


def test_no_value_is_written_into_a_script() -> None:
    # "${{ ... }}" inside a script is replaced before the script runs, so a
    # crafted input or branch name would become code. Values must arrive
    # through environment variables instead.
    for name, script in run_scripts().items():
        assert "${{" not in script, name


def test_every_action_used_is_pinned_to_a_commit() -> None:
    # Real steps only, not the example in the comment at the top.
    uses = re.findall(
        r"^\s*(?:- )?uses:\s*(\S+)", ACTION.read_text(encoding="utf-8"), re.MULTILINE
    )

    assert uses
    for reference in uses:
        assert re.fullmatch(r"[\w.-]+/[\w./-]+@[0-9a-f]{40}", reference), reference


def test_the_actions_python_does_not_replace_the_jobs_python() -> None:
    text = ACTION.read_text(encoding="utf-8")

    assert "update-environment: false" in text


def test_double_dash_ends_the_options(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # The script relies on this: "scan --format github -- PATH".
    odd = tmp_path / "-odd"
    odd.mkdir()
    (odd / "app.py").write_text("eval(x)\n", encoding="utf-8")

    assert main(["scan", "--format", "json", "--", str(odd)]) == 1
    assert json.loads(capsys.readouterr().out)["summary"]["findings"] == 1


def run_scan_script(
    workspace: Path,
    *,
    path: str = ".",
    changed_only: str = "true",
    sarif_file: str = "",
    base_ref: str = "",
) -> subprocess.CompletedProcess[str]:
    assert BASH is not None
    environment = {
        key: value for key, value in os.environ.items() if key != "GITHUB_STEP_SUMMARY"
    }
    environment |= {
        "PYTHON": sys.executable,
        "SCAN_PATH": path,
        "CHANGED_ONLY": changed_only,
        "SARIF_FILE": sarif_file,
        "BASE_REF": base_ref,
    }
    return subprocess.run(  # noqa: S603 (bash, a list of arguments)
        [BASH, "-c", run_scripts()["Scan with SecureLint"]],
        cwd=workspace,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )


def notes(output: str) -> list[str]:
    return [line for line in output.splitlines() if line.startswith("::")]


@needs_bash
def test_script_on_clean_code_passes(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("print('safe')\n", encoding="utf-8")

    completed = run_scan_script(tmp_path)

    assert completed.returncode == 0, completed.stderr
    assert completed.stdout == "No problems found in 1 file.\n"


@needs_bash
def test_script_fails_when_something_blocks(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("eval(x)\n", encoding="utf-8")

    completed = run_scan_script(tmp_path)

    assert completed.returncode == 1
    assert notes(completed.stdout)[0].startswith("::error file=app.py,line=1,")


@needs_bash
def test_script_writes_a_sarif_report(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("eval(x)\n", encoding="utf-8")

    completed = run_scan_script(tmp_path, sarif_file="results.sarif")

    assert completed.returncode == 1
    document = json.loads((tmp_path / "results.sarif").read_text(encoding="utf-8"))
    assert [item["ruleId"] for item in document["runs"][0]["results"]] == ["SL101"]


@needs_bash
def test_script_scans_a_path_that_starts_with_a_dash(tmp_path: Path) -> None:
    (tmp_path / "-odd").mkdir()
    (tmp_path / "-odd" / "app.py").write_text("eval(x)\n", encoding="utf-8")

    completed = run_scan_script(tmp_path, path="-odd")

    assert completed.returncode == 1


@needs_bash
@pytest.mark.parametrize("value", ["yes", "", "TRUE"])
def test_script_refuses_a_wrong_changed_only_value(tmp_path: Path, value: str) -> None:
    completed = run_scan_script(tmp_path, changed_only=value)

    assert completed.returncode == 2
    assert "changed-only must be" in completed.stdout


@needs_bash
def test_script_reports_a_missing_path(tmp_path: Path) -> None:
    completed = run_scan_script(tmp_path, path="missing", sarif_file="out.sarif")

    assert completed.returncode == 2
    assert "no such file or directory" in completed.stderr


def git(repo: Path, *arguments: str) -> None:
    assert GIT is not None
    subprocess.run(  # noqa: S603 (Git, a list of arguments)
        [
            GIT,
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.invalid",
            "-c",
            "commit.gpgsign=false",
            *arguments,
        ],
        cwd=repo,
        check=True,
        capture_output=True,
    )


@pytest.fixture
def pull_request(tmp_path: Path) -> Path:
    """A repository checked out the way a pull request is.

    main holds one old problem; the pull request adds a new one. As after
    actions/checkout with fetch-depth 0, the target branch is known as
    origin/main.
    """
    repo = tmp_path / "repo"
    repo.mkdir()
    git(repo, "init", "--quiet", "--initial-branch=main")
    (repo / "app.py").write_text("eval(old)\n", encoding="utf-8")
    git(repo, "add", ".")
    git(repo, "commit", "--quiet", "-m", "first")
    git(repo, "update-ref", "refs/remotes/origin/main", "HEAD")
    git(repo, "checkout", "--quiet", "-b", "feature")
    (repo / "app.py").write_text("eval(old)\neval(new)\n", encoding="utf-8")
    git(repo, "commit", "--quiet", "-am", "add a problem")
    return repo


@needs_bash
@pytest.mark.skipif(GIT is None, reason="git is not installed")
def test_script_on_a_pull_request_reports_only_its_lines(pull_request: Path) -> None:
    completed = run_scan_script(
        pull_request, base_ref="main", sarif_file="results.sarif"
    )

    assert completed.returncode == 1
    (note,) = notes(completed.stdout)
    assert note.startswith("::error file=app.py,line=2,")
    assert "Outside the changed lines: 1." in completed.stdout
    # The SARIF report holds the whole scan.
    document = json.loads((pull_request / "results.sarif").read_text(encoding="utf-8"))
    assert len(document["runs"][0]["results"]) == 2


@needs_bash
@pytest.mark.skipif(GIT is None, reason="git is not installed")
def test_script_on_a_pull_request_can_report_everything(pull_request: Path) -> None:
    completed = run_scan_script(pull_request, base_ref="main", changed_only="false")

    assert completed.returncode == 1
    assert len(notes(completed.stdout)) == 2


@needs_bash
@pytest.mark.skipif(GIT is None, reason="git is not installed")
def test_script_with_an_unknown_target_branch_stops(pull_request: Path) -> None:
    completed = run_scan_script(pull_request, base_ref="no-such-branch")

    assert completed.returncode == 2
    assert "cannot find where this branch left" in completed.stderr
