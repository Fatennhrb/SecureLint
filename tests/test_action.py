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


def test_the_action_has_its_scripts() -> None:
    assert set(run_scripts()) == {
        "Install SecureLint",
        "Install Trivy",
        "Run Trivy",
        "Scan with SecureLint",
    }


def trivy_pins() -> dict[str, str]:
    text = ACTION.read_text(encoding="utf-8")
    return dict(re.findall(r"^\s*(TRIVY_\w+):\s*\"?([\w.]+)\"?", text, re.MULTILINE))


def test_trivy_is_pinned_to_a_release_after_the_advisories() -> None:
    pins = trivy_pins()
    version = tuple(int(part) for part in pins["TRIVY_VERSION"].split("."))

    # 0.69.4 was the compromised release (CVE-2026-33634); 0.72.0 fixes the
    # last advisory published before this pin was chosen.
    assert version >= (0, 72, 0)
    for key in ("TRIVY_SHA256_X64", "TRIVY_SHA256_ARM64"):
        assert re.fullmatch(r"[0-9a-f]{64}", pins[key]), key


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


def test_ci_runs_the_action_and_pins_every_other_action() -> None:
    workflow = ACTION.parent / ".github" / "workflows" / "ci.yml"
    uses = re.findall(
        r"^\s*(?:- )?uses:\s*(\S+)", workflow.read_text(encoding="utf-8"), re.MULTILINE
    )

    # "./" is the Action in the same commit, so it needs no pin.
    assert "./" in uses
    for reference in uses:
        if reference != "./":
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
    trivy: str = "false",
    runner_temp: Path | None = None,
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
        "TRIVY": trivy,
        "RUNNER_TEMP": str(runner_temp or workspace),
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


@needs_bash
@pytest.mark.parametrize("value", ["yes", ""])
def test_script_refuses_a_wrong_trivy_value(tmp_path: Path, value: str) -> None:
    completed = run_scan_script(tmp_path, trivy=value)

    assert completed.returncode == 2
    assert "trivy must be" in completed.stdout


def fake_program(folder: Path, name: str, script: str) -> None:
    """Write a small shell script that stands in for a real program."""
    folder.mkdir(parents=True, exist_ok=True)
    program = folder / name
    program.write_text("#!/bin/sh\n" + textwrap.dedent(script), encoding="utf-8")
    program.chmod(0o755)


def run_step(
    name: str, workspace: Path, runner_temp: Path, **values: str
) -> subprocess.CompletedProcess[str]:
    assert BASH is not None
    environment = dict(os.environ) | {"RUNNER_TEMP": str(runner_temp)} | values
    return subprocess.run(  # noqa: S603 (bash, a list of arguments)
        [BASH, "-c", run_scripts()[name]],
        cwd=workspace,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )


@needs_bash
def test_trivy_is_only_installed_on_linux(tmp_path: Path) -> None:
    completed = run_step(
        "Install Trivy", tmp_path, tmp_path, RUNNER_OS="macOS", RUNNER_ARCH="ARM64"
    )

    assert completed.returncode == 2
    assert "only be used on Linux runners" in completed.stdout


@needs_bash
def test_a_download_with_the_wrong_checksum_never_runs(tmp_path: Path) -> None:
    # A "curl" that writes something else than the real Trivy archive.
    tools = tmp_path / "tools"
    fake_program(
        tools,
        "curl",
        """
        while [ $# -gt 0 ]; do
          if [ "$1" = "--output" ]; then echo "not trivy" > "$2"; fi
          shift
        done
        """,
    )
    path = f"{tools}{os.pathsep}{os.environ['PATH']}"

    completed = run_step(
        "Install Trivy",
        tmp_path,
        tmp_path,
        PATH=path,
        RUNNER_OS="Linux",
        RUNNER_ARCH="X64",
        **trivy_pins(),
    )

    assert completed.returncode == 2
    assert "does not have the expected checksum; it was not run" in completed.stdout
    assert list((tmp_path / "securelint-trivy").iterdir()) == []


@needs_bash
def test_the_trivy_report_reaches_the_scan(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "requirements.txt").write_text("requests==2.25.0\n", encoding="utf-8")
    report = {
        "SchemaVersion": 2,
        "Results": [
            {
                "Target": "requirements.txt",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2023-32681",
                        "PkgName": "requests",
                        "InstalledVersion": "2.25.0",
                        "Severity": "MEDIUM",
                    }
                ],
            }
        ],
    }
    # A "trivy" that writes a fixed report where it is asked to.
    fake_program(
        tmp_path / "securelint-trivy",
        "trivy",
        f"""
        while [ $# -gt 0 ]; do
          if [ "$1" = "--output" ]; then echo '{json.dumps(report)}' > "$2"; fi
          shift
        done
        """,
    )

    ran = run_step("Run Trivy", workspace, tmp_path, SCAN_PATH=".")
    completed = run_scan_script(workspace, trivy="true", runner_temp=tmp_path)

    assert ran.returncode == 0, ran.stdout
    assert completed.returncode == 1
    (note,) = notes(completed.stdout)
    assert note.startswith("::error file=requirements.txt,line=1,col=1,title=SL201")


@needs_bash
def test_a_failed_trivy_scan_stops(tmp_path: Path) -> None:
    fake_program(tmp_path / "securelint-trivy", "trivy", "exit 1\n")

    completed = run_step("Run Trivy", tmp_path, tmp_path, SCAN_PATH=".")

    assert completed.returncode == 2
    assert "Trivy could not complete its scan" in completed.stdout
