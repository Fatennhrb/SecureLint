"""Tests for the release workflow: what it may do, and what it may not.

Publishing only truly runs on GitHub. These tests check the rules the file
must keep, and run its version check with bash as GitHub would.
"""

import os
import re
import shutil
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

WORKFLOWS = Path(__file__).parent.parent / ".github" / "workflows"
RELEASE = WORKFLOWS / "release.yml"
BASH = shutil.which("bash")

needs_bash = pytest.mark.skipif(
    BASH is None or sys.platform == "win32",
    reason="runs the script with bash, as GitHub does on Linux",
)

_USES = re.compile(r"^\s*(?:- )?uses:\s*(\S+)", re.MULTILINE)
_PINNED = re.compile(r"[\w.-]+/[\w./-]+@[0-9a-f]{40}")


def text() -> str:
    return RELEASE.read_text(encoding="utf-8")


def jobs() -> dict[str, str]:
    """Return the text of each job, by the job's id."""
    body = text().split("\njobs:\n", 1)[1]
    parts = re.split(r"^  ([\w-]+):\n", body, flags=re.MULTILINE)
    return dict(zip(parts[1::2], parts[2::2], strict=True))


def run_scripts(source: str) -> dict[str, str]:
    """Return the script of each step that has one, by the step's name."""
    lines = source.splitlines()
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


@pytest.mark.parametrize("workflow", sorted(WORKFLOWS.glob("*.yml")), ids=str)
def test_every_action_in_every_workflow_is_pinned(workflow: Path) -> None:
    uses = _USES.findall(workflow.read_text(encoding="utf-8"))

    for reference in uses:
        if reference != "./":
            assert _PINNED.fullmatch(reference), reference


def test_the_jobs_and_their_order() -> None:
    found = jobs()

    assert list(found) == ["build", "testpypi", "pypi"]
    assert "needs: build" in found["testpypi"]
    # PyPI only after TestPyPI took the same files, and only for a tag.
    assert "needs: testpypi" in found["pypi"]
    assert "if: github.ref_type == 'tag'" in found["pypi"]


def test_only_the_publishing_jobs_can_prove_who_they_are() -> None:
    before_jobs = text().split("\njobs:\n", 1)[0]
    found = jobs()

    assert "permissions:\n  contents: read" in before_jobs
    assert "id-token" not in before_jobs
    assert "id-token" not in found["build"]
    for job in ("testpypi", "pypi"):
        assert "id-token: write" in found[job]


def test_each_publishing_job_has_its_own_environment() -> None:
    found = jobs()

    assert "name: testpypi" in found["testpypi"]
    assert "repository-url: https://test.pypi.org/legacy/" in found["testpypi"]
    assert "name: pypi" in found["pypi"]
    assert "repository-url" not in found["pypi"]


def test_the_publish_action_has_the_sigstore_fix() -> None:
    # GHSA-5xjx-3w67-w9x9 (critical) is fixed from v1.14.3.
    versions = re.findall(r"gh-action-pypi-publish@[0-9a-f]{40} # v([\d.]+)", text())

    assert len(versions) == 2
    for version in versions:
        assert tuple(map(int, version.split("."))) >= (1, 14, 3)


def test_no_value_is_written_into_a_script() -> None:
    for name, script in run_scripts(text()).items():
        assert "${{" not in script, name


def check_version(
    dist: Path, ref_type: str, tag: str
) -> subprocess.CompletedProcess[str]:
    assert BASH is not None
    script = run_scripts(text())["Check that the version matches the tag"]
    return subprocess.run(  # noqa: S603 (bash, a list of arguments)
        [BASH, "-c", script],
        cwd=dist.parent,
        env=dict(os.environ) | {"REF_TYPE": ref_type, "TAG": tag},
        capture_output=True,
        text=True,
        check=False,
    )


@pytest.fixture
def dist(tmp_path: Path) -> Path:
    folder = tmp_path / "dist"
    folder.mkdir()
    (folder / "securelint-1.0.0-py3-none-any.whl").write_bytes(b"")
    return folder


@needs_bash
@pytest.mark.parametrize(("ref_type", "tag"), [("tag", "v1.0.0"), ("branch", "main")])
def test_a_matching_tag_or_a_rehearsal_passes(
    dist: Path, ref_type: str, tag: str
) -> None:
    completed = check_version(dist, ref_type, tag)

    assert completed.returncode == 0, completed.stdout
    assert "Package version: 1.0.0" in completed.stdout


@needs_bash
@pytest.mark.parametrize("tag", ["v0.9.0", "v1.0.0rc1", "1.0.0"])
def test_a_tag_that_does_not_match_stops_the_release(dist: Path, tag: str) -> None:
    completed = check_version(dist, "tag", tag)

    assert completed.returncode == 1
    assert f"The tag {tag} does not match the package version 1.0.0" in (
        completed.stdout
    )
