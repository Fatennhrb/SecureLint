"""Tests for reporting only the lines a change touched.

These tests build small real Git repositories, so they need the ``git``
program. Each repository is created in a temporary folder with its own
settings; nothing outside it is touched.
"""

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest

from securelint.changes import (
    ChangedLines,
    ChangesError,
    _parse_diff,
    _unquote,
    find_changed_lines,
)
from securelint.cli import main

GIT = shutil.which("git")
needs_git = pytest.mark.skipif(GIT is None, reason="git is not installed")

OLD_CODE = b"import os\n\nos.system(old_command)\n"


def git(repo: Path, *arguments: str) -> None:
    assert GIT is not None
    subprocess.run(  # noqa: S603 (Git, a list of arguments, no shell)
        [
            GIT,
            # Settings for this test repository only.
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.invalid",
            "-c",
            "commit.gpgsign=false",
            "-c",
            "core.autocrlf=false",
            *arguments,
        ],
        cwd=repo,
        check=True,
        capture_output=True,
    )


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    """A repository whose main branch has one old problem, on a new branch."""
    root = tmp_path / "repo"
    root.mkdir()
    git(root, "init", "--quiet", "--initial-branch=main")
    (root / "app.py").write_bytes(OLD_CODE)
    (root / "lib").mkdir()
    (root / "lib" / "tools.py").write_bytes(b"def helper():\n    return 1\n")
    git(root, "add", ".")
    git(root, "commit", "--quiet", "-m", "first")
    git(root, "checkout", "--quiet", "-b", "feature")
    return root


def changed(repo: Path) -> dict[str, frozenset[int] | None]:
    """Return the changed lines since main, keyed by path from the repository."""
    result = find_changed_lines(repo, "main")
    top = repo.resolve()
    return {
        path.relative_to(top).as_posix(): lines for path, lines in result.files.items()
    }


@needs_git
def test_nothing_changed(repo: Path) -> None:
    assert changed(repo) == {}


@needs_git
def test_added_lines_of_a_committed_change(repo: Path) -> None:
    (repo / "app.py").write_bytes(OLD_CODE + b"os.system(new_command)\nx = 1\n")
    git(repo, "commit", "--quiet", "-am", "add lines")

    assert changed(repo) == {"app.py": frozenset({4, 5})}


@needs_git
def test_changes_not_committed_yet_count(repo: Path) -> None:
    (repo / "app.py").write_bytes(b"import os\n\nos.system(edited_command)\n")

    assert changed(repo) == {"app.py": frozenset({3})}


@needs_git
def test_a_new_tracked_file_is_changed_in_full(repo: Path) -> None:
    (repo / "lib" / "new.py").write_bytes(b"a = 1\nb = 2\nc = 3\n")
    git(repo, "add", ".")
    git(repo, "commit", "--quiet", "-m", "new file")

    assert changed(repo) == {"lib/new.py": frozenset({1, 2, 3})}


@needs_git
def test_a_file_git_does_not_track_is_changed_in_full(repo: Path) -> None:
    (repo / "scratch.py").write_bytes(b"eval(x)\n")

    assert changed(repo) == {"scratch.py": None}


@needs_git
def test_ignored_files_are_not_changes(repo: Path) -> None:
    (repo / ".gitignore").write_bytes(b"build/\n")
    git(repo, "add", ".gitignore")
    git(repo, "commit", "--quiet", "-m", "ignore build")
    (repo / "build").mkdir()
    (repo / "build" / "out.py").write_bytes(b"eval(x)\n")

    assert "build/out.py" not in changed(repo)


@needs_git
def test_deleted_lines_leave_nothing_to_report(repo: Path) -> None:
    (repo / "app.py").write_bytes(b"import os\n")
    git(repo, "commit", "--quiet", "-am", "remove lines")

    # The file changed, but no line of the new file is new.
    assert changed(repo) == {"app.py": frozenset()}


@needs_git
def test_a_deleted_file_leaves_nothing(repo: Path) -> None:
    git(repo, "rm", "--quiet", "lib/tools.py")
    git(repo, "commit", "--quiet", "-m", "remove file")

    assert changed(repo) == {}


@needs_git
def test_commits_on_main_after_the_branch_started_do_not_count(repo: Path) -> None:
    git(repo, "checkout", "--quiet", "main")
    (repo / "lib" / "tools.py").write_bytes(b"def helper():\n    return 2\n")
    git(repo, "commit", "--quiet", "-am", "change on main")
    git(repo, "checkout", "--quiet", "feature")

    # Compared with where the branch left main, not with main today.
    assert changed(repo) == {}


@needs_git
def test_works_from_a_folder_inside_the_repository(repo: Path) -> None:
    (repo / "app.py").write_bytes(OLD_CODE + b"x = 1\n")

    result = find_changed_lines(repo / "lib", "main")

    assert result.files == {(repo / "app.py").resolve(): frozenset({4})}


@needs_git
def test_result_remembers_the_branch_and_the_commit(repo: Path) -> None:
    result = find_changed_lines(repo, "main")

    assert result.base == "main"
    assert len(result.merge_base) == 40


@needs_git
def test_an_unknown_branch_is_an_error(repo: Path) -> None:
    with pytest.raises(ChangesError, match="cannot find where this branch left 'nope'"):
        find_changed_lines(repo, "nope")


@needs_git
def test_a_folder_outside_git_is_an_error(tmp_path: Path) -> None:
    outside = tmp_path / "not-a-repo"
    outside.mkdir()

    with pytest.raises(ChangesError, match="needs a Git repository"):
        find_changed_lines(outside, "main")


@pytest.mark.parametrize("base", ["", "-p", "--output=stolen.txt"])
def test_a_name_that_git_would_read_as_an_option_is_refused(
    tmp_path: Path, base: str
) -> None:
    # Refused before Git is even started.
    with pytest.raises(ChangesError, match="is not a branch or commit name"):
        find_changed_lines(tmp_path, base)


def test_missing_git_is_an_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(shutil, "which", lambda name: None)

    with pytest.raises(ChangesError, match="needs Git, which was not found"):
        find_changed_lines(tmp_path, "main")


def test_parse_diff_reads_hunks(tmp_path: Path) -> None:
    diff = (
        b"diff --git a/app.py b/app.py\n"
        b"--- a/app.py\n"
        b"+++ b/app.py\n"
        b"@@ -3 +3 @@\n"
        b"-old\n"
        b"+new\n"
        b"@@ -10,0 +11,2 @@\n"
        b"+added one\n"
        b"+added two\n"
        b"@@ -20,2 +21,0 @@\n"
        b"-removed one\n"
        b"-removed two\n"
    )

    assert _parse_diff(diff, tmp_path) == {(tmp_path / "app.py").resolve(): {3, 11, 12}}


def test_an_added_line_that_looks_like_a_file_name_is_read_as_a_line(
    tmp_path: Path,
) -> None:
    # The added line is "++ b/other.py"; in the diff it starts with "+++ ".
    diff = b"--- a/app.py\n+++ b/app.py\n@@ -0,0 +1,2 @@\n+++ b/other.py\n+x = 1\n"

    assert _parse_diff(diff, tmp_path) == {(tmp_path / "app.py").resolve(): {1, 2}}


def test_no_newline_note_is_not_a_line(tmp_path: Path) -> None:
    diff = (
        b"--- a/app.py\n"
        b"+++ b/app.py\n"
        b"@@ -1 +1,2 @@\n"
        b"-x = 1\n"
        b"\\ No newline at end of file\n"
        b"+x = 1\n"
        b"+y = 2\n"
        b"\\ No newline at end of file\n"
        b"--- a/next.py\n"
        b"+++ b/next.py\n"
        b"@@ -5 +5 @@\n"
        b"-a\n"
        b"+b\n"
    )

    assert _parse_diff(diff, tmp_path) == {
        (tmp_path / "app.py").resolve(): {1, 2},
        (tmp_path / "next.py").resolve(): {5},
    }


@pytest.mark.parametrize(
    ("written", "name"),
    [
        (b"b/app.py", "b/app.py"),
        (b'"b/with\\ttab.py"', "b/with\ttab.py"),
        (b'"b/quote\\"d.py"', 'b/quote"d.py'),
        (b'"b/back\\\\slash.py"', "b/back\\slash.py"),
        (b'"b/caf\\303\\251.py"', "b/café.py"),
        (b"b/caf\xc3\xa9.py", "b/café.py"),
    ],
)
def test_unquote_file_names(written: bytes, name: str) -> None:
    assert _unquote(written) == name


def test_changed_lines_contains(tmp_path: Path) -> None:
    changes = ChangedLines(
        base="main",
        merge_base="0" * 40,
        files={tmp_path / "a.py": frozenset({2}), tmp_path / "b.py": None},
    )

    assert changes.contains(tmp_path / "a.py", 2)
    assert not changes.contains(tmp_path / "a.py", 3)
    assert changes.contains(tmp_path / "b.py", 999)
    assert not changes.contains(tmp_path / "c.py", 1)


def scan_json(
    capsys: pytest.CaptureFixture[str], *arguments: str
) -> tuple[int, dict[str, Any], str]:
    code = main(["scan", *arguments, "--format", "json"])
    captured = capsys.readouterr()
    document: dict[str, Any] = json.loads(captured.out)
    return code, document, captured.err


def lines_of(items: list[dict[str, Any]]) -> list[tuple[str, int]]:
    return [(item["path"], item["line"]) for item in items]


@needs_git
def test_scan_reports_only_the_new_problem(
    repo: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    (repo / "app.py").write_bytes(OLD_CODE + b"os.system(new_command)\n")

    code, document, err = scan_json(capsys, str(repo), "--changed-since", "main")

    assert code == 1
    assert lines_of(document["findings"]) == [("app.py", 4)]
    assert lines_of(document["outside_change"]) == [("app.py", 3)]
    assert document["summary"]["outside_change"] == 1
    assert "securelint: reporting only lines changed since main" in err


@needs_git
def test_scan_with_only_old_problems_exits_0(
    repo: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    (repo / "lib" / "tools.py").write_bytes(b"def helper():\n    return 2\n")

    assert main(["scan", str(repo), "--changed-since", "main"]) == 0

    out = capsys.readouterr().out
    assert out == "No problems found in 2 files. Outside the changed lines: 1.\n"


@needs_git
def test_scan_of_a_folder_matches_the_right_files(
    repo: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    (repo / "lib" / "tools.py").write_bytes(
        b"def helper(command):\n    os.system(command)\n"
    )

    code, document, _ = scan_json(capsys, str(repo / "lib"), "--changed-since", "main")

    assert code == 1
    assert lines_of(document["findings"]) == [("tools.py", 2)]


@needs_git
def test_scan_with_an_unknown_branch_stops(
    repo: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["scan", str(repo), "--changed-since", "nope"]) == 2

    captured = capsys.readouterr()
    assert captured.out == ""
    assert "securelint: error: cannot find where this branch left 'nope'" in (
        captured.err
    )


@needs_git
def test_known_problems_stay_known(
    repo: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    main(["baseline", str(repo)])
    # The old line is edited, so it is both changed and no longer known.
    (repo / "app.py").write_bytes(b"import os\n\nos.system(edited)\nos.system(new)\n")
    (repo / "scratch.py").write_bytes(b"eval(x)\n")
    capsys.readouterr()

    code, document, _ = scan_json(capsys, str(repo), "--changed-since", "main")

    assert code == 1
    assert lines_of(document["findings"]) == [
        ("app.py", 3),
        ("app.py", 4),
        ("scratch.py", 1),
    ]


@needs_git
def test_text_report_counts_findings_outside_the_change(
    repo: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    (repo / "app.py").write_bytes(OLD_CODE + b"eval(text)\n")

    assert main(["scan", str(repo), "--changed-since", "main"]) == 1

    lines = capsys.readouterr().out.splitlines()
    assert lines[0].startswith("app.py:4:1  high      SL101")
    assert lines[-1] == (
        "1 problem found in 2 files (1 high). Outside the changed lines: 1."
    )


@needs_git
def test_sarif_keeps_findings_outside_the_change_as_notes(
    repo: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    (repo / "app.py").write_bytes(OLD_CODE + b"eval(text)\n")

    main(["scan", str(repo), "--changed-since", "main", "--format", "sarif"])

    results = json.loads(capsys.readouterr().out)["runs"][0]["results"]
    assert [(item["ruleId"], item["level"]) for item in results] == [
        ("SL102", "note"),
        ("SL101", "error"),
    ]


@needs_git
def test_html_report_lists_findings_outside_the_change(
    repo: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    (repo / "app.py").write_bytes(OLD_CODE + b"eval(text)\n")

    main(["scan", str(repo), "--changed-since", "main", "--format", "html"])

    page = capsys.readouterr().out
    assert "<h2>Outside the changed lines</h2>" in page
    assert "app.py:3 SL102</span>" in page
