"""Tests for telling known problems from new ones."""

import json
from pathlib import Path

import pytest

from securelint.baseline import (
    BASELINE_FILE_NAME,
    BaselineError,
    find_project_root,
    load_baseline,
)
from securelint.cli import main
from securelint.engine import scan
from securelint.html_report import format_html
from securelint.rules import ALL_RULES


def write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


@pytest.fixture
def project(tmp_path: Path) -> Path:
    """A project with two old problems, in two folders."""
    root = tmp_path / "project"
    (root / ".git").mkdir(parents=True)
    write(root / "src" / "app.py", "import os\n\nos.system(command)\n")
    write(root / "tools" / "run.py", "eval(text)\n")
    write(root / "src" / "clean.py", "x = 1\n")
    return root


def run(capsys: pytest.CaptureFixture[str], *arguments: str) -> tuple[int, str, str]:
    code = main(list(arguments))
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def scan_json(
    capsys: pytest.CaptureFixture[str], *arguments: str
) -> tuple[int, dict[str, object]]:
    code, out, _ = run(capsys, "scan", *arguments, "--format", "json")
    document: dict[str, object] = json.loads(out)
    return code, document


def test_baseline_command_writes_the_file_at_the_top_of_the_project(
    project: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    code, out, _ = run(capsys, "baseline", str(project))

    baseline_file = project / BASELINE_FILE_NAME
    assert code == 0
    assert out == f"Saved 2 known problems to {baseline_file}\n"
    document = json.loads(baseline_file.read_text(encoding="utf-8"))
    assert document["format_version"] == 1
    assert document["tool"] == "securelint"
    assert [(entry["path"], entry["rule_id"]) for entry in document["findings"]] == [
        ("src/app.py", "SL102"),
        ("tools/run.py", "SL101"),
    ]
    assert all(len(entry["fingerprint"]) == 16 for entry in document["findings"])
    # No line numbers: they would be wrong as soon as the code moved.
    assert all("line" not in entry for entry in document["findings"])


def test_baseline_file_is_the_same_when_written_twice(
    project: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    run(capsys, "baseline", str(project))
    first = (project / BASELINE_FILE_NAME).read_bytes()
    run(capsys, "baseline", str(project))

    assert (project / BASELINE_FILE_NAME).read_bytes() == first
    assert first.endswith(b"\n")


def test_baseline_started_in_a_folder_still_covers_the_whole_project(
    project: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    code, out, _ = run(capsys, "baseline", str(project / "src"))

    assert code == 0
    assert out == f"Saved 2 known problems to {project / BASELINE_FILE_NAME}\n"
    assert not (project / "src" / BASELINE_FILE_NAME).exists()


def test_without_a_baseline_every_finding_is_new(
    project: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    code, out, err = run(capsys, "scan", str(project))

    assert code == 1
    assert out.splitlines()[-1] == "2 problems found in 3 files (2 high)."
    assert err == ""


def test_known_problems_do_not_fail_the_scan(
    project: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    run(capsys, "baseline", str(project))

    code, out, err = run(capsys, "scan", str(project))

    assert code == 0
    assert out == "No problems found in 3 files. Known problems not shown: 2.\n"
    assert f"securelint: using baseline {project / BASELINE_FILE_NAME}" in err


def test_a_new_problem_is_reported_next_to_the_known_ones(
    project: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    run(capsys, "baseline", str(project))
    write(project / "src" / "clean.py", "x = 1\npickle.loads(blob)\n")

    code, out, _ = run(capsys, "scan", str(project))

    assert code == 1
    lines = out.splitlines()
    assert lines[0].startswith("src/clean.py:2:1  high      SL103")
    assert lines[-1] == (
        "1 problem found in 3 files (1 high). Known problems not shown: 2."
    )


def test_a_known_problem_stays_known_when_lines_move(
    project: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    run(capsys, "baseline", str(project))
    write(
        project / "src" / "app.py",
        "import os\nimport sys\n\n# moved down by three lines\n\nos.system(command)\n",
    )

    code, document = scan_json(capsys, str(project))

    assert code == 0
    assert document["findings"] == []
    assert [(item["path"], item["line"]) for item in document["known"]] == [  # type: ignore[attr-defined]
        ("src/app.py", 6),
        ("tools/run.py", 1),
    ]


def test_editing_a_known_line_makes_it_new_again(
    project: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    run(capsys, "baseline", str(project))
    write(project / "src" / "app.py", "import os\n\nos.system(other_command)\n")

    code, out, err = run(capsys, "scan", str(project))

    assert code == 1
    assert "src/app.py:3:1  high      SL102" in out
    assert "Known problems not shown: 1." in out
    assert "1 entry is in the baseline but no longer found" in err


def test_a_second_copy_of_a_known_line_is_new(
    project: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    run(capsys, "baseline", str(project))
    write(
        project / "src" / "app.py",
        "import os\n\nos.system(command)\nos.system(command)\n",
    )

    code, document = scan_json(capsys, str(project))

    assert code == 1
    assert [item["line"] for item in document["findings"]] == [4]  # type: ignore[attr-defined]
    assert len(document["known"]) == 2  # type: ignore[arg-type]


def test_scanning_one_folder_uses_the_same_baseline(
    project: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    run(capsys, "baseline", str(project))

    code, out, err = run(capsys, "scan", str(project / "src"))

    # The path shown is relative to the folder, but the finding is still
    # recognised as the one recorded from the top of the project.
    assert code == 0
    assert out == "No problems found in 2 files. Known problems not shown: 1.\n"
    # The problem recorded in the other folder was not looked at; that does
    # not mean it was fixed.
    assert "no longer found" not in err


def test_scanning_one_file_uses_the_same_baseline(
    project: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    run(capsys, "baseline", str(project))

    code, out, _ = run(capsys, "scan", str(project / "tools" / "run.py"))

    assert code == 0
    assert out == "No problems found in 1 file. Known problems not shown: 1.\n"


def test_fingerprint_does_not_depend_on_the_folder_scanned(project: Path) -> None:
    root = project.resolve()
    (whole,) = [
        f for f in scan(project, ALL_RULES, root=root).findings if f.rule_id == "SL102"
    ]
    (part,) = scan(project / "src", ALL_RULES, root=root).findings
    (single,) = scan(project / "src" / "app.py", ALL_RULES, root=root).findings

    assert (whole.path, part.path, single.path) == ("src/app.py", "app.py", "app.py")
    assert whole.fingerprint == part.fingerprint == single.fingerprint


def test_a_fixed_problem_is_pointed_out(
    project: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    run(capsys, "baseline", str(project))
    write(project / "tools" / "run.py", "x = 1\n")

    code, out, err = run(capsys, "scan", str(project))

    assert code == 0
    assert out == "No problems found in 3 files. Known problems not shown: 1.\n"
    assert (
        "securelint: 1 entry is in the baseline but no longer found; "
        "run `securelint baseline` to write it again"
    ) in err


def test_writing_the_baseline_again_drops_fixed_problems(
    project: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    run(capsys, "baseline", str(project))
    write(project / "tools" / "run.py", "x = 1\n")

    _, out, _ = run(capsys, "baseline", str(project))
    assert out.startswith("Saved 1 known problem to ")

    _, _, err = run(capsys, "scan", str(project))
    assert "no longer found" not in err


def test_a_known_problem_silenced_by_a_comment_is_not_called_fixed(
    project: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    write(project / "tools" / "run.py", "x = 1\n")
    write(project / "src" / "app.py", "os.system(command)\n")
    run(capsys, "baseline", str(project))
    # The line is edited (a comment is added), so its fingerprint changes;
    # the entry no longer matches and is reported as such.
    write(
        project / "src" / "app.py", "os.system(command)  # securelint: ignore[SL102]\n"
    )

    code, out, err = run(capsys, "scan", str(project))

    assert code == 0
    assert "Silenced by a comment: 1." in out
    assert "1 entry is in the baseline but no longer found" in err


def test_no_baseline_option_shows_everything(
    project: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    run(capsys, "baseline", str(project))

    code, out, err = run(capsys, "scan", str(project), "--no-baseline")

    assert code == 1
    assert out.splitlines()[-1] == "2 problems found in 3 files (2 high)."
    assert "using baseline" not in err


def test_json_report_lists_known_problems(
    project: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    run(capsys, "baseline", str(project))

    _, document = scan_json(capsys, str(project))

    assert document["summary"]["known"] == 2  # type: ignore[index]
    assert document["summary"]["findings"] == 0  # type: ignore[index]
    known = document["known"]
    assert [item["rule_id"] for item in known] == ["SL102", "SL101"]  # type: ignore[attr-defined]


def test_html_report_lists_known_problems(
    project: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    run(capsys, "baseline", str(project))

    _, out, _ = run(capsys, "scan", str(project), "--format", "html")

    assert "Known problems not shown: 2." in out
    assert "<h2>Known problems</h2>" in out
    assert "src/app.py:3 SL102</span>" in out


def test_html_report_has_no_known_section_without_a_baseline(tmp_path: Path) -> None:
    write(tmp_path / "app.py", "eval(x)\n")

    assert "Known problems" not in format_html(scan(tmp_path, ALL_RULES))


def test_baseline_respects_the_settings(
    project: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    write(project / "pyproject.toml", '[tool.securelint]\nexclude = ["tools"]\n')

    _, out, _ = run(capsys, "baseline", str(project))

    assert out.startswith("Saved 1 known problem to ")


def test_baseline_is_written_next_to_the_settings_file(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # No .git folder here: the settings file marks the top of the project.
    write(tmp_path / "pyproject.toml", "[tool.securelint]\n")
    write(tmp_path / "pkg" / "app.py", "eval(x)\n")

    code, _, _ = run(capsys, "baseline", str(tmp_path / "pkg"))

    assert code == 0
    assert (tmp_path / BASELINE_FILE_NAME).is_file()


def test_baseline_is_not_written_when_a_file_cannot_be_scanned(
    project: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    write(project / "src" / "broken.py", "def oops(:\n")

    code, out, err = run(capsys, "baseline", str(project))

    assert code == 2
    assert out == ""
    assert "the baseline was not written" in err
    assert not (project / BASELINE_FILE_NAME).exists()


def test_baseline_for_a_missing_path_is_an_error(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    code, _, err = run(capsys, "baseline", str(tmp_path / "missing"))

    assert code == 2
    assert "no such file or directory" in err


@pytest.mark.parametrize(
    ("content", "message"),
    [
        ("{not json", "not valid JSON"),
        ("[]", "not a SecureLint baseline file"),
        ('{"format_version": 1}', "not a SecureLint baseline file"),
        ('{"format_version": 99, "findings": []}', "does not read"),
        ('{"format_version": 1, "findings": [{}]}', "an entry has no fingerprint"),
        ('{"format_version": 1, "findings": ["abc"]}', "an entry has no fingerprint"),
        (
            '{"format_version": 1, "findings": [{"fingerprint": ""}]}',
            "an entry has no fingerprint",
        ),
    ],
)
def test_a_damaged_baseline_stops_the_scan(
    project: Path, capsys: pytest.CaptureFixture[str], content: str, message: str
) -> None:
    write(project / BASELINE_FILE_NAME, content)

    code, out, err = run(capsys, "scan", str(project))

    # No report: the baseline decides what counts as new, so a scan with a
    # baseline that cannot be read proves nothing.
    assert code == 2
    assert out == ""
    assert message in err


def test_load_baseline(tmp_path: Path) -> None:
    path = tmp_path / BASELINE_FILE_NAME
    assert load_baseline(path) is None

    write(path, '{"format_version": 1, "findings": []}')
    assert load_baseline(path) == frozenset()

    write(
        path,
        '{"format_version": 1, "findings": '
        '[{"fingerprint": "aaaa"}, {"fingerprint": "bbbb", "path": "x.py"}]}',
    )
    assert load_baseline(path) == frozenset({"aaaa", "bbbb"})

    write(path, "{")
    with pytest.raises(BaselineError):
        load_baseline(path)


def test_find_project_root(tmp_path: Path) -> None:
    deep = tmp_path / "a" / "b"
    deep.mkdir(parents=True)
    script = deep / "script.py"
    script.write_text("x = 1\n", encoding="utf-8")

    # Nothing marks a project: the scanned directory is its own top.
    assert find_project_root(deep) == deep.resolve()
    assert find_project_root(script) == deep.resolve()

    (tmp_path / "a" / ".git").mkdir()
    assert find_project_root(deep) == (tmp_path / "a").resolve()

    # A baseline file nearer than the repository top wins.
    (deep / BASELINE_FILE_NAME).write_text("{}", encoding="utf-8")
    assert find_project_root(script) == deep.resolve()
