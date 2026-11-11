"""Tests for finding the files to scan."""

from pathlib import Path

import pytest

from securelint.discovery import SourceFile, discover


def write(path: Path, text: str = "") -> Path:
    """Create a file and any missing parent directories."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def relative_paths(files: list[SourceFile]) -> list[str]:
    return [source_file.relative_path for source_file in files]


def test_finds_python_files_in_nested_directories(tmp_path: Path) -> None:
    write(tmp_path / "app.py")
    write(tmp_path / "pkg" / "views.py")
    write(tmp_path / "pkg" / "sub" / "models.py")

    assert relative_paths(discover(tmp_path)) == [
        "app.py",
        "pkg/sub/models.py",
        "pkg/views.py",
    ]


def test_source_file_points_at_the_real_file(tmp_path: Path) -> None:
    views = write(tmp_path / "pkg" / "views.py", "x = 1\n")

    assert discover(tmp_path) == [SourceFile(path=views, relative_path="pkg/views.py")]


def test_ignores_files_that_are_not_python(tmp_path: Path) -> None:
    write(tmp_path / "app.py")
    write(tmp_path / "README.md")
    write(tmp_path / "data.json")
    write(tmp_path / "stubs.pyi")
    write(tmp_path / "notes.py.txt")

    assert relative_paths(discover(tmp_path)) == ["app.py"]


def test_results_are_sorted(tmp_path: Path) -> None:
    for name in ["zebra.py", "alpha.py", "b/inner.py", "a/inner.py"]:
        write(tmp_path / name)

    assert relative_paths(discover(tmp_path)) == [
        "a/inner.py",
        "alpha.py",
        "b/inner.py",
        "zebra.py",
    ]


@pytest.mark.parametrize(
    "name", [".git", ".venv", ".tox", "__pycache__", "node_modules"]
)
def test_skips_directories_that_hold_no_project_code(tmp_path: Path, name: str) -> None:
    write(tmp_path / "app.py")
    write(tmp_path / name / "hidden.py")
    write(tmp_path / "pkg" / name / "hidden.py")

    assert relative_paths(discover(tmp_path)) == ["app.py"]


def test_skips_a_virtual_environment_with_any_name(tmp_path: Path) -> None:
    write(tmp_path / "app.py")
    write(tmp_path / "my-env" / "pyvenv.cfg", "home = /usr/bin\n")
    write(tmp_path / "my-env" / "Lib" / "site-packages" / "requests" / "api.py")

    assert relative_paths(discover(tmp_path)) == ["app.py"]


def test_the_scanned_directory_itself_is_never_skipped(tmp_path: Path) -> None:
    # Skipping applies to directories found during the search, not to the
    # directory the user asked for.
    target = tmp_path / ".hidden"
    write(target / "app.py")

    assert relative_paths(discover(target)) == ["app.py"]


def test_empty_directory_gives_no_files(tmp_path: Path) -> None:
    assert discover(tmp_path) == []


def test_single_file_target(tmp_path: Path) -> None:
    script = write(tmp_path / "pkg" / "script.py")

    assert discover(script) == [SourceFile(path=script, relative_path="script.py")]


def test_single_file_target_is_kept_whatever_its_extension(tmp_path: Path) -> None:
    script = write(tmp_path / "deploy")

    assert relative_paths(discover(script)) == ["deploy"]


def test_missing_target_is_an_error(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError, match="no such file or directory"):
        discover(tmp_path / "does-not-exist")


def test_symbolic_links_are_not_followed(tmp_path: Path) -> None:
    project = tmp_path / "project"
    write(project / "app.py")
    outside = tmp_path / "outside"
    secret = write(outside / "secret.py")
    try:
        (project / "linked_dir").symlink_to(outside, target_is_directory=True)
        (project / "linked_file.py").symlink_to(secret)
        # A link back to a parent would make a naive search loop forever.
        (project / "loop").symlink_to(project, target_is_directory=True)
    except OSError:
        pytest.skip("this system does not allow creating symbolic links")

    assert relative_paths(discover(project)) == ["app.py"]
