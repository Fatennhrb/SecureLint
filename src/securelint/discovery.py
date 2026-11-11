"""Find the Python files to scan."""

from dataclasses import dataclass
from pathlib import Path

# Directories that never hold the project's own source code. Hidden
# directories (``.git``, ``.venv``, ``.tox``, tool caches) and virtual
# environments are skipped as well; see ``_is_skipped``.
_SKIPPED_DIRECTORY_NAMES = frozenset({"__pycache__", "node_modules"})


@dataclass(frozen=True, slots=True)
class SourceFile:
    """One file to scan."""

    path: Path
    """Where to read the file from."""

    relative_path: str
    """The path shown in reports: relative to the scanned directory, with
    forward slashes, so it is the same on Windows and Linux."""


def discover(target: Path) -> list[SourceFile]:
    """Return the Python files under ``target``, sorted by relative path.

    ``target`` is a directory to search, or a single file. A file named
    directly is always returned, whatever its extension, because the user
    asked for it.

    Symbolic links are not followed. A link can point outside the scanned
    directory or back to one of its own parents, and a scanner run on
    someone else's code must not be led to either.

    Raises ``FileNotFoundError`` if ``target`` does not exist.
    """
    if target.is_file():
        return [SourceFile(path=target, relative_path=target.name)]
    if not target.is_dir():
        raise FileNotFoundError(f"no such file or directory: {target}")

    found: list[SourceFile] = []
    # A list of directories still to visit, instead of a recursive function:
    # a very deeply nested tree then cannot hit Python's recursion limit.
    pending = [target]
    while pending:
        directory = pending.pop()
        for entry in directory.iterdir():
            if entry.is_symlink():
                continue
            if entry.is_dir():
                if not _is_skipped(entry):
                    pending.append(entry)
            elif entry.suffix == ".py" and entry.is_file():
                relative_path = entry.relative_to(target).as_posix()
                found.append(SourceFile(path=entry, relative_path=relative_path))

    # The order files come back from the operating system differs between
    # machines. Sorting makes two scans of the same code give the same report.
    return sorted(found, key=lambda source_file: source_file.relative_path)


def _is_skipped(directory: Path) -> bool:
    """Return True for a directory that should not be searched."""
    if directory.name.startswith(".") or directory.name in _SKIPPED_DIRECTORY_NAMES:
        return True
    # Every virtual environment has this file at its top level, whatever the
    # directory is called. It holds third-party code, not the project's own.
    return (directory / "pyvenv.cfg").is_file()
