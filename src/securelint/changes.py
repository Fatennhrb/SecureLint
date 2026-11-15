"""Find the lines a change touched, by asking Git.

``securelint scan --changed-since main`` reports only the findings on lines
that the current branch added or changed since it left ``main``. A
developer who edits one function then hears about that function, not
about everything else in the file.

"Changed" means: compared with the commit where the branch left ``main``
(Git's merge base), including changes not yet committed. A file Git does
not track yet counts as changed in full.

Git is run as a separate program with a fixed list of arguments, never
through a shell. The branch name comes from the command line, so a name
starting with ``-`` is refused: Git would read it as an option.
"""

import re
import shutil
import subprocess
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, replace
from pathlib import Path

from securelint.engine import ScanResult
from securelint.model import Finding

# "@@ -12,3 +12,4 @@": 3 old lines from line 12 became 4 new lines from
# line 12. A count left out means 1.
_HUNK = re.compile(rb"^@@ -\d+(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")

_TIMEOUT_SECONDS = 60

# Git writes unusual characters in file names the way C strings do.
_ESCAPES = {
    ord("a"): b"\a",
    ord("b"): b"\b",
    ord("f"): b"\f",
    ord("n"): b"\n",
    ord("r"): b"\r",
    ord("t"): b"\t",
    ord("v"): b"\v",
}


class ChangesError(Exception):
    """The changed lines cannot be found; the message says why."""


@dataclass(frozen=True, slots=True)
class ChangedLines:
    """The lines a change touched, file by file."""

    base: str
    """The branch or commit the change is compared with, as given."""

    merge_base: str
    """The commit where the current branch left ``base``."""

    files: Mapping[Path, frozenset[int] | None]
    """For each changed file, as a full path: the changed line numbers, or
    ``None`` when the whole file is new."""

    def contains(self, path: Path, line: int) -> bool:
        """Return True if ``line`` of the file at ``path`` (a full path) changed."""
        if path not in self.files:
            return False
        lines = self.files[path]
        return lines is None or line in lines


def find_changed_lines(place: Path, base: str) -> ChangedLines:
    """Return the lines changed since the current branch left ``base``.

    ``place`` is any path inside the Git repository.

    Raises ``ChangesError`` when Git is missing, ``place`` is not in a Git
    repository, or ``base`` cannot be found. Reporting nothing in those
    cases would look like a clean change.
    """
    if not base or base.startswith("-"):
        raise ChangesError(f"{base!r} is not a branch or commit name")
    git = shutil.which("git")
    if git is None:
        raise ChangesError("--changed-since needs Git, which was not found")

    start = place.resolve()
    if not start.is_dir():
        start = start.parent
    top_output = _git(
        git,
        start,
        ["rev-parse", "--show-toplevel"],
        "--changed-since needs a Git repository",
    )
    top = Path(top_output.decode("utf-8", "surrogateescape").strip()).resolve()

    merge_base = (
        _git(
            git,
            top,
            ["merge-base", base, "HEAD"],
            # A shallow copy of a repository (GitHub Actions' default) does
            # not hold the commit where the branch started.
            f"cannot find where this branch left {base!r} (in GitHub Actions, "
            "check out the whole history with fetch-depth: 0)",
        )
        .decode("ascii", "replace")
        .strip()
    )

    diff = _git(
        git,
        top,
        [
            "-c",
            "core.quotepath=off",
            "diff",
            # Fixed choices, so the user's own Git settings cannot change
            # the layout of what is read below.
            "--no-color",
            "--no-ext-diff",
            "--no-textconv",
            "--no-relative",
            "--find-renames",
            "--src-prefix=a/",
            "--dst-prefix=b/",
            "--unified=0",
            merge_base,
        ],
        "cannot list the changed lines",
    )
    files: dict[Path, frozenset[int] | None] = {
        path: frozenset(lines) for path, lines in _parse_diff(diff, top).items()
    }

    untracked = _git(
        git,
        top,
        ["ls-files", "--others", "--exclude-standard", "-z"],
        "cannot list the new files",
    )
    for name in untracked.split(b"\0"):
        if name:
            path = top / name.decode("utf-8", "surrogateescape")
            files[path.resolve()] = None

    return ChangedLines(base=base, merge_base=merge_base, files=files)


def split_outside_change(
    result: ScanResult, changes: ChangedLines, target: Path
) -> ScanResult:
    """Move the findings on lines the change did not touch out of ``findings``.

    They are kept in ``result.outside_change``, so reports can count them.
    ``target`` is the file or directory that was scanned.
    """
    directory = target.resolve()
    if not directory.is_dir():
        directory = directory.parent

    def touched(finding: Finding) -> bool:
        return changes.contains((directory / finding.path).resolve(), finding.line)

    return replace(
        result,
        findings=tuple(f for f in result.findings if touched(f)),
        outside_change=tuple(f for f in result.findings if not touched(f)),
    )


def _parse_diff(diff: bytes, top: Path) -> dict[Path, set[int]]:
    """Read ``git diff --unified=0`` output: the new line numbers of each file."""
    files: dict[Path, set[int]] = {}
    current: set[int] | None = None
    # Lines of the current hunk still to come. They are skipped by count,
    # so an added line that happens to start with "++ " is never mistaken
    # for the "+++ " line that names a file.
    remaining = 0
    for raw in diff.split(b"\n"):
        if remaining:
            if raw.startswith((b"+", b"-", b" ")):
                remaining -= 1
                continue
            if raw.startswith(b"\\"):
                # "\ No newline at end of file" is not a line of the file.
                continue
            remaining = 0

        if raw.startswith(b"+++ "):
            name = raw[4:]
            if name == b"/dev/null":
                # The file was deleted: none of its lines exist any more.
                current = None
                continue
            path_text = _unquote(name).removeprefix("b/")
            current = files.setdefault((top / path_text).resolve(), set())
            continue

        match = _HUNK.match(raw)
        if match is not None and current is not None:
            old_count = int(match[1]) if match[1] is not None else 1
            start = int(match[2])
            new_count = int(match[3]) if match[3] is not None else 1
            current.update(range(start, start + new_count))
            remaining = old_count + new_count
    return files


def _unquote(name: bytes) -> str:
    """Return a file name as Git wrote it, without its quotes and escapes."""
    if len(name) >= 2 and name.startswith(b'"') and name.endswith(b'"'):
        data = name[1:-1]
        decoded = bytearray()
        index = 0
        while index < len(data):
            byte = data[index]
            if byte == ord("\\") and index + 1 < len(data):
                following = data[index + 1]
                octal = data[index + 1 : index + 4]
                if len(octal) == 3 and all(ord("0") <= b <= ord("7") for b in octal):
                    decoded.append(int(octal, 8))
                    index += 4
                    continue
                decoded += _ESCAPES.get(following, bytes([following]))
                index += 2
                continue
            decoded.append(byte)
            index += 1
        name = bytes(decoded)
    return name.decode("utf-8", "surrogateescape")


def _git(git: str, cwd: Path, arguments: Sequence[str], problem: str) -> bytes:
    """Run Git and return what it wrote; raise ``ChangesError`` if it failed."""
    try:
        completed = subprocess.run(  # noqa: S603 (Git, a list of arguments, no shell)
            [git, *arguments],
            cwd=cwd,
            capture_output=True,
            check=False,
            timeout=_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ChangesError(f"{problem}: Git could not be run ({error})") from error
    if completed.returncode != 0:
        details = completed.stderr.decode("utf-8", "replace").strip().splitlines()
        reason = details[-1] if details else f"Git exit code {completed.returncode}"
        raise ChangesError(f"{problem}: {reason}")
    return completed.stdout
