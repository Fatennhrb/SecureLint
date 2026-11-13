"""Turn a source file into a syntax tree without ever crashing the scan.

SecureLint reads code it did not write, so any file may be broken, in the
wrong encoding, or built on purpose to break a parser. One bad file must
become one reported failure, never the end of the scan.

The code is only parsed. It is never imported or run.
"""

import ast
import warnings
from dataclasses import dataclass

from securelint.discovery import SourceFile


@dataclass(frozen=True, slots=True)
class ParsedFile:
    """A file that was read and parsed successfully."""

    source_file: SourceFile
    tree: ast.Module

    source: bytes
    """The file's content as read from disk, kept for reading its comments."""


@dataclass(frozen=True, slots=True)
class ParseFailure:
    """A file that could not be scanned, and why."""

    relative_path: str
    message: str

    line: int | None = None
    """Line of the problem, starting at 1, when the parser reports one."""


def parse(source_file: SourceFile) -> ParsedFile | ParseFailure:
    """Read and parse one file.

    Returns a ``ParseFailure`` instead of raising when the file cannot be
    read or is not valid Python.
    """
    relative_path = source_file.relative_path
    try:
        # Bytes, not text: ``ast.parse`` then finds the file's encoding the
        # same way Python does (a byte order mark or a "coding:" comment).
        data = source_file.path.read_bytes()
    except OSError as error:
        reason = error.strerror or type(error).__name__
        return ParseFailure(relative_path, f"cannot read file: {reason}")

    try:
        # Parsing can emit a SyntaxWarning about the scanned code, e.g. for
        # "\d" in a normal string. That is the project's business, not a
        # problem in SecureLint, so it must not appear in our output.
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            tree = ast.parse(data, filename=relative_path)
    except SyntaxError as error:
        # Also covers a wrong or unknown encoding.
        return ParseFailure(
            relative_path, error.msg or "invalid syntax", line=error.lineno
        )
    except ValueError as error:
        # Python 3.11 reports a null byte in the source this way.
        return ParseFailure(relative_path, str(error))
    except RecursionError:
        # Extremely deep nesting, e.g. thousands of chained operators.
        return ParseFailure(relative_path, "code is nested too deeply to parse")

    return ParsedFile(source_file=source_file, tree=tree, source=data)
