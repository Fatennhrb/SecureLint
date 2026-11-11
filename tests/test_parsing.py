"""Tests for reading and parsing source files safely."""

import ast
import warnings
from pathlib import Path

import pytest

from securelint.discovery import SourceFile
from securelint.parsing import ParsedFile, ParseFailure, parse


def source(tmp_path: Path, content: bytes, name: str = "app.py") -> SourceFile:
    """Write ``content`` to a file and return it as a ``SourceFile``."""
    path = tmp_path / name
    path.write_bytes(content)
    return SourceFile(path=path, relative_path=name)


def parse_ok(source_file: SourceFile) -> ParsedFile:
    result = parse(source_file)
    assert isinstance(result, ParsedFile), result
    return result


def parse_failure(source_file: SourceFile) -> ParseFailure:
    result = parse(source_file)
    assert isinstance(result, ParseFailure), result
    return result


def test_valid_file_gives_a_syntax_tree(tmp_path: Path) -> None:
    source_file = source(tmp_path, b"import os\n\nx = os.getcwd()\n")

    result = parse_ok(source_file)

    assert result.source_file is source_file
    assert isinstance(result.tree, ast.Module)
    assert isinstance(result.tree.body[0], ast.Import)


def test_empty_file_is_valid(tmp_path: Path) -> None:
    assert parse_ok(source(tmp_path, b"")).tree.body == []


def test_syntax_error_is_reported_with_its_line(tmp_path: Path) -> None:
    failure = parse_failure(source(tmp_path, b"x = 1\ndef broken(:\n    pass\n"))

    assert failure.relative_path == "app.py"
    assert failure.line == 2
    assert failure.message


def test_file_in_the_wrong_encoding_is_reported(tmp_path: Path) -> None:
    # 0xE9 is "é" in Latin-1 but is not valid UTF-8, Python's default.
    failure = parse_failure(source(tmp_path, b"name = 'caf\xe9'\n"))

    assert failure.relative_path == "app.py"


def test_declared_encoding_is_respected(tmp_path: Path) -> None:
    content = b"# -*- coding: latin-1 -*-\nname = 'caf\xe9'\n"

    tree = parse_ok(source(tmp_path, content)).tree

    assignment = tree.body[0]
    assert isinstance(assignment, ast.Assign)
    assert isinstance(assignment.value, ast.Constant)
    assert assignment.value.value == "café"


def test_utf8_byte_order_mark_is_accepted(tmp_path: Path) -> None:
    # Some Windows editors put these three bytes at the start of a file.
    assert len(parse_ok(source(tmp_path, b"\xef\xbb\xbfx = 1\n")).tree.body) == 1


def test_null_byte_is_reported(tmp_path: Path) -> None:
    failure = parse_failure(source(tmp_path, b"x = 1\x00\n"))

    assert "null byte" in failure.message


def test_unreadable_file_is_reported(tmp_path: Path) -> None:
    missing = SourceFile(path=tmp_path / "gone.py", relative_path="gone.py")

    failure = parse_failure(missing)

    assert failure.relative_path == "gone.py"
    assert failure.message.startswith("cannot read file")
    assert failure.line is None


def test_too_deeply_nested_code_is_reported(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Real input that causes this differs between Python versions, so the
    # test makes the parser raise the error directly.
    def raise_recursion_error(*args: object, **kwargs: object) -> ast.Module:
        raise RecursionError

    monkeypatch.setattr(ast, "parse", raise_recursion_error)

    failure = parse_failure(source(tmp_path, b"x = 1\n"))

    assert failure.message == "code is nested too deeply to parse"


def test_warnings_about_the_scanned_code_are_silenced(tmp_path: Path) -> None:
    # "\d" in a normal string makes Python 3.12+ emit a SyntaxWarning.
    source_file = source(tmp_path, b"pattern = '\\d+'\n")

    with warnings.catch_warnings():
        warnings.simplefilter("error")
        parse_ok(source_file)


def test_code_is_parsed_but_never_run(tmp_path: Path) -> None:
    marker = tmp_path / "marker.txt"
    code = f"open({str(marker)!r}, 'w').close()\nraise SystemExit(1)\n"

    parse_ok(source(tmp_path, code.encode()))

    assert not marker.exists()
