"""Tests for following imports back to the real name."""

import ast

import pytest

from securelint.context import FileContext, collect_imports


def context_for(code: str) -> FileContext:
    nodes = list(ast.walk(ast.parse(code)))
    return FileContext(path="app.py", imports=collect_imports(nodes))


def name_of(code: str, expression: str) -> str | None:
    """Return the qualified name of ``expression`` in a file holding ``code``."""
    return context_for(code).qualified_name(ast.parse(expression, mode="eval").body)


@pytest.mark.parametrize(
    ("code", "expression", "expected"),
    [
        # import ...
        ("import os", "os.system", "os.system"),
        ("import subprocess as sp", "sp.run", "subprocess.run"),
        ("import os.path", "os.path.join", "os.path.join"),
        ("import os.path as p", "p.join", "os.path.join"),
        ("import os, subprocess as sp", "sp.Popen", "subprocess.Popen"),
        # from ... import ...
        ("from os import system", "system", "os.system"),
        ("from os import system as sh", "sh", "os.system"),
        ("from os import path", "path.join", "os.path.join"),
        ("from os.path import join", "join", "os.path.join"),
        ("from subprocess import run, Popen", "Popen", "subprocess.Popen"),
        ("from xml.etree import ElementTree as ET", "ET", "xml.etree.ElementTree"),
        # A project's own modules keep their leading dots.
        ("from . import tools", "tools.system", ".tools.system"),
        ("from .tools import system", "system", ".tools.system"),
        ("from ..pkg.tools import system as sh", "sh", "..pkg.tools.system"),
        # Names the file does not import are returned as written.
        ("", "eval", "eval"),
        ("", "os.system", "os.system"),
        ("import os", "data.load", "data.load"),
        ("from os import *", "system", "system"),
    ],
)  # fmt: skip
def test_qualified_name(code: str, expression: str, expected: str) -> None:
    assert name_of(code, expression) == expected


@pytest.mark.parametrize(
    "expression",
    ["get_module().system", "modules[0].run", "(a or b).load", "'text'.join"],
)
def test_expression_that_is_not_a_chain_of_names_has_no_name(expression: str) -> None:
    assert name_of("import os", expression) is None


def test_imports_inside_functions_are_followed() -> None:
    code = "def restore(blob):\n    import pickle as pk\n    return pk.loads(blob)\n"

    assert name_of(code, "pk.loads") == "pickle.loads"


def test_an_import_shadows_a_builtin() -> None:
    # After this import, eval() is the project's own function.
    assert name_of("from mylib import eval", "eval") == "mylib.eval"


def test_collect_imports_mapping() -> None:
    code = "import os\nimport subprocess as sp\nfrom pickle import loads as unpickle\n"

    assert context_for(code).imports == {
        "os": "os",
        "sp": "subprocess",
        "unpickle": "pickle.loads",
    }
