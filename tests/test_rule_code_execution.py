"""Tests for SL101, calls to eval() and exec()."""

from pathlib import Path

import pytest

from securelint.engine import scan
from securelint.model import Confidence, Finding, Severity
from securelint.rules.code_execution import DynamicCodeExecution


def findings_in(tmp_path: Path, code: str) -> tuple[Finding, ...]:
    (tmp_path / "app.py").write_text(code, encoding="utf-8")
    return scan(tmp_path, [DynamicCodeExecution()]).findings


@pytest.mark.parametrize(
    "code",
    [
        "eval(user_input)\n",
        "exec(user_input)\n",
        "eval(request.args['q'])\n",
        "eval(f'{a} + {b}')\n",
        "eval('print(' + name + ')')\n",
        "eval(text, {}, {})\n",
        "import builtins\nbuiltins.eval(data)\n",
        "import builtins\nbuiltins.exec(data)\n",
        "value = int(eval(data))\n",
    ],
)
def test_reports_code_built_at_run_time(tmp_path: Path, code: str) -> None:
    assert [finding.rule_id for finding in findings_in(tmp_path, code)] == ["SL101"]


@pytest.mark.parametrize(
    "code",
    [
        "eval('2 + 2')\n",
        "exec('import os')\n",
        "eval(b'2 + 2')\n",
        # Methods and functions that only share the name.
        "model.eval()\n",
        "model.eval(data)\n",
        "session.exec(statement)\n",
        "evaluate(data)\n",
        "literal_eval(data)\n",
        "import ast\nast.literal_eval(data)\n",
        # Not a call.
        "run = eval\n",
        "eval()\n",
    ],
)
def test_does_not_report_safe_code(tmp_path: Path, code: str) -> None:
    assert findings_in(tmp_path, code) == ()


def test_finding_details(tmp_path: Path) -> None:
    (finding,) = findings_in(tmp_path, "x = 1\nif x:\n    y = eval(data)\n")

    assert finding.path == "app.py"
    assert (finding.line, finding.column) == (3, 9)
    assert finding.severity is Severity.HIGH
    assert finding.confidence is Confidence.MEDIUM
    assert finding.message.startswith("eval() runs its argument as Python code")


def test_message_names_the_function_that_was_called(tmp_path: Path) -> None:
    (finding,) = findings_in(tmp_path, "exec(code)\n")

    assert finding.message.startswith("exec() ")


def test_reports_every_call(tmp_path: Path) -> None:
    findings = findings_in(tmp_path, "eval(a)\nexec(b)\neval(eval(c))\n")

    assert [(f.line, f.column) for f in findings] == [(1, 1), (2, 1), (3, 1), (3, 6)]
