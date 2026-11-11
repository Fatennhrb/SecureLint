"""Tests for SL102, shell commands built at run time."""

from pathlib import Path

import pytest

from securelint.engine import scan
from securelint.model import Confidence, Finding, Severity
from securelint.rules.shell_injection import ShellCommandInjection


def findings_in(tmp_path: Path, code: str) -> tuple[Finding, ...]:
    (tmp_path / "app.py").write_text(code, encoding="utf-8")
    return scan(tmp_path, [ShellCommandInjection()]).findings


@pytest.mark.parametrize(
    "code",
    [
        "os.system('ping ' + host)\n",
        "os.system(command)\n",
        "os.system(f'rm -rf {folder}')\n",
        "os.system(command=cmd)\n",
        "os.popen('cat ' + name)\n",
        "subprocess.getoutput('ls ' + folder)\n",
        "subprocess.getstatusoutput(command)\n",
        "subprocess.run(command, shell=True)\n",
        "subprocess.run(f'convert {name} out.png', shell=True)\n",
        "subprocess.run(args=command, shell=True)\n",
        "subprocess.run(command, check=True, shell=True, text=True)\n",
        "subprocess.call(command, shell=True)\n",
        "subprocess.check_call(command, shell=True)\n",
        "subprocess.check_output(command, shell=True)\n",
        "subprocess.Popen(command, shell=True)\n",
        # With shell=True the list's first element is still shell text.
        "subprocess.run(['ls ' + folder], shell=True)\n",
        # The module or function imported under another name.
        "sp.run(command, shell=True)\n",
        "run(command, shell=True)\n",
        "Popen(command, shell=True)\n",
    ],
)
def test_reports_shell_commands_built_at_run_time(tmp_path: Path, code: str) -> None:
    assert [finding.rule_id for finding in findings_in(tmp_path, code)] == ["SL102"]


@pytest.mark.parametrize(
    "code",
    [
        # Fixed commands.
        "os.system('clear')\n",
        "os.popen('date')\n",
        "subprocess.run('ls -l', shell=True)\n",
        "subprocess.run(['ls', '-l'], shell=True)\n",
        "subprocess.getoutput('whoami')\n",
        # No shell: each list item is passed as one argument.
        "subprocess.run(['ping', host])\n",
        "subprocess.run(command)\n",
        "subprocess.run(command, shell=False)\n",
        "subprocess.Popen(['git', 'log', branch])\n",
        # Whether a shell is used is not known here.
        "subprocess.run(command, shell=use_shell)\n",
        # Other things that only share a name.
        "app.run(host, debug=True)\n",
        "pool.call(command)\n",
        "system(command)\n",
        "os.system()\n",
        "os.path.join(a, b)\n",
    ],
)
def test_does_not_report_safe_code(tmp_path: Path, code: str) -> None:
    assert findings_in(tmp_path, code) == ()


def test_finding_details(tmp_path: Path) -> None:
    code = "import os\n\ndef ping(host):\n    return os.system('ping ' + host)\n"

    (finding,) = findings_in(tmp_path, code)

    assert finding.path == "app.py"
    assert (finding.line, finding.column) == (4, 12)
    assert finding.severity is Severity.HIGH
    assert finding.confidence is Confidence.MEDIUM
    assert finding.message.startswith("os.system() runs its command through the shell")


def test_message_shows_shell_true_for_subprocess(tmp_path: Path) -> None:
    (finding,) = findings_in(tmp_path, "subprocess.run(command, shell=True)\n")

    assert finding.message.startswith("subprocess.run(..., shell=True) runs")
