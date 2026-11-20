"""Rules about running operating-system commands."""

import ast
from collections.abc import Iterable

from securelint.context import FileContext
from securelint.engine import Rule
from securelint.model import Confidence, Finding, Severity
from securelint.rules._helpers import is_fixed
from securelint.rules._sources import SHELL_CLEANERS, find_source, with_source

# These always hand their command to the shell.
_ALWAYS_SHELL = frozenset(
    {
        "os.system",
        "os.popen",
        "subprocess.getoutput",
        "subprocess.getstatusoutput",
    }
)

# These use the shell only when called with ``shell=True``.
_SHELL_ON_REQUEST = frozenset(
    {
        "subprocess.run",
        "subprocess.call",
        "subprocess.check_call",
        "subprocess.check_output",
        "subprocess.Popen",
    }
)

# Programs that read a command as text after "-c" ("/c" for cmd.exe).
_SHELLS = frozenset({"sh", "bash", "dash", "zsh", "ksh", "ash", "fish", "cmd"})

# The command is the first argument, or one of these keywords.
_COMMAND_KEYWORDS = frozenset({"args", "command", "cmd"})


class ShellCommandInjection(Rule):
    """SL102: a shell command is built at run time.

    A shell reads its command as text, and characters such as ``;``, ``|``
    and ``$( )`` start new commands. If part of the text can come from
    outside the program, whoever controls it can run their own commands.

    Reported::

        os.system("ping " + host)
        subprocess.run(f"convert {name} out.png", shell=True)
        subprocess.run(["sh", "-c", command])  # a shell started by hand

    Not reported::

        os.system("clear")                    # a fixed command
        subprocess.run(["ping", host])        # no shell: host is one argument

    The fix is the last form: pass a list of arguments and leave out
    ``shell=True``, so no shell ever reads the text.
    """

    rule_id = "SL102"
    title = "Shell command built at run time"
    node_types = (ast.Call,)

    def check(self, node: ast.AST, context: FileContext) -> Iterable[Finding]:
        if not isinstance(node, ast.Call):
            return []
        name = context.qualified_name(node.func)
        command = _command_argument(node)
        if name in _ALWAYS_SHELL:
            label = f"{name}()"
        elif name in _SHELL_ON_REQUEST and _has_shell_true(node, context):
            label = f"{name}(..., shell=True)"
        elif name in _SHELL_ON_REQUEST and command is not None:
            started = _shell_started_by_hand(command, context)
            if started is None:
                return []
            shell, flag, command = started
            label = f'{name}(["{shell}", "{flag}", ...])'
        else:
            return []

        if command is None or is_fixed(command, context):
            return []
        # The rule sees that the command is not fixed. Unless it also
        # finds where a part comes from, it cannot be fully sure.
        message, confidence = with_source(
            f"{label} runs its command through the shell; if any part of the "
            "command can come from a user, they can run their own commands.",
            Confidence.MEDIUM,
            find_source(command, context, SHELL_CLEANERS),
        )
        return [
            Finding(
                rule_id=self.rule_id,
                message=message,
                severity=Severity.HIGH,
                confidence=confidence,
                path=context.path,
                line=node.lineno,
                column=node.col_offset + 1,
            )
        ]


def _has_shell_true(call: ast.Call, context: FileContext) -> bool:
    """Return True if the call certainly asks for a shell.

    That is ``shell=True``, or ``shell=use_shell`` when ``use_shell`` was
    given the value ``True`` once and never changed. A value that is not
    known is left alone: it may well be ``False``.
    """
    for keyword in call.keywords:
        if keyword.arg != "shell":
            continue
        value = keyword.value
        if isinstance(value, ast.Name):
            value = context.value_of(value) or value
        return isinstance(value, ast.Constant) and value.value is True
    return False


def _command_argument(call: ast.Call) -> ast.expr | None:
    if call.args:
        return call.args[0]
    for keyword in call.keywords:
        if keyword.arg in _COMMAND_KEYWORDS:
            return keyword.value
    return None


def _shell_started_by_hand(
    command: ast.expr, context: FileContext
) -> tuple[str, str, ast.expr] | None:
    """Find a shell started without ``shell=True``.

    ``["sh", "-c", script]`` runs ``script`` through the shell just like
    ``shell=True`` does. Returns the shell as written, its flag, and the
    script, or ``None`` when the list does not start a shell this way.
    """
    if isinstance(command, ast.Name):
        command = context.value_of(command) or command
    if not isinstance(command, ast.List | ast.Tuple) or not command.elts:
        return None
    program = command.elts[0]
    if not (isinstance(program, ast.Constant) and isinstance(program.value, str)):
        return None
    # "/bin/bash" and "cmd.exe" are bash and cmd.
    shell = program.value.replace("\\", "/").rpartition("/")[2].lower()
    shell = shell.removesuffix(".exe")
    if shell not in _SHELLS:
        return None
    for position, part in enumerate(command.elts[1:-1], start=1):
        if not (isinstance(part, ast.Constant) and isinstance(part.value, str)):
            continue
        if _is_command_flag(shell, part.value):
            return program.value, part.value, command.elts[position + 1]
    return None


def _is_command_flag(shell: str, flag: str) -> bool:
    """Return True for the flag that makes the next argument a command.

    That is ``-c``, also among other short flags (``-lc``, ``-ec``), and
    ``/c`` or ``/k`` for cmd.exe.
    """
    if shell == "cmd":
        return flag.lower() in {"/c", "/k"}
    return (
        flag.startswith("-")
        and not flag.startswith("--")
        and "c" in flag[1:]
        and flag[1:].isalpha()
    )
