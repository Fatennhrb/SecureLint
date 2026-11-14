"""Rules about running operating-system commands."""

import ast
from collections.abc import Iterable

from securelint.context import FileContext
from securelint.engine import Rule
from securelint.model import Confidence, Finding, Severity
from securelint.rules._helpers import is_fixed
from securelint.rules._sources import find_source, with_source

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
        if name in _ALWAYS_SHELL:
            label = f"{name}()"
        elif name in _SHELL_ON_REQUEST and _has_shell_true(node):
            label = f"{name}(..., shell=True)"
        else:
            return []

        command = _command_argument(node)
        if command is None or is_fixed(command, context):
            return []
        # The rule sees that the command is not fixed. Unless it also
        # finds where a part comes from, it cannot be fully sure.
        message, confidence = with_source(
            f"{label} runs its command through the shell; if any part of the "
            "command can come from a user, they can run their own commands.",
            Confidence.MEDIUM,
            find_source(command, context),
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


def _has_shell_true(call: ast.Call) -> bool:
    return any(
        keyword.arg == "shell"
        and isinstance(keyword.value, ast.Constant)
        and keyword.value.value is True
        for keyword in call.keywords
    )


def _command_argument(call: ast.Call) -> ast.expr | None:
    if call.args:
        return call.args[0]
    for keyword in call.keywords:
        if keyword.arg in _COMMAND_KEYWORDS:
            return keyword.value
    return None
