"""Rules about running text as code."""

import ast
from collections.abc import Iterable

from securelint.context import FileContext
from securelint.engine import Rule
from securelint.model import Confidence, Finding, Severity
from securelint.rules._helpers import is_fixed
from securelint.rules._sources import find_source, with_source

_DANGEROUS_BUILTINS = frozenset({"eval", "exec", "builtins.eval", "builtins.exec"})


class DynamicCodeExecution(Rule):
    """SL101: ``eval()`` or ``exec()`` is called with a value built at run time.

    Both functions run a string as Python code. If any part of that string
    can come from outside the program (a web form, a file, a network
    message), whoever controls it can run any code they like.

    Reported::

        eval(user_input)
        exec(f"result = {expression}")
        builtins.eval(data)

    Not reported::

        eval("2 + 2")        # a fixed string: nobody can change it
        model.eval()         # a method that only shares the name
    """

    rule_id = "SL101"
    title = "Code built at run time is run with eval() or exec()"
    node_types = (ast.Call,)

    def check(self, node: ast.AST, context: FileContext) -> Iterable[Finding]:
        if not isinstance(node, ast.Call):
            return []
        name = context.qualified_name(node.func)
        if name not in _DANGEROUS_BUILTINS:
            return []
        # The code to run is always the first argument. A literal there is
        # fixed when the program is written, so it cannot be an attack.
        if not node.args or is_fixed(node.args[0], context):
            return []
        # The rule sees that the argument is not fixed. Unless it also
        # finds where the value comes from, it cannot be fully sure.
        message, confidence = with_source(
            f"{name.removeprefix('builtins.')}() runs its argument as Python "
            "code; if that value can come from a user, they can run any code.",
            Confidence.MEDIUM,
            find_source(node.args[0], context),
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
