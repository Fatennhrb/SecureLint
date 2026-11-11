"""Rules about running text as code."""

import ast
from collections.abc import Iterable

from securelint.context import FileContext
from securelint.engine import Rule
from securelint.model import Confidence, Finding, Severity

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
    node_types = (ast.Call,)

    def check(self, node: ast.AST, context: FileContext) -> Iterable[Finding]:
        if not isinstance(node, ast.Call):
            return []
        name = context.qualified_name(node.func)
        if name not in _DANGEROUS_BUILTINS:
            return []
        # The code to run is always the first argument. A literal there is
        # fixed when the program is written, so it cannot be an attack.
        if not node.args or isinstance(node.args[0], ast.Constant):
            return []
        return [
            Finding(
                rule_id=self.rule_id,
                message=(
                    f"{name.removeprefix('builtins.')}() runs its argument as "
                    "Python code; "
                    "if that value can come from a user, they can run any code."
                ),
                severity=Severity.HIGH,
                # The rule sees that the argument is not fixed, but not where
                # it comes from, so it cannot be fully sure.
                confidence=Confidence.MEDIUM,
                path=context.path,
                line=node.lineno,
                column=node.col_offset + 1,
            )
        ]
