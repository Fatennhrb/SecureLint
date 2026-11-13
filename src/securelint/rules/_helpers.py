"""Small syntax-tree helpers shared by the rules."""

import ast

from securelint.context import FileContext

MAX_HOPS = 10
"""How many variables a rule follows one after the other (``a = b``, then
``b = c``...). The limit stops two variables that point at each other from
being followed for ever."""


def is_fixed(node: ast.expr, context: FileContext, hops: int = 0) -> bool:
    """Return True if the value is written in the source and cannot change.

    That is a literal such as ``"ls -l"`` or ``42``, a list or tuple made
    only of such literals, or a variable that was given such a value once
    and never changed. A fixed value cannot carry an attack, because
    nobody outside the program can influence it.
    """
    if isinstance(node, ast.Constant):
        return True
    if isinstance(node, ast.List | ast.Tuple):
        return all(is_fixed(element, context, hops) for element in node.elts)
    if isinstance(node, ast.Name) and hops < MAX_HOPS:
        value = context.value_of(node)
        if value is None:
            return False
        # A list kept in a variable can be changed after it is created
        # (command.append(...)), so it is not trusted to stay as written.
        if isinstance(value, ast.List):
            return False
        return is_fixed(value, context, hops + 1)
    return False
