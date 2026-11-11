"""Small syntax-tree helpers shared by the rules."""

import ast


def is_fixed(node: ast.expr) -> bool:
    """Return True if the value is written in the source and cannot change.

    That is a literal such as ``"ls -l"`` or ``42``, or a list or tuple
    made only of such literals. A fixed value cannot carry an attack,
    because nobody outside the program can influence it.
    """
    if isinstance(node, ast.Constant):
        return True
    if isinstance(node, ast.List | ast.Tuple):
        return all(is_fixed(element) for element in node.elts)
    return False
