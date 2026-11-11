"""Small syntax-tree helpers shared by the rules."""

import ast


def dotted_name(node: ast.expr) -> str | None:
    """Return the name a call is made on, e.g. ``"os.system"`` or ``"eval"``.

    Returns ``None`` when the expression is not a plain chain of names, for
    example ``get_module().system``.
    """
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return ".".join(reversed(parts))
    return None


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
