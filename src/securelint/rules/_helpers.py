"""Small syntax-tree helpers shared by the rules."""

import ast

from securelint.context import MAX_HOPS, FileContext


def is_fixed(node: ast.expr, context: FileContext, hops: int = 0) -> bool:
    """Return True if the value is written in the source and cannot change.

    That is a literal such as ``"ls -l"`` or ``42``, a list or tuple made
    only of such literals, or a variable that was given such a value once
    and never changed. Fixed pieces put together are fixed as well:
    ``"ls " + "-l"``, ``f"{TABLE}_old"`` when ``TABLE`` is fixed, and
    ``", ".join("?" for _ in ids)``, which can only contain ``?`` and
    ``, `` however long it gets.

    A fixed value cannot carry an attack, because nobody outside the
    program can influence it.
    """
    if isinstance(node, ast.Constant):
        return True
    if isinstance(node, ast.List | ast.Tuple):
        return all(is_fixed(element, context, hops) for element in node.elts)
    # "ls " + "-l"   and   "%s items" % 10
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add | ast.Mod):
        return is_fixed(node.left, context, hops) and is_fixed(
            node.right, context, hops
        )
    # f"{TABLE}_old"
    if isinstance(node, ast.JoinedStr):
        return all(is_fixed(part, context, hops) for part in node.values)
    if isinstance(node, ast.FormattedValue):
        return is_fixed(node.value, context, hops) and (
            node.format_spec is None or is_fixed(node.format_spec, context, hops)
        )
    # ", ".join(...)
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "join"
        and len(node.args) == 1
        and not node.keywords
    ):
        return is_fixed(node.func.value, context, hops) and _has_fixed_items(
            node.args[0], context, hops
        )
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


def _has_fixed_items(node: ast.expr, context: FileContext, hops: int) -> bool:
    """Return True if every item of a sequence is fixed, whatever its length."""
    # "?" for _ in ids: the number of items changes, each item does not.
    if isinstance(node, ast.GeneratorExp | ast.ListComp | ast.SetComp):
        return is_fixed(node.elt, context, hops)
    if isinstance(node, ast.List | ast.Tuple | ast.Set):
        return all(is_fixed(element, context, hops) for element in node.elts)
    return False
