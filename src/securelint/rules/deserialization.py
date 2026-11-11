"""Rules about turning stored data back into Python objects."""

import ast
from collections.abc import Iterable

from securelint.engine import Rule
from securelint.model import Confidence, Finding, Severity
from securelint.rules._helpers import dotted_name, is_fixed

# Formats that can describe "call this function" as part of the data.
_PICKLE_LIKE = frozenset(
    {f"{module}.{function}" for module in ("pickle", "cPickle", "_pickle", "dill")
     for function in ("load", "loads", "Unpickler")}
    | {"marshal.load", "marshal.loads"}
)  # fmt: skip

_YAML_LOAD = frozenset({"yaml.load", "yaml.load_all"})
_YAML_ALWAYS_UNSAFE = frozenset({"yaml.unsafe_load", "yaml.unsafe_load_all"})

# Loaders that only build plain data: strings, numbers, lists, dicts.
_SAFE_YAML_LOADERS = frozenset(
    {"SafeLoader", "CSafeLoader", "BaseLoader", "CBaseLoader"}
)


class UnsafeDeserialization(Rule):
    """SL103: data is loaded with a format that can run code.

    A pickle file is not only data: it is a small program that rebuilds the
    objects, and it may call any function. YAML's full loaders can create
    arbitrary Python objects in the same way. Whoever can change the data
    can therefore run code in the program that loads it.

    Reported::

        pickle.load(uploaded_file)
        pickle.loads(request.data)
        yaml.load(document)
        yaml.load(document, Loader=yaml.Loader)

    Not reported::

        yaml.safe_load(document)
        yaml.load(document, Loader=yaml.SafeLoader)
        json.loads(text)                # JSON can only describe data
    """

    rule_id = "SL103"
    node_types = (ast.Call,)

    def check(self, node: ast.AST, path: str) -> Iterable[Finding]:
        if not isinstance(node, ast.Call):
            return []
        name = dotted_name(node.func)
        if name is None:
            return []
        # Data written in the source itself cannot be changed by anyone.
        if not node.args or is_fixed(node.args[0]):
            return []

        if name in _PICKLE_LIKE:
            message = (
                f"{name}() can run code hidden in the data it loads; only load "
                "data your own program wrote, or use a format such as JSON."
            )
            # Loading the program's own cache file is common and harmless,
            # and the rule cannot tell where the data comes from.
            confidence = Confidence.LOW
        elif name in _YAML_ALWAYS_UNSAFE or (
            name in _YAML_LOAD and not _uses_safe_yaml_loader(node)
        ):
            message = (
                f"{name}() without a safe loader can run code hidden in the "
                "document; use yaml.safe_load()."
            )
            # A safe loader does the same job, so this is rarely on purpose.
            confidence = Confidence.MEDIUM
        else:
            return []

        return [
            Finding(
                rule_id=self.rule_id,
                message=message,
                severity=Severity.HIGH,
                confidence=confidence,
                path=path,
                line=node.lineno,
                column=node.col_offset + 1,
            )
        ]


def _uses_safe_yaml_loader(call: ast.Call) -> bool:
    """Return True for ``yaml.load(data, Loader=<a safe loader>)``."""
    loader: ast.expr | None = None
    if len(call.args) >= 2:
        loader = call.args[1]
    for keyword in call.keywords:
        if keyword.arg == "Loader":
            loader = keyword.value
    if loader is None:
        return False
    name = dotted_name(loader)
    # "yaml.SafeLoader" and a directly imported "SafeLoader" both count.
    return name is not None and name.rpartition(".")[2] in _SAFE_YAML_LOADERS
