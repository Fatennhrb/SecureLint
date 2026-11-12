"""The detection rules that every scan runs."""

from securelint.engine import Rule
from securelint.rules.code_execution import DynamicCodeExecution
from securelint.rules.deserialization import UnsafeDeserialization
from securelint.rules.hardcoded_secrets import HardcodedSecret
from securelint.rules.shell_injection import ShellCommandInjection
from securelint.rules.sql_injection import SqlInjection

ALL_RULES: tuple[Rule, ...] = (
    DynamicCodeExecution(),
    ShellCommandInjection(),
    UnsafeDeserialization(),
    HardcodedSecret(),
    SqlInjection(),
)
