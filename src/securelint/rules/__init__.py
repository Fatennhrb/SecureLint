"""The detection rules that every scan runs."""

from securelint.engine import Rule
from securelint.rules.code_execution import DynamicCodeExecution

ALL_RULES: tuple[Rule, ...] = (DynamicCodeExecution(),)
