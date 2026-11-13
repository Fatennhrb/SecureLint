"""Corpus: running text as code (SL101)."""

import ast
import builtins
from builtins import eval as evaluate


def calculator(expression):
    return eval(expression)  # expect: SL101


def run_plugin(source):
    exec(source)  # expect: SL101


def formula(cell):
    return eval(f"{cell.left} + {cell.right}")  # expect: SL101


def through_builtins(data):
    return builtins.eval(data)  # expect: SL101


def renamed_import(data):
    return evaluate(data)  # expect: SL101


def compiled_first(source):
    code = compile(source, "<plugin>", "exec")
    exec(code)  # expect: SL101


def stored_in_a_variable(data):
    run = eval
    return run(data)  # expect: SL101


# ---- Safe code: nothing below is dangerous. ----


def fixed_expression():
    return eval("2 + 2")


def fixed_in_two_parts():
    return eval("2 + " + "2")


def model_in_evaluation_mode(model):
    model.eval()
    return model


def literal_only(text):
    return ast.literal_eval(text)
