"""Corpus: loading data with a format that can run code (SL103)."""

import json
import marshal
import pickle
import pickle as pk
from pickle import loads

import pandas
import yaml
from yaml import SafeLoader, load


def session_from_cookie(request):
    return pickle.loads(request.cookies["session"])  # expect: SL103


def uploaded_model(uploaded_file):
    return pickle.load(uploaded_file)  # expect: SL103


def renamed_module(blob):
    return pk.loads(blob)  # expect: SL103


def imported_function(blob):
    return loads(blob)  # expect: SL103


def with_unpickler(stream):
    return pickle.Unpickler(stream).load()  # expect: SL103


def bytecode(blob):
    return marshal.loads(blob)  # expect: SL103


def config(document):
    return yaml.load(document)  # expect: SL103


def config_with_full_power(document):
    return yaml.load(document, Loader=yaml.Loader)  # expect: SL103


def config_unsafe(document):
    return yaml.unsafe_load(document)  # expect: SL103


def imported_yaml_load(document):
    return load(document)  # expect: SL103


def stored_in_a_variable(blob):
    restore = pickle.loads
    return restore(blob)  # missed: SL103


def shared_table(download_path):
    return pandas.read_pickle(download_path)  # missed: SL103


# ---- Safe code: nothing below is dangerous. ----


def config_safely(document):
    return yaml.safe_load(document)


def config_with_safe_loader(document):
    return yaml.load(document, Loader=yaml.SafeLoader)


def imported_safe_loader(document):
    return load(document, Loader=SafeLoader)


def from_json(text):
    return json.loads(text)


def save(state):
    return pickle.dumps(state)


def fixed_data():
    return pickle.loads(b"\x80\x04N.")


def deep_copy(state):
    return pickle.loads(pickle.dumps(state))  # false-alarm: SL103
