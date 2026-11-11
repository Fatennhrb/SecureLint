"""Tests for SL103, loading data with a format that can run code."""

from pathlib import Path

import pytest

from securelint.engine import scan
from securelint.model import Confidence, Finding, Severity
from securelint.rules.deserialization import UnsafeDeserialization


def findings_in(tmp_path: Path, code: str) -> tuple[Finding, ...]:
    (tmp_path / "app.py").write_text(code, encoding="utf-8")
    return scan(tmp_path, [UnsafeDeserialization()]).findings


@pytest.mark.parametrize(
    "code",
    [
        "pickle.load(uploaded_file)\n",
        "pickle.loads(request.data)\n",
        "pickle.Unpickler(stream).load()\n",
        "cPickle.loads(data)\n",
        "dill.load(file)\n",
        "dill.loads(data)\n",
        "marshal.load(file)\n",
        "marshal.loads(data)\n",
        "with open(path, 'rb') as f:\n    state = pickle.load(f)\n",
        "yaml.load(document)\n",
        "yaml.load(document, Loader=yaml.Loader)\n",
        "yaml.load(document, Loader=yaml.FullLoader)\n",
        "yaml.load(document, Loader=yaml.UnsafeLoader)\n",
        "yaml.load(document, yaml.Loader)\n",
        "yaml.load(document, Loader=get_loader())\n",
        "yaml.load_all(document)\n",
        "yaml.unsafe_load(document)\n",
        "yaml.unsafe_load_all(document)\n",
    ],
)
def test_reports_unsafe_loading(tmp_path: Path, code: str) -> None:
    assert [finding.rule_id for finding in findings_in(tmp_path, code)] == ["SL103"]


@pytest.mark.parametrize(
    "code",
    [
        "yaml.safe_load(document)\n",
        "yaml.safe_load_all(document)\n",
        "yaml.load(document, Loader=yaml.SafeLoader)\n",
        "yaml.load(document, Loader=yaml.CSafeLoader)\n",
        "yaml.load(document, Loader=yaml.BaseLoader)\n",
        "yaml.load(document, Loader=SafeLoader)\n",
        "yaml.load(document, yaml.SafeLoader)\n",
        "yaml.load_all(document, Loader=yaml.SafeLoader)\n",
        # Formats that can only describe data.
        "json.load(file)\n",
        "json.loads(text)\n",
        "tomllib.load(file)\n",
        # Writing is not loading.
        "pickle.dump(state, file)\n",
        "pickle.dumps(state)\n",
        "yaml.dump(config)\n",
        # Data fixed in the source.
        "pickle.loads(b'\\x80\\x04N.')\n",
        "yaml.load('key: value')\n",
        # Other things that only share a name.
        "loader.load(file)\n",
        "config.loads(text)\n",
        "pickle.load()\n",
    ],
)
def test_does_not_report_safe_code(tmp_path: Path, code: str) -> None:
    assert findings_in(tmp_path, code) == ()


def test_pickle_finding_details(tmp_path: Path) -> None:
    code = "import pickle\n\ndef restore(blob):\n    return pickle.loads(blob)\n"

    (finding,) = findings_in(tmp_path, code)

    assert finding.path == "app.py"
    assert (finding.line, finding.column) == (4, 12)
    assert finding.severity is Severity.HIGH
    # Loading your own pickle file is common, so the rule is less sure here.
    assert finding.confidence is Confidence.LOW
    assert finding.message.startswith("pickle.loads() can run code hidden in the data")


def test_yaml_finding_details(tmp_path: Path) -> None:
    (finding,) = findings_in(tmp_path, "config = yaml.load(document)\n")

    assert (finding.line, finding.column) == (1, 10)
    assert finding.severity is Severity.HIGH
    assert finding.confidence is Confidence.MEDIUM
    assert finding.message.startswith("yaml.load() without a safe loader")
    assert "yaml.safe_load()" in finding.message
