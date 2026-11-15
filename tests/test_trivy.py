"""Tests for reading Trivy reports (rule SL201).

The reports here are written by hand in the shape of Trivy's JSON format
(`trivy fs --format json`), with only the fields SecureLint reads.
"""

import json
from pathlib import Path
from typing import Any

import pytest

from securelint.cli import main
from securelint.model import Confidence, Severity
from securelint.trivy import TrivyReportError, read_trivy_report

REQUIREMENTS = "# web\nrequests==2.25.0\nDjango[argon2]==4.2.0\n"


def vulnerability(**fields: Any) -> dict[str, Any]:
    return {
        "VulnerabilityID": "CVE-2023-32681",
        "PkgName": "requests",
        "InstalledVersion": "2.25.0",
        "FixedVersion": "2.31.0",
        "Severity": "MEDIUM",
        "Title": "requests: Proxy-Authorization header leaked",
    } | fields


def report(*vulnerabilities: dict[str, Any], target: str = "requirements.txt") -> Any:
    return {
        "SchemaVersion": 2,
        "ArtifactName": ".",
        "Results": [
            {
                "Target": target,
                "Class": "lang-pkgs",
                "Type": "pip",
                "Vulnerabilities": list(vulnerabilities),
            }
        ],
    }


def write_report(tmp_path: Path, document: Any) -> Path:
    path = tmp_path / "trivy.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


@pytest.fixture
def project(tmp_path: Path) -> Path:
    folder = tmp_path / "project"
    folder.mkdir()
    (folder / "requirements.txt").write_text(REQUIREMENTS, encoding="utf-8")
    return folder


def read(project: Path, document: Any) -> list[Any]:
    return read_trivy_report(
        write_report(project.parent, document), project, project.resolve()
    )


def test_a_vulnerability_becomes_a_finding(project: Path) -> None:
    (finding,) = read(project, report(vulnerability()))

    assert finding.rule_id == "SL201"
    assert finding.path == "requirements.txt"
    assert (finding.line, finding.column) == (2, 1)
    assert finding.severity is Severity.MEDIUM
    assert finding.confidence is Confidence.HIGH
    assert finding.message == (
        "requests 2.25.0 has a known vulnerability, CVE-2023-32681: requests: "
        "Proxy-Authorization header leaked. Upgrade to a fixed version (2.31.0)."
    )
    assert len(finding.fingerprint) == 16


@pytest.mark.parametrize(
    ("trivy", "severity"),
    [
        ("CRITICAL", Severity.CRITICAL),
        ("HIGH", Severity.HIGH),
        ("LOW", Severity.LOW),
        # No severity yet is not taken as harmless.
        ("UNKNOWN", Severity.MEDIUM),
    ],
)
def test_severities(project: Path, trivy: str, severity: Severity) -> None:
    (finding,) = read(project, report(vulnerability(Severity=trivy)))

    assert finding.severity is severity


@pytest.mark.parametrize("name", ["django", "DJANGO", "Django"])
def test_package_names_ignore_case_and_extras(project: Path, name: str) -> None:
    (finding,) = read(project, report(vulnerability(PkgName=name)))

    assert finding.line == 3


def test_dashes_dots_and_underscores_are_the_same(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text(
        "zope.interface==5.0\nPyYAML==5.3\n", encoding="utf-8"
    )
    document = report(
        vulnerability(PkgName="pyyaml"), vulnerability(PkgName="zope-interface")
    )

    lines = sorted(finding.line for finding in read(tmp_path, document))

    assert lines == [1, 2]


def test_other_files_are_searched_for_the_name(tmp_path: Path) -> None:
    (tmp_path / "poetry.lock").write_text(
        '[[package]]\nname = "requests-toolbelt"\n\n[[package]]\nname = "requests"\n',
        encoding="utf-8",
    )

    (finding,) = read(tmp_path, report(vulnerability(), target="poetry.lock"))

    # Not line 2: "requests-toolbelt" is another package.
    assert finding.line == 5


def test_a_package_that_is_not_written_in_the_file_is_on_line_1(
    project: Path,
) -> None:
    (finding,) = read(project, report(vulnerability(PkgName="urllib3")))

    assert finding.line == 1


def test_without_a_fixed_version(project: Path) -> None:
    (finding,) = read(project, report(vulnerability(FixedVersion="", Title="")))

    assert finding.message == (
        "requests 2.25.0 has a known vulnerability, CVE-2023-32681. "
        "No fixed version is available yet."
    )


def test_a_long_title_stays_on_one_short_line(project: Path) -> None:
    title = "first line\nsecond line " + "x" * 500

    (finding,) = read(project, report(vulnerability(Title=title)))

    assert "\n" not in finding.message
    assert "first line second line" in finding.message
    assert len(finding.message) < 320


def test_the_same_problem_listed_twice_is_reported_once(project: Path) -> None:
    findings = read(project, report(vulnerability(), vulnerability()))

    assert len(findings) == 1


def test_identity_survives_moving_but_not_a_new_version(project: Path) -> None:
    (before,) = read(project, report(vulnerability()))
    (project / "requirements.txt").write_text(
        "flask==3.0.0\n" + REQUIREMENTS, encoding="utf-8"
    )
    (moved,) = read(project, report(vulnerability()))
    (upgraded,) = read(project, report(vulnerability(InstalledVersion="2.26.0")))

    assert moved.line == before.line + 1
    assert moved.fingerprint == before.fingerprint
    assert upgraded.fingerprint != before.fingerprint


def test_results_without_vulnerabilities_are_skipped(project: Path) -> None:
    document = {
        "SchemaVersion": 2,
        "Results": [{"Target": "not-here.lock", "Class": "lang-pkgs"}],
    }

    assert read(project, document) == []
    assert read(project, {"SchemaVersion": 2}) == []


def test_with_both_rules_ignored_nothing_is_read(project: Path) -> None:
    path = write_report(project.parent, "not even a report")

    assert read_trivy_report(path, project, project, ignore={"SL201", "SL202"}) == []


@pytest.mark.parametrize(
    ("document", "message"),
    [
        ([], "the report is not an object"),
        ({"Results": {}}, "Results is not a list"),
        ({"Results": ["x"]}, "a result is not an object"),
        (report(vulnerability(PkgName=None)), "PkgName is missing"),
        (report(vulnerability(Severity="SEVERE")), "unknown severity 'SEVERE'"),
        (report(vulnerability(), target=""), "Target is missing"),
    ],
)
def test_a_report_of_the_wrong_shape_is_refused(
    project: Path, document: Any, message: str
) -> None:
    with pytest.raises(TrivyReportError, match=message):
        read(project, document)


@pytest.mark.parametrize(
    "target", ["../secrets.txt", "/etc/passwd", "C:/Windows/win.ini", "a/../../b"]
)
def test_paths_outside_the_folder_are_refused(project: Path, target: str) -> None:
    with pytest.raises(TrivyReportError, match="not a file of the scanned folder"):
        read(project, report(vulnerability(), target=target))


def test_a_file_missing_from_the_folder_is_refused(project: Path) -> None:
    # The report was made on another folder.
    with pytest.raises(TrivyReportError, match="run Trivy on the folder"):
        read(project, report(vulnerability(), target="backend/requirements.txt"))


def test_a_report_that_is_not_json_is_refused(project: Path) -> None:
    path = project.parent / "trivy.json"
    path.write_text("Total: 1 (HIGH: 1)", encoding="utf-8")

    with pytest.raises(TrivyReportError, match="cannot read the Trivy report"):
        read_trivy_report(path, project, project)


# The command line.


def scan(project: Path, *options: str) -> int:
    return main(["scan", str(project), *options])


def test_scan_reports_the_dependency_with_the_code(
    project: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    (project / "app.py").write_text("eval(x)\n", encoding="utf-8")
    path = write_report(project.parent, report(vulnerability()))

    assert scan(project, "--trivy-report", str(path)) == 1

    captured = capsys.readouterr()
    assert "app.py:1:1" in captured.out
    assert "requirements.txt:2:1  medium    SL201" in captured.out
    # app.py and requirements.txt: two files were checked, not one.
    assert "2 problems found in 2 files (1 high, 1 medium)." in captured.out
    assert "using Trivy report" in captured.err


def test_files_are_counted_once_and_only_with_problems(
    project: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    (project / "app.py").write_text("print('safe')\n", encoding="utf-8")
    two_problems = report(
        vulnerability(), vulnerability(VulnerabilityID="CVE-2024-35195")
    )
    nothing = {"SchemaVersion": 2, "Results": [{"Target": "requirements.txt"}]}

    scan(project, "--trivy-report", str(write_report(project.parent, two_problems)))
    with_problems = capsys.readouterr().out
    scan(project, "--trivy-report", str(write_report(project.parent, nothing)))
    without = capsys.readouterr().out

    assert "2 problems found in 2 files" in with_problems
    assert without == "No problems found in 1 file.\n"


def test_the_policy_applies_to_dependencies(
    project: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    (project / "pyproject.toml").write_text(
        '[tool.securelint.policy]\nblock-severity = "high"\n', encoding="utf-8"
    )
    path = write_report(project.parent, report(vulnerability()))

    # Medium is below the policy's "high": a warning, not a failure.
    assert scan(project, "--trivy-report", str(path)) == 0
    assert "Warnings: 1." in capsys.readouterr().out


def test_dependencies_can_be_put_in_the_baseline(
    project: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    (project / "pyproject.toml").write_text("[tool.securelint]\n", encoding="utf-8")
    path = write_report(project.parent, report(vulnerability()))

    assert main(["baseline", str(project), "--trivy-report", str(path)]) == 0
    assert scan(project, "--trivy-report", str(path)) == 0
    assert "Known problems not shown: 1." in capsys.readouterr().out


def test_sarif_names_the_rule(
    project: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = write_report(project.parent, report(vulnerability()))

    scan(project, "--trivy-report", str(path), "--format", "sarif")

    rules = json.loads(capsys.readouterr().out)["runs"][0]["tool"]["driver"]["rules"]
    assert rules[0]["id"] == "SL201"
    assert rules[0]["shortDescription"]["text"] == (
        "Dependency with a known vulnerability"
    )


def test_a_bad_report_stops_the_scan(
    project: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = write_report(project.parent, {"Results": "nope"})

    assert scan(project, "--trivy-report", str(path)) == 2
    assert "error: not a Trivy JSON report" in capsys.readouterr().err


def test_a_missing_report_stops_the_scan(
    project: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    missing = project.parent / "missing.json"

    assert scan(project, "--trivy-report", str(missing)) == 2
    assert "cannot read the Trivy report" in capsys.readouterr().err


def test_a_report_needs_a_folder(
    project: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    (project / "app.py").write_text("print('safe')\n", encoding="utf-8")
    path = write_report(project.parent, report(vulnerability()))

    assert main(["scan", str(project / "app.py"), "--trivy-report", str(path)]) == 2
    assert "needs a folder" in capsys.readouterr().err


def test_sl201_can_be_ignored_in_the_settings(
    project: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    (project / "pyproject.toml").write_text(
        '[tool.securelint]\nignore = ["SL201"]\n', encoding="utf-8"
    )
    path = write_report(project.parent, report(vulnerability()))

    assert scan(project, "--trivy-report", str(path)) == 0
    assert "No problems found" in capsys.readouterr().out


# Dockerfiles and other configuration files (rule SL202).

DOCKERFILE = "FROM python:3.13\nRUN apt-get update\nRUN apt-get update\nCOPY . /app\n"


def setting(line: int | None = 2, **fields: Any) -> dict[str, Any]:
    item: dict[str, Any] = {
        "ID": "DS017",
        "Title": "'RUN <package-manager> update' instruction alone",
        "Message": "The instruction 'RUN <package-manager> update' should always "
        "be followed by '<package-manager> install' in the same RUN statement.",
        "Resolution": "Combine '<package-manager> update' and "
        "'<package-manager> install' instructions to single one.",
        "Severity": "HIGH",
        "Status": "FAIL",
    }
    if line is not None:
        item["CauseMetadata"] = {"Provider": "Dockerfile", "StartLine": line}
    return item | fields


def settings_report(*items: dict[str, Any]) -> Any:
    return {
        "SchemaVersion": 2,
        "Results": [
            {
                "Target": "Dockerfile",
                "Class": "config",
                "Type": "dockerfile",
                "Misconfigurations": list(items),
            }
        ],
    }


@pytest.fixture
def docker(tmp_path: Path) -> Path:
    (tmp_path / "Dockerfile").write_text(DOCKERFILE, encoding="utf-8")
    return tmp_path


def test_a_failed_check_becomes_a_finding(docker: Path) -> None:
    (finding,) = read(docker, settings_report(setting()))

    assert finding.rule_id == "SL202"
    assert (finding.path, finding.line, finding.column) == ("Dockerfile", 2, 1)
    assert finding.severity is Severity.HIGH
    assert finding.confidence is Confidence.MEDIUM
    assert finding.message == (
        "'RUN <package-manager> update' instruction alone (DS017): The instruction "
        "'RUN <package-manager> update' should always be followed by "
        "'<package-manager> install' in the same RUN statement. Fix: Combine "
        "'<package-manager> update' and '<package-manager> install' instructions "
        "to single one."
    )


def test_a_check_about_the_whole_file_is_on_line_1(docker: Path) -> None:
    item = setting(
        line=None,
        ID="DS002",
        Title="Image user should not be 'root'",
        Message="Specify at least 1 USER command in Dockerfile.",
        Resolution="",
    )

    (finding,) = read(docker, settings_report(item))

    assert finding.line == 1
    assert finding.message == (
        "Image user should not be 'root' (DS002): "
        "Specify at least 1 USER command in Dockerfile."
    )


def test_only_failed_checks_are_problems(docker: Path) -> None:
    items = [
        setting(Status="PASS"),
        setting(Status="EXCEPTION"),
        # Without a status, the check is taken as failed, not as passed.
        {key: value for key, value in setting(line=3).items() if key != "Status"},
    ]

    (finding,) = read(docker, settings_report(*items))

    assert finding.line == 3


def test_identical_lines_are_two_problems_that_survive_moving(docker: Path) -> None:
    first = read(docker, settings_report(setting(2), setting(3)))
    (docker / "Dockerfile").write_text("# app\n" + DOCKERFILE, encoding="utf-8")
    moved = read(docker, settings_report(setting(4), setting(3)))

    assert len({finding.fingerprint for finding in first}) == 2
    assert {finding.fingerprint for finding in moved} == {
        finding.fingerprint for finding in first
    }


def test_a_line_the_file_does_not_have_is_refused(docker: Path) -> None:
    with pytest.raises(TrivyReportError, match="line 9 of Dockerfile, which has 4"):
        read(docker, settings_report(setting(9)))


@pytest.mark.parametrize("line", ["2", -1, True, 2.5])
def test_a_line_that_is_not_a_number_is_refused(docker: Path, line: object) -> None:
    item = setting() | {"CauseMetadata": {"StartLine": line}}

    with pytest.raises(TrivyReportError, match="StartLine is not a line"):
        read(docker, settings_report(item))


def test_a_check_without_an_id_is_refused(docker: Path) -> None:
    with pytest.raises(TrivyReportError, match="ID is missing"):
        read(docker, settings_report(setting(ID="")))


def test_each_rule_can_be_ignored_alone(docker: Path) -> None:
    (docker / "requirements.txt").write_text(REQUIREMENTS, encoding="utf-8")
    document = settings_report(setting())
    document["Results"] += report(vulnerability())["Results"]
    path = write_report(docker, document)

    without_dependencies = read_trivy_report(path, docker, docker, ignore={"SL201"})
    without_settings = read_trivy_report(path, docker, docker, ignore={"SL202"})

    assert [finding.rule_id for finding in without_dependencies] == ["SL202"]
    assert [finding.rule_id for finding in without_settings] == ["SL201"]


def test_sarif_names_the_dockerfile_rule(
    docker: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = write_report(docker.parent, settings_report(setting()))

    assert scan(docker, "--trivy-report", str(path), "--format", "sarif") == 1

    rules = json.loads(capsys.readouterr().out)["runs"][0]["tool"]["driver"]["rules"]
    assert rules[0]["id"] == "SL202"
    assert rules[0]["shortDescription"]["text"] == (
        "Unsafe setting in a Dockerfile or configuration file"
    )
