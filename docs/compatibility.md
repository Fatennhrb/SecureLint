> [← Back to SecureLint overview](../README.md) · [Full original README snapshot](archive/README-original-2026-11-18.md)

> Contract and compatibility notes for the released command-line tool and planned 1.x series. Features under development are explicitly distinguished below.

## Stability

From version 1.0.0, SecureLint follows [semantic versioning](https://semver.org).
Within 1.x, these stay as they are, so a CI job or a program built on them
keeps working; only a 2.0.0 may change them:

- **The commands and options**: `securelint scan` with `--format`,
  `--no-baseline`, `--changed-since`, `--trivy-report` and `--explain`;
  `securelint baseline` with `--trivy-report`; `securelint explain` with
  `--line` and `--format` (from 1.1.0); `securelint --version`.
- **The exit codes**: 0 nothing blocks, 1 something blocks, 2 the scan could
  not be completed. For `explain`: 0 every finding on the line was explained,
  2 one was not.
- **The JSON report** (`format_version` 1): no field is removed or renamed;
  new fields may be added.
- **The SARIF report**: SARIF 2.1.0, with the `securelint/v1` fingerprints.
- **The rule ids** and what each one is about: `SL001`, `SL101` to `SL105`,
  `SL201` and `SL202`.
- **The fingerprints**: the same code gives the same fingerprint, so a
  baseline file keeps working after an update.
- **The settings** in `[tool.securelint]`, `[tool.securelint.policy]` and
  `[tool.securelint.ai]`, and the silencing comment
  `# securelint: ignore[SLxxx] reason`.
- **The GitHub Action's inputs**: `path`, `changed-only`, `sarif-file`,
  `python-version`, `trivy` and `explain`.

Not promised, because improving them is the point of new versions:

- **Which lines are reported.** A rule that gets better finds new problems
  and drops false alarms, so a minor version can report findings an older
  one did not. The baseline keeps those from failing a project at once.
- The wording of messages, the layout of the text and HTML reports and of
  the job summary, and the text of AI explanations.
- The measured numbers in this README (detection, speed), which are measured
  again for each version.
