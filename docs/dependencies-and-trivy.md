> [← Back to SecureLint overview](../README.md) · [Full original README snapshot](archive/README-original-2026-11-18.md)

> SecureLint accepts Trivy JSON findings alongside its own source-code findings. The GitHub Action can invoke Trivy when configured.

## Checking dependencies and Dockerfiles with Trivy

SecureLint checks the code you write. The packages a project uses can have
known vulnerabilities too, and its Dockerfile can have unsafe settings;
[Trivy](https://trivy.dev) finds both. SecureLint does not run Trivy: run it
yourself on the same folder, then give SecureLint its JSON report.

```console
trivy fs --scanners vuln,misconfig --format json --output trivy.json .
securelint scan . --trivy-report trivy.json
```

Each vulnerability becomes a finding of rule `SL201`, reported on the line of
`requirements.txt` (or of the lock file) that names the package, with the
installed version and the version that fixes it.

Each failed check of a Dockerfile (or of another configuration file Trivy
checks) becomes a finding of rule `SL202`, on the line Trivy points to, with
Trivy's check ID and how to fix it. A check about the whole file, such as a
missing `USER` line, is reported on line 1. Checks the file passed, and those
the project accepted as exceptions, are not reported. Trivy's secret scanner is
not read; rule `SL104` looks for secrets in the code.

The baseline, the policy, `--changed-since` and every report format work for
these findings as for the code's.
`securelint baseline --trivy-report trivy.json` records them as known; run
Trivy on the top of the project for that.

A dependency finding keeps its identity when other lines of the file change,
and becomes new when the package's version changes. A Dockerfile finding is
identified like the code's: by its check and the text of its line.

The report is checked before it is used: one that cannot be read, is not a
Trivy JSON report, or names a file outside the scanned folder stops the scan
with exit code 2, instead of being taken as "no problems".
