# Security policy

## Reporting a vulnerability

Please report a vulnerability in SecureLint privately, not in a public issue:
on GitHub, open the repository's **Security** tab and choose
**Report a vulnerability**. Only the maintainer sees the report.

Useful to include: the SecureLint version (`securelint --version`), what you
ran, what happened, and what you expected. A small file that shows the
problem helps most.

You can expect a first answer within a week. SecureLint is maintained by one
person in their spare time, so a fix may take longer; you will be told what
is planned, and credited in the changelog if you wish.

## What counts

Anything that breaks the promises in the [threat model](docs/threat-model.md),
for example:

- a scan that reports "passed" although a file could not be scanned,
- scanned code, a file name, a Trivy report or an AI answer that can change
  the verdict, fake a note, or run a script in a report,
- a secret or an AI key that leaves the machine, or reaches a log or report,
- a way to make the GitHub Action run commands it should not.

A rule that misses a dangerous line or reports a safe one is not a
vulnerability: please open a normal issue for it, with the line in question.

## Supported versions

Only the latest release receives security fixes.
