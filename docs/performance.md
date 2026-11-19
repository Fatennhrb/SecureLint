> [← Back to SecureLint overview](../README.md) · [Full original README snapshot](archive/README-original-2026-11-18.md)

> Benchmarks were recorded on one laptop using the fastest of five runs; details and caveats are retained below.

## How fast is it?

Measured by scanning Python's own standard library, 3,659 files and 58.6 MB,
with all five rules (`python benchmarks/scan_speed.py`), keeping the fastest
of five runs:

| Version | Time | Speed | Measured on |
|---------|-----:|------:|-------------|
| 0.1.0 | 12.25 s | 299 files per second | 2026-11-12 |
| 0.2.0 | 11.64 s | 314 files per second | 2026-11-13 |
| 0.3.0 | 14.06 s | 260 files per second | 2026-11-14 |
| 0.4.0 | 11.68 s | 313 files per second | 2026-11-15 |
| 0.5.0 | 11.77 s | 311 files per second | 2026-11-15 |
| 0.6.0 | 11.91 s | 307 files per second | 2026-11-15 |
| 1.0.0 | 11.68 s | 313 files per second | 2026-11-16 |

All were measured on the same laptop with Python 3.13.5 on Windows 11.

The laptop itself was slower on 2026-11-14, so the 0.3.0 row cannot be
compared with the others. Version 0.2.0 was timed again that day, right
after version 0.3.0, and took 15.36 s. Measured side by side, version 0.3.0 is
therefore not slower than version 0.2.0. Its new features (settings, silencing
comments, fingerprints, the baseline and the policy) do their work only on
files that have findings, or after the scan.

Version 0.3.0 was timed again on 2026-11-15, right after version 0.4.0, and
took 11.65 s: the two are as fast as each other. The 0.4.0 features (SARIF,
GitHub notes, changed lines) only change what is reported after the scan.

Version 0.4.0 was timed again right before version 0.5.0 and took 11.75 s, so
these two are as fast as each other too. This benchmark scans Python code
only; reading a Trivy report adds the time Trivy itself takes, which depends
on Trivy and not on SecureLint.

Version 0.5.0 was timed again right after version 0.6.0 and took 12.34 s: the
two are as fast as each other. Explanations are asked for only with
`--explain`, after the scan, so the time they take is the AI's answer time,
not the scan's.

Version 0.6.0 was timed again right after version 1.0.0 and took 11.86 s: the
two are as fast as each other, as expected, since 1.0.0 changed no rule.

Version 0.2.0 does more work for each file, because it follows values through
variables, yet it is not slower. A first attempt at that feature walked every
file twice and took 25 s; this benchmark showed it, and the two walks were
merged into one.

This is one laptop, so the numbers are a reference point for later versions
and not a promise. The very first scan of files the system has not read
recently is much slower (131 s when version 0.1.0 was measured), because the
time then goes to reading from the disk.
