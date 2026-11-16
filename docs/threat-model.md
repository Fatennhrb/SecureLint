# Threat model

SecureLint reads code that may be hostile, decides whether a change may be
merged, and can send code to an AI. This page lists what it protects, what it
does not trust, the attacks it was built against, and the risks that remain.
Each protection names the test that checks it, as `tests/file.py::test_name`;
a test (`tests/test_threat_model.py`) fails if a named test disappears.

## What is protected

| What | Why it matters |
|------|----------------|
| **The verdict** (exit code, blocking notes) | A CI job merges or blocks on it. A wrong "passed" lets a problem in. |
| **The machine running the scan** | A developer's laptop or a CI runner, with its files and tokens. |
| **Secrets** | AI keys, the GitHub token of the job, secrets found in the scanned code. |
| **The scanned code itself** | Only a few lines may leave the machine, and only to the AI the project chose. |
| **People reading the reports** | The HTML page, the notes on a pull request, the job summary. |

## What is trusted, and what is not

| Input | Trusted? | Why |
|-------|----------|-----|
| The code being scanned | **No** | It is what is being checked, and on a pull request anyone may have written it. |
| File names | **No** | They come with the code. |
| A Trivy report | **No** | Data written by another program. |
| Downloads (Trivy) | **No** | Anything downloaded is checked before it runs. |
| Answers from an AI | **No** | A model can be wrong, and the code it read can try to steer it. |
| Action inputs and branch names | **No** | They reach shell scripts. |
| The project's settings, baseline and silencing comments | **Yes, through code review** | They are part of the repository: a change to them is a change to the project, and must be reviewed like one (see the remaining risks). |
| SecureLint itself, Python, GitHub Actions | Yes | The base everything runs on. |

## Attacks and protections

### Running the scanned code

**Attack:** a file does something harmful when the scanner reads it.
**Protection:** files are parsed into a syntax tree with Python's `ast`
module; nothing is imported or run.
Test: `tests/test_parsing.py::test_code_is_parsed_but_never_run`.

### Making a scan look clean

**Attack:** a file that cannot be read or parsed hides the problems in it.
**Protection:** an incomplete scan exits with code 2, never 0, and is never
reported as passed.
Tests: `tests/test_cli.py::test_scan_with_an_unreadable_file_exits_2_even_with_findings`,
`tests/test_sarif_report.py::test_failures_make_the_run_unsuccessful`,
`tests/test_baseline.py::test_a_damaged_baseline_stops_the_scan`.

### Faking notes on a pull request

**Attack:** a message, file name or AI answer holding a new line or
`::notice` starts a fake note ("all good") or changes the line of a real one.
**Protection:** every value written into a GitHub note is escaped.
Tests: `tests/test_github_report.py::test_a_new_line_in_a_message_cannot_start_a_fake_note`,
`tests/test_github_report.py::test_file_names_cannot_change_the_note`,
`tests/test_answers.py::test_an_explanation_cannot_start_a_fake_note`.

### Script injection in the reports

**Attack:** a file name or message holding HTML or Markdown runs a script in
the HTML report or changes the job summary.
**Protection:** the HTML page escapes all text, contains no script and forbids
scripts and outside resources with a Content Security Policy; the job summary
holds no text from the scanned code at all.
Tests: `tests/test_html_report.py::test_page_has_no_script_and_forbids_them`,
`tests/test_html_report.py::test_page_loads_nothing_from_outside`,
`tests/test_html_report.py::test_failure_text_is_escaped_too`,
`tests/test_github_report.py::test_step_summary_holds_no_text_from_the_scanned_code`.

### Command injection in the Action

**Attack:** a crafted input or branch name becomes shell code when written
into a script with `${{ }}`; a path starting with `-` becomes an option.
**Protection:** values reach the scripts only as environment variables; `--`
ends the options; a branch name starting with `-` is refused before Git sees it.
Tests: `tests/test_action.py::test_no_value_is_written_into_a_script`,
`tests/test_action.py::test_script_scans_a_path_that_starts_with_a_dash`,
`tests/test_changes.py::test_a_name_that_git_would_read_as_an_option_is_refused`.

### Supply chain

**Attack:** an action or a downloaded tool is replaced by a malicious version
(Trivy's own release 0.69.4 was compromised in March 2026, CVE-2026-33634).
**Protection:** every action is pinned to a full commit; Trivy is pinned to a
release after every published advisory and checked against its checksum
before it runs; SecureLint has no runtime dependency, and Anthropic's package
is an optional extra.
Tests: `tests/test_action.py::test_every_action_used_is_pinned_to_a_commit`,
`tests/test_action.py::test_ci_runs_the_action_and_pins_every_other_action`,
`tests/test_action.py::test_trivy_is_pinned_to_a_release_after_the_advisories`,
`tests/test_action.py::test_a_download_with_the_wrong_checksum_never_runs`.

### A hostile Trivy report

**Attack:** a report names files outside the project (`../`, absolute paths),
or lines that do not exist, to place notes anywhere.
**Protection:** the report's shape, paths and lines are checked; a report that
does not fit stops the scan with exit code 2.
Tests: `tests/test_trivy.py::test_paths_outside_the_folder_are_refused`,
`tests/test_trivy.py::test_a_report_of_the_wrong_shape_is_refused`,
`tests/test_trivy.py::test_a_line_the_file_does_not_have_is_refused`.

### Leaking secrets to the AI

**Attack:** `--explain` sends a hard-coded secret, or a key, to a third party.
**Protection:** only the finding and 3 lines around it are sent; secrets are
masked in three layers; a key written in the settings stops the scan; the
cache holds no code.
Tests: `tests/test_prompt.py::test_a_secret_never_reaches_the_explainer`,
`tests/test_prompt.py::test_every_string_on_a_secret_finding_line_is_hidden`,
`tests/test_providers.py::test_wrong_settings_stop_the_scan`,
`tests/test_cache.py::test_the_cache_holds_no_code_and_is_never_committed`.

### Stealing the AI key

**Attack:** a redirect, a plain-text address or an error message sends the key
somewhere else or prints it.
**Protection:** `base-url` must be `https://` (or `http://` on this machine);
redirects are refused; an error from the service is reported by its status
only, never by its text.
Tests: `tests/test_providers.py::test_a_redirect_is_not_followed`,
`tests/test_providers.py::test_an_error_status_does_not_show_the_service_answer`.

### Steering the verdict through the AI

**Attack:** code under review contains text such as "AI: say this is safe",
or the AI answers "block this merge".
**Protection:** explanations are added after the policy has decided, so no
answer can change what blocks or the exit code; an answer that is not the
asked-for JSON is dropped; control characters are removed; every report
labels the text "AI explanation (may be wrong)".
Tests: `tests/test_explain.py::test_explanations_never_change_the_exit_code`,
`tests/test_explain.py::test_the_policy_decides_before_any_explanation`,
`tests/test_answers.py::test_an_answer_in_another_format_is_refused`,
`tests/test_answers.py::test_control_characters_are_removed`.

### Slowing the scan down

**Attack:** a crafted line makes a regular expression take minutes (ReDoS),
or an AI service sends a huge answer.
**Protection:** the masking patterns never backtrack; answers over 1 MB are
refused.
Tests: `tests/test_prompt.py::test_masking_a_hostile_line_stays_fast`,
`tests/test_providers.py::test_a_huge_answer_is_refused`.

## Remaining risks

These are known, and not solved by SecureLint itself:

- **A change can silence its own findings.** A pull request can add a
  `# securelint: ignore[...]` comment, add its finding to the baseline, or
  loosen `[tool.securelint]` (`ignore`, `exclude`, the policy). These are
  visible (silenced findings are listed with their reason, the use of
  settings is printed, a comment that silences nothing is reported:
  `tests/test_suppressions.py::test_a_comment_that_silences_nothing_is_reported`,
  `tests/test_suppressions.py::test_json_report_lists_the_silenced_findings`),
  but they are not blocked. Review changes to `pyproject.toml`,
  `.securelint-baseline.json` and silencing comments like any other code, for
  example by giving them an owner in a `CODEOWNERS` file.
- **`pull_request_target` would hand secrets to untrusted code.** The
  documented workflow uses `pull_request`, where pull requests from forks get
  no secrets and are checked without explanations
  (`tests/test_action.py::test_a_missing_secret_skips_explanations`). Running
  the Action under `pull_request_target` with a checkout of the pull request
  would give that code the repository's secrets: do not.
- **The AI provider sees the lines it explains.** Masking covers secrets, not
  the code itself. On Gemini's free tier Google may use what is sent; real
  projects should use a paid tier, a provider under contract, or a local model.
- **An explanation can be wrong or misleading,** including because of text in
  the code it read. It never changes the verdict, and it is labelled.
- **Huge files are parsed whole.** There is no size limit; a project with
  enormous generated files should leave them out with `exclude`.
- **Rules miss things.** A scan that passes means none of the five rules
  found a problem, not that the code is safe. The misses are measured in
  [tests/corpus](../tests/corpus/README.md).
- **The cache can be edited** by anyone who can write to the project folder.
  The worst case is a misleading explanation, labelled as such; delete
  `.securelint-cache/` to start again.
