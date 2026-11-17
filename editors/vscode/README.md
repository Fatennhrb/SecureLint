# SecureLint for VS Code

Security problems in your Python code, shown as you work and explained by
**Lint**, SecureLint's mascot.

This extension runs [SecureLint](https://github.com/Fatennhrb/SecureLint), a
security scanner for Python, on the files you open and save.

## What it does

- **Squiggles on save.** Each time a Python file is opened or saved,
  SecureLint checks it. What it finds is underlined and listed in the
  Problems panel: red for high and critical, yellow for medium, blue for low.
  Findings your project's policy only warns about are never shown in red.
- **Lint's panel.** The SecureLint icon in the activity bar opens Lint, who
  shows the problems of the file you are editing. Lint is all clean when
  there is nothing to fix, thinks while SecureLint works, and shows the
  problem list when it finds something. Click a problem to go to its line.
- **Ask Lint.** Ask for a short explanation of a problem and how to fix it,
  written by the AI provider your project chose. The answer is marked
  "AI explanation (may be wrong)". **Copy fix** copies the suggested fix,
  for you to check and paste.
- **Silence this.** Adds `# securelint: ignore[SL102]` to the line and selects
  a placeholder for the reason, which SecureLint asks for.

Ask Lint and Silence this are also in the lightbulb menu (`Ctrl+.`) on each
squiggle.

## Requirements

- SecureLint 1.1.0 or newer: `pip install -U securelint`. Squiggles work
  with 1.0.0; Ask Lint needs 1.1.0.
- For Ask Lint: an AI provider set up in the project's `pyproject.toml`, under
  `[tool.securelint.ai]`, with its key in an environment variable. See
  [Explaining findings with an AI](https://github.com/Fatennhrb/SecureLint#explaining-findings-with-an-ai).

## Settings

| Setting | Default | Meaning |
|---------|---------|---------|
| `securelint.executable` | `securelint` | The SecureLint program to run, or its full path. Only your own settings can change it, not a folder's settings. |

## Privacy and safety

- The extension sends nothing anywhere by itself. Checking a file runs
  SecureLint on your machine.
- Ask Lint sends something to an AI only when you click it, and only through
  SecureLint: the finding and the few lines around it, with secrets replaced
  by `***`, never the whole file. Explanations are cached in
  `.securelint-cache/`, so asking again about unchanged code sends nothing.
- The extension only runs in folders you trust, since it runs a program on
  your files.
- Lint's panel runs no script and loads nothing from the network. Its links
  can only run the extension's own commands, which accept only files that
  were checked.
- Lint stays still when VS Code's Reduce Motion setting is on.

## License

MIT
