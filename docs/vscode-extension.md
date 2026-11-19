> [← Back to SecureLint overview](../README.md) · [Full original README snapshot](archive/README-original-2026-11-18.md)

> Experimental development extension on `main`, not included with the published PyPI 1.0.0 package and not listed on the VS Code Marketplace. See the [extension setup guide](../editors/vscode/README.md).

## VS Code extension

The extension in
[`editors/vscode`](https://github.com/Fatennhrb/SecureLint/tree/main/editors/vscode)
runs SecureLint on the Python files you open and save, with Lint, the mascot,
in its own panel:

- **Squiggles on save.** Findings are underlined and listed in the Problems
  panel: red for high and critical, yellow for medium, blue for low.
- **Lint's panel.** Lint shows the problems of the file you are editing: all
  clean, thinking while SecureLint works, or the problem list. Click a problem
  to go to its line.
- **Ask Lint.** A short explanation and fix from the project's AI provider,
  marked "AI explanation (may be wrong)", with **Copy fix** to copy the fix.
  It runs `securelint explain FILE --line N` (see
  [Explaining one line](ai-explanations.md#explaining-one-line)), so it uses the same settings,
  masking and cache.
- **Silence this.** Adds `# securelint: ignore[SL102]` to the line, with a
  placeholder for the reason.

The panel runs no script and loads nothing from the network, the extension
only starts in folders VS Code trusts, and Lint stays still when VS Code's
Reduce Motion setting is on. Its tests run inside VS Code 1.100.0, the oldest
version it supports, on every push.

It is not on the VS Code Marketplace yet. Each CI run builds it as
`securelint.vsix` (in the run's **securelint-vsix** artifact); install it with
**Extensions > ... > Install from VSIX**, or build it yourself:

```bash
cd editors/vscode
npm ci --ignore-scripts
npm run package
code --install-extension securelint.vsix
```

Squiggles work with SecureLint 1.0.0; Ask Lint needs `securelint explain`,
which is in this repository and comes to PyPI with version 1.1.0. Its own
[README](https://github.com/Fatennhrb/SecureLint/blob/main/editors/vscode/README.md)
lists its setting and how it treats your code.
