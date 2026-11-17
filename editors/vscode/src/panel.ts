/**
 * The page shown in Lint's panel. Kept apart from the VS Code API so it
 * can be tested on its own.
 *
 * The page runs no script, and its Content Security Policy only lets it
 * load images and styles from the extension itself: nothing from the
 * network, and no inline code.
 */

export interface PanelResources {
  /** The source VS Code gives the webview for the extension's files. */
  readonly cspSource: string;
  /** Where the webview can load Lint's "all clean" drawing from. */
  readonly lintImage: string;
}

/** Return the HTML of Lint's panel while there is nothing to report. */
export function lintPanelHtml(resources: PanelResources): string {
  const source = escapeAttribute(resources.cspSource);
  const policy = [
    "default-src 'none'",
    `img-src ${source}`,
    "style-src 'unsafe-inline'",
  ].join("; ");
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="${policy}">
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
body { font-family: var(--vscode-font-family); color: var(--vscode-foreground);
  display: flex; flex-direction: column; align-items: center; gap: 8px;
  padding: 16px 8px; text-align: center; }
img { width: 96px; height: 96px; }
p { margin: 0; font-size: var(--vscode-font-size); }
.hint { color: var(--vscode-descriptionForeground); }
</style>
</head>
<body>
<img src="${escapeAttribute(resources.lintImage)}" alt="Lint, all clean">
<p>Lint is ready.</p>
<p class="hint">Open a Python file to have it checked.</p>
</body>
</html>`;
}

/** Escape a value for an HTML attribute written in double quotes. */
export function escapeAttribute(value: string): string {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll('"', "&quot;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;");
}
