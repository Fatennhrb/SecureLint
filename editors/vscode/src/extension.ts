/**
 * SecureLint for VS Code.
 *
 * For now it only shows Lint, the mascot, in its own panel. Later steps
 * run SecureLint on Python files and show what it finds.
 */

import * as vscode from "vscode";

import { lintPanelHtml } from "./panel";

export function activate(context: vscode.ExtensionContext): void {
  const provider = new LintViewProvider(context.extensionUri);
  context.subscriptions.push(
    vscode.window.registerWebviewViewProvider("securelint.lint", provider),
  );
}

export function deactivate(): void {
  // Nothing to clean up: VS Code disposes of what was registered.
}

class LintViewProvider implements vscode.WebviewViewProvider {
  constructor(private readonly extensionUri: vscode.Uri) {}

  resolveWebviewView(view: vscode.WebviewView): void {
    const media = vscode.Uri.joinPath(this.extensionUri, "media");
    view.webview.options = {
      // The page runs no script and may only read the media folder.
      enableScripts: false,
      localResourceRoots: [media],
    };
    view.webview.html = lintPanelHtml({
      cspSource: view.webview.cspSource,
      lintImage: view.webview
        .asWebviewUri(vscode.Uri.joinPath(media, "lint-clean.svg"))
        .toString(),
    });
  }
}
