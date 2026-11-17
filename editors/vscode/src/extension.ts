/**
 * SecureLint for VS Code.
 *
 * Checks Python files when they are opened or saved, shows what SecureLint
 * finds as squiggles, and shows Lint, the mascot, in its own panel.
 */

import * as vscode from "vscode";

import { Checker } from "./checker";
import { lintPanelHtml } from "./panel";

export function activate(context: vscode.ExtensionContext): void {
  const log = vscode.window.createOutputChannel("SecureLint", { log: true });
  const checker = new Checker(log);
  context.subscriptions.push(
    log,
    checker,
    ...checker.start(),
    vscode.window.registerWebviewViewProvider(
      "securelint.lint",
      new LintViewProvider(context.extensionUri),
    ),
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
