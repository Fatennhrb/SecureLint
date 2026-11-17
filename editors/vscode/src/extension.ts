/**
 * SecureLint for VS Code.
 *
 * Checks Python files when they are opened or saved, shows what SecureLint
 * finds as squiggles, and shows Lint, the mascot, in its own panel with
 * the problems of the file being edited.
 */

import * as vscode from "vscode";

import { Checker, lineRange } from "./checker";
import { lintPanelHtml, type PanelView, REVEAL_COMMAND } from "./panel";

export function activate(context: vscode.ExtensionContext): void {
  const log = vscode.window.createOutputChannel("SecureLint", { log: true });
  const checker = new Checker(log);
  const panel = new LintViewProvider(context.extensionUri, checker);
  context.subscriptions.push(
    log,
    checker,
    ...checker.start(),
    vscode.window.registerWebviewViewProvider("securelint.lint", panel),
    vscode.window.onDidChangeActiveTextEditor(() => {
      panel.refresh();
    }),
    checker.onDidChangeState((uri) => {
      if (uri.toString() === vscode.window.activeTextEditor?.document.uri.toString()) {
        panel.refresh();
      }
    }),
    vscode.commands.registerCommand(REVEAL_COMMAND, (uri: unknown, line: unknown) =>
      revealProblem(checker, uri, line),
    ),
  );
}

export function deactivate(): void {
  // Nothing to clean up: VS Code disposes of what was registered.
}

class LintViewProvider implements vscode.WebviewViewProvider {
  private view: vscode.WebviewView | undefined;

  constructor(
    private readonly extensionUri: vscode.Uri,
    private readonly checker: Checker,
  ) {}

  resolveWebviewView(view: vscode.WebviewView): void {
    this.view = view;
    view.webview.options = {
      // The page runs no script, may only read the media folder, and its
      // links may only run the command that jumps to a problem.
      enableScripts: false,
      enableCommandUris: [REVEAL_COMMAND],
      localResourceRoots: [this.media()],
    };
    view.onDidDispose(() => {
      this.view = undefined;
    });
    this.refresh();
  }

  /** Show the state of the file being edited. */
  refresh(): void {
    if (this.view === undefined) {
      return;
    }
    const webview = this.view.webview;
    const image = (mood: string): string =>
      webview.asWebviewUri(vscode.Uri.joinPath(this.media(), `lint-${mood}.svg`)).toString();
    webview.html = lintPanelHtml(
      {
        cspSource: webview.cspSource,
        images: { clean: image("clean"), thinking: image("thinking"), problem: image("problem") },
      },
      this.currentView(),
    );
  }

  private currentView(): PanelView {
    const document = vscode.window.activeTextEditor?.document;
    if (document?.languageId !== "python" || document.uri.scheme !== "file") {
      return { kind: "idle" };
    }
    return {
      kind: "file",
      name: vscode.workspace.asRelativePath(document.uri),
      uri: document.uri.toString(),
      state: this.checker.stateOf(document.uri),
    };
  }

  private media(): vscode.Uri {
    return vscode.Uri.joinPath(this.extensionUri, "media");
  }
}

/**
 * Open a checked file at a problem's line. The arguments come from a link
 * in the panel, so they are checked: only a file Lint has checked is opened.
 */
async function revealProblem(checker: Checker, uriText: unknown, line: unknown): Promise<void> {
  if (typeof uriText !== "string" || !Number.isSafeInteger(line) || (line as number) < 1) {
    return;
  }
  const uri = vscode.Uri.parse(uriText, true);
  if (uri.scheme !== "file" || checker.stateOf(uri) === undefined) {
    return;
  }
  const document = await vscode.workspace.openTextDocument(uri);
  const range = lineRange(document, line as number);
  await vscode.window.showTextDocument(document, { selection: range });
}
