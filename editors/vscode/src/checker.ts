/**
 * Checks Python files with SecureLint when they are opened or saved, and
 * shows what it finds as squiggles and in the Problems panel.
 *
 * The file on disk is scanned, so the squiggles match the saved text.
 */

import * as vscode from "vscode";

import type { Problem, ProblemLevel } from "./report";
import { scanFile } from "./scan";

const LEVELS: Readonly<Record<ProblemLevel, vscode.DiagnosticSeverity>> = {
  error: vscode.DiagnosticSeverity.Error,
  warning: vscode.DiagnosticSeverity.Warning,
  information: vscode.DiagnosticSeverity.Information,
};

export class Checker implements vscode.Disposable {
  private readonly diagnostics = vscode.languages.createDiagnosticCollection("securelint");
  /** The scan running for each file, so a newer save can stop it. */
  private readonly running = new Map<string, AbortController>();
  private warnedNotFound = false;

  constructor(private readonly log: vscode.LogOutputChannel) {}

  /** Start following open and saved Python files. */
  start(): vscode.Disposable[] {
    for (const document of vscode.workspace.textDocuments) {
      void this.check(document);
    }
    return [
      vscode.workspace.onDidOpenTextDocument((document) => this.check(document)),
      vscode.workspace.onDidSaveTextDocument((document) => this.check(document)),
      vscode.workspace.onDidCloseTextDocument((document) => {
        this.stop(document.uri);
        this.diagnostics.delete(document.uri);
      }),
    ];
  }

  async check(document: vscode.TextDocument): Promise<void> {
    if (document.languageId !== "python" || document.uri.scheme !== "file") {
      return;
    }
    const key = document.uri.toString();
    this.stop(document.uri);
    const controller = new AbortController();
    this.running.set(key, controller);

    const command = vscode.workspace
      .getConfiguration("securelint")
      .get<string>("executable", "securelint");
    const outcome = await scanFile({
      command,
      file: document.uri.fsPath,
      signal: controller.signal,
    });
    if (this.running.get(key) === controller) {
      this.running.delete(key);
    }

    switch (outcome.kind) {
      case "done":
        this.diagnostics.set(
          document.uri,
          outcome.problems.map((problem) => toDiagnostic(document, problem)),
        );
        this.log.info(
          `${vscode.workspace.asRelativePath(document.uri)}: ${String(outcome.problems.length)} problem(s)`,
        );
        break;
      case "cancelled":
        break;
      case "not-found":
        this.log.warn(`Could not start "${outcome.command}".`);
        this.warnNotFound(outcome.command);
        break;
      case "failed":
        // Old squiggles may point at lines that have moved since.
        this.diagnostics.delete(document.uri);
        this.log.error(`${vscode.workspace.asRelativePath(document.uri)}: ${outcome.message}`);
        break;
    }
  }

  dispose(): void {
    for (const controller of this.running.values()) {
      controller.abort();
    }
    this.running.clear();
    this.diagnostics.dispose();
  }

  private stop(uri: vscode.Uri): void {
    const key = uri.toString();
    this.running.get(key)?.abort();
    this.running.delete(key);
  }

  /** Say once per session that SecureLint is missing, and how to get it. */
  private warnNotFound(command: string): void {
    if (this.warnedNotFound) {
      return;
    }
    this.warnedNotFound = true;
    void vscode.window.showWarningMessage(
      `SecureLint could not start "${command}". Install it with ` +
        "`pip install securelint`, or set securelint.executable to its full path.",
    );
  }
}

function toDiagnostic(document: vscode.TextDocument, problem: Problem): vscode.Diagnostic {
  // SecureLint counts lines and columns from 1, VS Code from 0.
  const lineIndex = Math.min(problem.line, document.lineCount) - 1;
  const line = document.lineAt(lineIndex);
  const start =
    problem.column > 0
      ? Math.min(problem.column - 1, line.text.length)
      : line.firstNonWhitespaceCharacterIndex;
  const end = line.text.length > start ? line.text.length : start + 1;
  const diagnostic = new vscode.Diagnostic(
    new vscode.Range(lineIndex, start, lineIndex, end),
    problem.message,
    LEVELS[problem.level],
  );
  diagnostic.source = "SecureLint";
  if (problem.code !== "") {
    diagnostic.code = problem.code;
  }
  return diagnostic;
}
