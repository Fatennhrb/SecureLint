/**
 * Checks Python files with SecureLint when they are opened or saved, and
 * shows what it finds as squiggles and in the Problems panel. It also
 * keeps each file's state, so Lint's panel can show it.
 *
 * The file on disk is scanned, so the squiggles match the saved text.
 */

import * as vscode from "vscode";

import type { Problem, ProblemLevel } from "./report";
import { type FileState, scanFile } from "./scan";

const LEVELS: Readonly<Record<ProblemLevel, vscode.DiagnosticSeverity>> = {
  error: vscode.DiagnosticSeverity.Error,
  warning: vscode.DiagnosticSeverity.Warning,
  information: vscode.DiagnosticSeverity.Information,
};

export class Checker implements vscode.Disposable {
  private readonly diagnostics = vscode.languages.createDiagnosticCollection("securelint");
  /** The scan running for each file, so a newer save can stop it. */
  private readonly running = new Map<string, AbortController>();
  private readonly states = new Map<string, FileState>();
  private readonly changed = new vscode.EventEmitter<vscode.Uri>();
  private warnedNotFound = false;

  /** Fires with a file's address when its state changes. */
  readonly onDidChangeState = this.changed.event;

  constructor(private readonly log: vscode.LogOutputChannel) {}

  /** The state of a file, or undefined if it is not checked. */
  stateOf(uri: vscode.Uri): FileState | undefined {
    return this.states.get(uri.toString());
  }

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
        this.states.delete(document.uri.toString());
        this.changed.fire(document.uri);
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
    this.setState(document.uri, { kind: "checking" });

    const command = vscode.workspace
      .getConfiguration("securelint")
      .get<string>("executable", "securelint");
    const outcome = await scanFile({
      command,
      file: document.uri.fsPath,
      signal: controller.signal,
    });
    if (outcome.kind === "cancelled") {
      // A newer check of the same file has taken over.
      return;
    }
    this.running.delete(key);

    const name = vscode.workspace.asRelativePath(document.uri);
    switch (outcome.kind) {
      case "done":
        this.diagnostics.set(
          document.uri,
          outcome.problems.map((problem) => toDiagnostic(document, problem)),
        );
        this.log.info(`${name}: ${String(outcome.problems.length)} problem(s)`);
        break;
      case "not-found":
        this.diagnostics.delete(document.uri);
        this.log.warn(`Could not start "${outcome.command}".`);
        this.warnNotFound(outcome.command);
        break;
      case "failed":
        // Old squiggles may point at lines that have moved since.
        this.diagnostics.delete(document.uri);
        this.log.error(`${name}: ${outcome.message}`);
        break;
    }
    this.setState(document.uri, outcome);
  }

  dispose(): void {
    for (const controller of this.running.values()) {
      controller.abort();
    }
    this.running.clear();
    this.diagnostics.dispose();
    this.changed.dispose();
  }

  private setState(uri: vscode.Uri, state: FileState): void {
    this.states.set(uri.toString(), state);
    this.changed.fire(uri);
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

/** Turn a SecureLint line (from 1) into a range in the document. */
export function lineRange(document: vscode.TextDocument, lineNumber: number, column = 0): vscode.Range {
  // SecureLint counts lines and columns from 1, VS Code from 0.
  const lineIndex = Math.min(Math.max(lineNumber, 1), document.lineCount) - 1;
  const line = document.lineAt(lineIndex);
  const start =
    column > 0 ? Math.min(column - 1, line.text.length) : line.firstNonWhitespaceCharacterIndex;
  const end = line.text.length > start ? line.text.length : start + 1;
  return new vscode.Range(lineIndex, start, lineIndex, end);
}

function toDiagnostic(document: vscode.TextDocument, problem: Problem): vscode.Diagnostic {
  const diagnostic = new vscode.Diagnostic(
    lineRange(document, problem.line, problem.column),
    problem.message,
    LEVELS[problem.level],
  );
  diagnostic.source = "SecureLint";
  if (problem.code !== "") {
    diagnostic.code = problem.code;
  }
  return diagnostic;
}
