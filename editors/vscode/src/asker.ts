/**
 * Asks SecureLint, and through it the project's AI provider, to explain the
 * findings on one line, and keeps the answers for Lint's panel.
 *
 * Answers belong to the text that was explained: when the file is checked
 * again (after a save), its answers are dropped, since lines may have moved.
 */

import * as vscode from "vscode";

import type { Checker } from "./checker";
import { type Answer, answerKey } from "./panel";
import { splitExplanation } from "./report";
import { explainLine } from "./scan";

export class Asker implements vscode.Disposable {
  private readonly answers = new Map<string, Map<string, Answer>>();
  /** Goes up each time a file's answers are dropped, to ignore late ones. */
  private readonly generations = new Map<string, number>();
  private readonly running = new Set<AbortController>();
  private readonly changed = new vscode.EventEmitter<vscode.Uri>();
  private readonly listener: vscode.Disposable;

  /** Fires with a file's address when one of its answers changes. */
  readonly onDidChangeAnswers = this.changed.event;

  constructor(
    private readonly checker: Checker,
    private readonly log: vscode.LogOutputChannel,
  ) {
    this.listener = checker.onDidChangeState((uri) => {
      const state = checker.stateOf(uri);
      if (state === undefined || state.kind === "checking") {
        this.drop(uri);
      }
    });
  }

  /** The answers for a file, by `answerKey(line, rule)`. */
  answersFor(uri: vscode.Uri): ReadonlyMap<string, Answer> {
    return this.answers.get(uri.toString()) ?? new Map<string, Answer>();
  }

  /** Ask about every finding on one line of a checked file. */
  async ask(uri: vscode.Uri, line: number): Promise<void> {
    const state = this.checker.stateOf(uri);
    if (state?.kind !== "done") {
      return;
    }
    const codes = state.problems
      .filter((problem) => problem.line === line && problem.code !== "")
      .map((problem) => problem.code);
    const answers = this.answersOf(uri);
    if (codes.length === 0 || codes.some((code) => answers.get(answerKey(line, code))?.kind === "asking")) {
      return;
    }
    for (const code of codes) {
      answers.set(answerKey(line, code), { kind: "asking" });
    }
    this.changed.fire(uri);

    const key = uri.toString();
    const generation = this.generations.get(key) ?? 0;
    const controller = new AbortController();
    this.running.add(controller);
    const outcome = await explainLine(
      {
        command: vscode.workspace.getConfiguration("securelint").get<string>("executable", "securelint"),
        file: uri.fsPath,
        signal: controller.signal,
      },
      line,
    );
    this.running.delete(controller);
    if (outcome.kind === "cancelled" || (this.generations.get(key) ?? 0) !== generation) {
      // The file changed while the AI was answering: this answer is stale.
      return;
    }

    const name = vscode.workspace.asRelativePath(uri);
    for (const code of codes) {
      answers.set(answerKey(line, code), this.toAnswer(outcome, line, code));
    }
    if (outcome.kind === "done") {
      this.log.info(`${name}:${String(line)}: explained ${codes.join(", ")}`);
    } else {
      this.log.warn(`${name}:${String(line)}: could not explain`);
    }
    this.changed.fire(uri);
  }

  dispose(): void {
    for (const controller of this.running) {
      controller.abort();
    }
    this.running.clear();
    this.listener.dispose();
    this.changed.dispose();
  }

  private toAnswer(
    outcome: Awaited<ReturnType<typeof explainLine>>,
    line: number,
    code: string,
  ): Answer {
    switch (outcome.kind) {
      case "done": {
        const found = outcome.problems.find((problem) => problem.line === line && problem.code === code);
        if (found?.explanation === undefined) {
          return { kind: "failed", message: "SecureLint gave no explanation for this problem." };
        }
        return { kind: "answered", explanation: splitExplanation(found.explanation) };
      }
      case "not-found":
        return { kind: "failed", message: `Lint cannot find SecureLint ("${outcome.command}").` };
      case "failed":
        return { kind: "failed", message: outcome.message };
      case "cancelled":
        return { kind: "failed", message: "The question was cancelled." };
    }
  }

  private answersOf(uri: vscode.Uri): Map<string, Answer> {
    const key = uri.toString();
    let answers = this.answers.get(key);
    if (answers === undefined) {
      answers = new Map<string, Answer>();
      this.answers.set(key, answers);
    }
    return answers;
  }

  private drop(uri: vscode.Uri): void {
    const key = uri.toString();
    this.generations.set(key, (this.generations.get(key) ?? 0) + 1);
    if (this.answers.delete(key)) {
      this.changed.fire(uri);
    }
  }
}
