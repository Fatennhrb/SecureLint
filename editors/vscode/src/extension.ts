/**
 * SecureLint for VS Code.
 *
 * Checks Python files when they are opened or saved, shows what SecureLint
 * finds as squiggles, and shows Lint, the mascot, in its own panel with
 * the problems of the file being edited. Lint can be asked to explain a
 * problem, and a problem can be silenced with a comment.
 */

import * as vscode from "vscode";

import { Asker } from "./asker";
import { Checker, lineRange } from "./checker";
import {
  type Answer,
  answerKey,
  ASK_COMMAND,
  COPY_FIX_COMMAND,
  lintPanelHtml,
  PANEL_COMMANDS,
  type Mood,
  MOODS,
  type PanelView,
  REVEAL_COMMAND,
  SILENCE_COMMAND,
} from "./panel";
import type { FileState } from "./scan";
import { REASON_PLACEHOLDER, RULE_ID, silenceEdit } from "./silence";

/**
 * What the extension tells other code, read-only: used by the tests that
 * run inside VS Code to wait for a check or an answer.
 */
export interface SecureLintApi {
  stateOf(uri: vscode.Uri): FileState | undefined;
  answersFor(uri: vscode.Uri): ReadonlyMap<string, Answer>;
}

export function activate(context: vscode.ExtensionContext): SecureLintApi {
  const log = vscode.window.createOutputChannel("SecureLint", { log: true });
  const checker = new Checker(log);
  const asker = new Asker(checker, log);
  const panel = new LintViewProvider(context.extensionUri, checker, asker);
  const refreshIfActive = (uri: vscode.Uri): void => {
    if (uri.toString() === vscode.window.activeTextEditor?.document.uri.toString()) {
      panel.refresh();
    }
  };
  context.subscriptions.push(
    log,
    checker,
    asker,
    ...checker.start(),
    vscode.window.registerWebviewViewProvider("securelint.lint", panel),
    vscode.window.onDidChangeActiveTextEditor(() => {
      panel.refresh();
    }),
    vscode.workspace.onDidChangeConfiguration((change) => {
      if (change.affectsConfiguration(REDUCE_MOTION)) {
        panel.refresh();
      }
    }),
    checker.onDidChangeState(refreshIfActive),
    asker.onDidChangeAnswers(refreshIfActive),
    vscode.commands.registerCommand(REVEAL_COMMAND, (uri: unknown, line: unknown) =>
      revealProblem(checker, uri, line),
    ),
    vscode.commands.registerCommand(ASK_COMMAND, (uri: unknown, line: unknown) =>
      askLint(checker, asker, uri, line),
    ),
    vscode.commands.registerCommand(COPY_FIX_COMMAND, (uri: unknown, line: unknown, rule: unknown) =>
      copyFix(checker, asker, uri, line, rule),
    ),
    vscode.commands.registerCommand(SILENCE_COMMAND, (uri: unknown, line: unknown, rule: unknown) =>
      silence(checker, uri, line, rule),
    ),
    vscode.languages.registerCodeActionsProvider({ language: "python", scheme: "file" }, new LintActions(), {
      providedCodeActionKinds: [vscode.CodeActionKind.QuickFix],
    }),
  );
  return {
    stateOf: (uri) => checker.stateOf(uri),
    answersFor: (uri) => asker.answersFor(uri),
  };
}

export function deactivate(): void {
  // Nothing to clean up: VS Code disposes of what was registered.
}

/** VS Code's setting for less motion: "on", "off", or "auto" (the system's). */
const REDUCE_MOTION = "workbench.reduceMotion";

class LintViewProvider implements vscode.WebviewViewProvider {
  private view: vscode.WebviewView | undefined;
  /** Lint's drawings, read once from the media folder. */
  private drawings: Record<Mood, string> = { clean: "", thinking: "", problem: "" };

  constructor(
    private readonly extensionUri: vscode.Uri,
    private readonly checker: Checker,
    private readonly asker: Asker,
  ) {
    void this.readDrawings();
  }

  resolveWebviewView(view: vscode.WebviewView): void {
    this.view = view;
    view.webview.options = {
      // The page runs no script and loads no file (Lint is drawn in the
      // page), and its links may only run the panel's own commands.
      enableScripts: false,
      enableCommandUris: PANEL_COMMANDS,
      localResourceRoots: [],
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
    // "auto" is left to the drawings themselves, which stay still when the
    // system asks for less motion.
    const still = vscode.workspace.getConfiguration().get<string>(REDUCE_MOTION) === "on";
    this.view.webview.html = lintPanelHtml({ drawings: this.drawings, still }, this.currentView());
  }

  private async readDrawings(): Promise<void> {
    const media = vscode.Uri.joinPath(this.extensionUri, "media");
    const decoder = new TextDecoder();
    for (const mood of MOODS) {
      const bytes = await vscode.workspace.fs.readFile(vscode.Uri.joinPath(media, `lint-${mood}.svg`));
      this.drawings = { ...this.drawings, [mood]: decoder.decode(bytes) };
    }
    this.refresh();
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
      answers: this.asker.answersFor(document.uri),
    };
  }

  private media(): vscode.Uri {
    return vscode.Uri.joinPath(this.extensionUri, "media");
  }
}

/** The 💡 actions on a SecureLint squiggle: ask Lint, or silence it. */
class LintActions implements vscode.CodeActionProvider {
  provideCodeActions(
    document: vscode.TextDocument,
    _range: vscode.Range,
    context: vscode.CodeActionContext,
  ): vscode.CodeAction[] {
    const actions: vscode.CodeAction[] = [];
    for (const diagnostic of context.diagnostics) {
      const rule = typeof diagnostic.code === "string" ? diagnostic.code : "";
      if (diagnostic.source !== "SecureLint" || !RULE_ID.test(rule)) {
        continue;
      }
      const args = [document.uri.toString(), diagnostic.range.start.line + 1];
      const ask = new vscode.CodeAction(`Ask Lint about ${rule}`, vscode.CodeActionKind.QuickFix);
      ask.command = { title: ask.title, command: ASK_COMMAND, arguments: args };
      ask.diagnostics = [diagnostic];
      actions.push(ask);
      if (rule !== "SL001") {
        const quiet = new vscode.CodeAction(`Silence ${rule} on this line`, vscode.CodeActionKind.QuickFix);
        quiet.command = { title: quiet.title, command: SILENCE_COMMAND, arguments: [...args, rule] };
        quiet.diagnostics = [diagnostic];
        actions.push(quiet);
      }
    }
    return actions;
  }
}

/**
 * Check the arguments a command got. They can come from a link in the
 * panel, so only a file Lint has checked, a line number and a rule id are
 * accepted.
 */
function checkedTarget(
  checker: Checker,
  uriText: unknown,
  line: unknown,
): { uri: vscode.Uri; line: number } | undefined {
  if (typeof uriText !== "string" || !Number.isSafeInteger(line) || (line as number) < 1) {
    return undefined;
  }
  const uri = vscode.Uri.parse(uriText, true);
  if (uri.scheme !== "file" || checker.stateOf(uri) === undefined) {
    return undefined;
  }
  return { uri, line: line as number };
}

function checkedRule(rule: unknown): string | undefined {
  return typeof rule === "string" && RULE_ID.test(rule) ? rule : undefined;
}

async function revealProblem(checker: Checker, uriText: unknown, line: unknown): Promise<void> {
  const target = checkedTarget(checker, uriText, line);
  if (target === undefined) {
    return;
  }
  const document = await vscode.workspace.openTextDocument(target.uri);
  await vscode.window.showTextDocument(document, { selection: lineRange(document, target.line) });
}

async function askLint(checker: Checker, asker: Asker, uriText: unknown, line: unknown): Promise<void> {
  const target = checkedTarget(checker, uriText, line);
  if (target === undefined) {
    return;
  }
  // Show Lint's panel, where the answer appears.
  await vscode.commands.executeCommand("securelint.lint.focus");
  await asker.ask(target.uri, target.line);
}

async function copyFix(
  checker: Checker,
  asker: Asker,
  uriText: unknown,
  line: unknown,
  rule: unknown,
): Promise<void> {
  const target = checkedTarget(checker, uriText, line);
  const code = checkedRule(rule);
  if (target === undefined || code === undefined) {
    return;
  }
  // The fix is taken from Lint's own answers, never from the link.
  const answer = asker.answersFor(target.uri).get(answerKey(target.line, code));
  if (answer?.kind !== "answered" || answer.explanation.fix === "") {
    return;
  }
  await vscode.env.clipboard.writeText(answer.explanation.fix);
  vscode.window.setStatusBarMessage("$(check) Lint's fix copied. Check it before you use it.", 4000);
}

async function silence(checker: Checker, uriText: unknown, line: unknown, rule: unknown): Promise<void> {
  const target = checkedTarget(checker, uriText, line);
  const code = checkedRule(rule);
  if (target === undefined || code === undefined) {
    return;
  }
  const document = await vscode.workspace.openTextDocument(target.uri);
  if (target.line > document.lineCount) {
    return;
  }
  const text = document.lineAt(target.line - 1).text;
  const edit = silenceEdit(text, code);
  if (edit.kind === "refuse") {
    void vscode.window.showInformationMessage(edit.reason);
    return;
  }
  const editor = await vscode.window.showTextDocument(document);
  const position = new vscode.Position(target.line - 1, edit.column);
  if (edit.kind === "insert") {
    await editor.edit((builder) => {
      builder.insert(position, edit.text);
    });
    return;
  }
  // The reason is selected, so typing replaces it.
  const snippet = new vscode.SnippetString(edit.text.replaceAll("$", "\\$"));
  snippet.appendPlaceholder(REASON_PLACEHOLDER);
  await editor.insertSnippet(snippet, position);
}
