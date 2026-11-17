/**
 * Tests that run inside a real VS Code, with the real SecureLint.
 *
 * They need `securelint` (1.1.0 or newer) on the PATH, and no AI set up:
 * Ask Lint is checked to fail cleanly, so nothing is ever sent to an AI.
 * The Python files are written to a new temporary folder for each run, so
 * the repository holds no risky code.
 */

import * as assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import * as vscode from "vscode";

import type { SecureLintApi } from "../../src/extension";
import { ASK_COMMAND, REVEAL_COMMAND, SILENCE_COMMAND } from "../../src/panel";
import type { FileState } from "../../src/scan";

const RISKY = `"""Synthetic code for the extension's tests."""
import os
import pickle

user_text = input("Type something: ")
eval(user_text)
os.system("echo " + user_text)
data = pickle.loads(bytes.fromhex(user_text))
`;
const SAFE = 'print("all good")\n';

let folder = "";
let api: SecureLintApi;

/** Wait until `check` returns a value, or fail after `seconds`. */
async function waitFor<T>(what: string, check: () => T | undefined, seconds = 30): Promise<T> {
  const end = Date.now() + seconds * 1000;
  for (;;) {
    const value = check();
    if (value !== undefined) {
      return value;
    }
    if (Date.now() > end) {
      assert.fail(`timed out waiting for ${what}`);
    }
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
}

/** Wait for the file's check to end, and return how it ended. */
function checked(uri: vscode.Uri): Promise<FileState> {
  return waitFor(`the check of ${uri.fsPath}`, () => {
    const state = api.stateOf(uri);
    return state === undefined || state.kind === "checking" ? undefined : state;
  });
}

function rules(state: FileState): string[] {
  return state.kind === "done" ? state.problems.map((problem) => problem.code) : [];
}

async function open(name: string, text: string): Promise<vscode.TextDocument> {
  const path = join(folder, name);
  writeFileSync(path, text);
  const document = await vscode.workspace.openTextDocument(path);
  await vscode.window.showTextDocument(document);
  return document;
}

describe("SecureLint in VS Code", function () {
  this.timeout(90_000);

  before(async () => {
    folder = mkdtempSync(join(tmpdir(), "securelint-vscode-"));
    // Opening a Python file starts the extension.
    await open("start.py", SAFE);
    const extension = vscode.extensions.getExtension<SecureLintApi>("fatennhrb.securelint");
    assert.ok(extension, "the extension is not installed");
    api = await extension.activate();
  });

  after(async () => {
    await vscode.commands.executeCommand("workbench.action.closeAllEditors");
    rmSync(folder, { recursive: true, force: true });
  });

  it("underlines each problem in a risky file", async () => {
    const document = await open("risky.py", RISKY);
    const state = await checked(document.uri);
    assert.deepEqual(rules(state), ["SL101", "SL102", "SL103"]);

    const diagnostics = vscode.languages.getDiagnostics(document.uri);
    assert.deepEqual(
      diagnostics.map((item) => [item.source, item.code, item.range.start.line, item.severity]),
      [
        ["SecureLint", "SL101", 5, vscode.DiagnosticSeverity.Error],
        ["SecureLint", "SL102", 6, vscode.DiagnosticSeverity.Error],
        ["SecureLint", "SL103", 7, vscode.DiagnosticSeverity.Error],
      ],
    );
  });

  it("finds nothing in a safe file", async () => {
    const document = await open("safe.py", SAFE);
    assert.deepEqual(await checked(document.uri), { kind: "done", problems: [] });
    assert.deepEqual(vscode.languages.getDiagnostics(document.uri), []);
  });

  it("offers Ask Lint and Silence in the lightbulb menu", async () => {
    const document = await open("menu.py", RISKY);
    await checked(document.uri);
    const actions = await vscode.commands.executeCommand<vscode.CodeAction[]>(
      "vscode.executeCodeActionProvider",
      document.uri,
      new vscode.Range(5, 0, 5, 1),
    );
    const titles = actions.map((action) => action.title);
    assert.ok(titles.includes("Ask Lint about SL101"), titles.join(", "));
    assert.ok(titles.includes("Silence SL101 on this line"), titles.join(", "));
  });

  it("silences a problem with a comment, then stops reporting it", async () => {
    const document = await open("silence.py", RISKY);
    await checked(document.uri);

    await vscode.commands.executeCommand(SILENCE_COMMAND, document.uri.toString(), 6, "SL101");
    assert.equal(
      document.lineAt(5).text,
      "eval(user_text)  # securelint: ignore[SL101] why this is safe",
    );

    await document.save();
    const state = await waitFor("the check after the save", () => {
      const now = api.stateOf(document.uri);
      return now?.kind === "done" && !rules(now).includes("SL101") ? now : undefined;
    });
    assert.deepEqual(rules(state), ["SL102", "SL103"]);
  });

  it("says why Lint cannot answer when no AI is set up", async () => {
    const document = await open("ask.py", RISKY);
    await checked(document.uri);

    await vscode.commands.executeCommand(ASK_COMMAND, document.uri.toString(), 7);
    const answer = await waitFor("Lint's answer", () => {
      const now = api.answersFor(document.uri).get("7:SL102");
      return now === undefined || now.kind === "asking" ? undefined : now;
    });
    if (answer.kind !== "failed") assert.fail(`Lint answered: ${JSON.stringify(answer)}`);
    assert.match(answer.message, /no AI provider is set up/);
  });

  it("refuses a link to a file Lint has not checked", async () => {
    const other = vscode.Uri.file(join(folder, "never-opened.py"));
    writeFileSync(other.fsPath, SAFE);
    await vscode.commands.executeCommand(REVEAL_COMMAND, other.toString(), 1);
    assert.notEqual(vscode.window.activeTextEditor?.document.uri.fsPath, other.fsPath);
  });

  it("shows Lint's panel", async () => {
    await vscode.commands.executeCommand("securelint.lint.focus");
  });
});
