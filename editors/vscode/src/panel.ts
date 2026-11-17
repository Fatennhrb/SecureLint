/**
 * The page shown in Lint's panel. Kept apart from the VS Code API so it
 * can be tested on its own.
 *
 * The page runs no script, and its Content Security Policy only lets it
 * load images from the extension itself: nothing from the network, and no
 * code. A problem in the list is a link to one command of ours, the only
 * one the panel may run, which jumps to the problem's line.
 */

import type { Explanation, Problem, ProblemLevel } from "./report";
import type { FileState } from "./scan";

/** Jump to a problem, with [file address, line]. */
export const REVEAL_COMMAND = "securelint.revealProblem";
/** Ask the AI about a line, with [file address, line]. */
export const ASK_COMMAND = "securelint.askLint";
/** Copy the AI's fix, with [file address, line, rule]. */
export const COPY_FIX_COMMAND = "securelint.copyFix";
/** Add a silencing comment, with [file address, line, rule]. */
export const SILENCE_COMMAND = "securelint.silence";

/** The only commands the panel's links may run. */
export const PANEL_COMMANDS = [REVEAL_COMMAND, ASK_COMMAND, COPY_FIX_COMMAND, SILENCE_COMMAND];

/** What Lint knows about one problem after it was asked about it. */
export type Answer =
  | { readonly kind: "asking" }
  | { readonly kind: "answered"; readonly explanation: Explanation }
  | { readonly kind: "failed"; readonly message: string };

/** The key of a problem's answer: one per rule on a line. */
export function answerKey(line: number, rule: string): string {
  return `${String(line)}:${rule}`;
}

export interface PanelResources {
  /** The source VS Code gives the webview for the extension's files. */
  readonly cspSource: string;
  /** Where the webview can load each of Lint's drawings from. */
  readonly images: { readonly clean: string; readonly thinking: string; readonly problem: string };
}

/** What the panel shows: nothing to check, or the file being edited. */
export type PanelView =
  | { readonly kind: "idle" }
  | {
      readonly kind: "file";
      /** The file's name, as shown to the user. */
      readonly name: string;
      /** The file's address, given back to the reveal command. */
      readonly uri: string;
      /** Undefined while the file has not been checked yet. */
      readonly state: FileState | undefined;
      /** What Lint was asked about, by `answerKey(line, rule)`. */
      readonly answers?: ReadonlyMap<string, Answer>;
    };

type Mood = "clean" | "thinking" | "problem";

const ALT: Readonly<Record<Mood, string>> = {
  clean: "Lint, all clean",
  thinking: "Lint, thinking",
  problem: "Lint, found a problem",
};

const LEVEL_NAME: Readonly<Record<ProblemLevel, string>> = {
  error: "Error",
  warning: "Warning",
  information: "Note",
};

/** Return the HTML of Lint's panel for what is happening now. */
export function lintPanelHtml(resources: PanelResources, view: PanelView): string {
  const { mood, title, hint, list } = content(view);
  const policy = [
    "default-src 'none'",
    `img-src ${escapeHtml(resources.cspSource)}`,
    "style-src 'unsafe-inline'",
  ].join("; ");
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="${policy}">
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
body { font-family: var(--vscode-font-family); font-size: var(--vscode-font-size);
  color: var(--vscode-foreground); padding: 12px 8px; }
header { display: flex; flex-direction: column; align-items: center; gap: 6px;
  text-align: center; margin-bottom: 12px; }
img { width: 96px; height: 96px; }
h1 { font-size: 1.1em; margin: 0; font-weight: 600; }
p { margin: 0; }
.hint { color: var(--vscode-descriptionForeground); }
ul { list-style: none; margin: 0; padding: 0; }
li { padding: 6px 8px; border-radius: 4px; }
li + li { border-top: 1px solid var(--vscode-widget-border, transparent); }
a { color: var(--vscode-textLink-foreground); text-decoration: none; }
a:hover, a:focus { text-decoration: underline; outline: none; }
a.where { display: block; color: inherit; font-weight: 600; }
.actions { margin-top: 4px; }
.busy { color: var(--vscode-descriptionForeground); font-style: italic; }
.failed { margin-top: 4px; color: var(--vscode-errorForeground); }
.answer { margin-top: 6px; padding: 6px 8px; border-left: 2px solid var(--vscode-textLink-foreground);
  background: var(--vscode-textBlockQuote-background); }
.answer p + p { margin-top: 4px; }
.label { font-weight: 600; color: var(--vscode-descriptionForeground); }
.level { display: inline-block; width: 8px; height: 8px; border-radius: 50%;
  margin-right: 6px; }
.error { background: var(--vscode-editorError-foreground); }
.warning { background: var(--vscode-editorWarning-foreground); }
.information { background: var(--vscode-editorInfo-foreground); }
.message { margin-top: 2px; color: var(--vscode-descriptionForeground); }
code { font-family: var(--vscode-editor-font-family); }
</style>
</head>
<body>
<header>
<img src="${escapeHtml(resources.images[mood])}" alt="${ALT[mood]}">
<h1 role="status">${title}</h1>
${hint === "" ? "" : `<p class="hint">${hint}</p>`}
</header>
${list}
</body>
</html>`;
}

interface Content {
  mood: Mood;
  /** HTML, already escaped. */
  title: string;
  hint: string;
  list: string;
}

function content(view: PanelView): Content {
  if (view.kind === "idle") {
    return {
      mood: "clean",
      title: "Lint is ready.",
      hint: "Open a Python file to have it checked.",
      list: "",
    };
  }
  const name = `<code>${escapeHtml(view.name)}</code>`;
  const state = view.state ?? { kind: "checking" };
  switch (state.kind) {
    case "checking":
      return { mood: "thinking", title: `Lint is checking ${name}…`, hint: "", list: "" };
    case "not-found":
      return {
        mood: "problem",
        title: "Lint cannot find SecureLint.",
        hint:
          "Install it with <code>pip install securelint</code>, or set " +
          "<code>securelint.executable</code> to its full path.",
        list: "",
      };
    case "failed":
      return {
        mood: "problem",
        title: `Lint could not check ${name}.`,
        hint: escapeHtml(state.message),
        list: "",
      };
    case "done":
      if (state.problems.length === 0) {
        return {
          mood: "clean",
          title: `No problems in ${name}.`,
          hint: "Lint checks it again each time you save.",
          list: "",
        };
      }
    {
      const answers = view.answers ?? new Map<string, Answer>();
      const thinking = [...answers.values()].some((answer) => answer.kind === "asking");
      return {
        mood: thinking ? "thinking" : "problem",
        title: `${countProblems(state.problems.length)} in ${name}`,
        hint: thinking
          ? "Lint is asking the AI…"
          : "Click a line to go to it, or ask Lint to explain a problem.",
        list: problemList(view.uri, state.problems, answers),
      };
    }
  }
}

function problemList(
  uri: string,
  problems: readonly Problem[],
  answers: ReadonlyMap<string, Answer>,
): string {
  const items = problems.map((problem) => {
    const rule = problem.code === "" ? "" : ` · ${escapeHtml(problem.code)}`;
    const answer = problem.code === "" ? undefined : answers.get(answerKey(problem.line, problem.code));
    return `<li>
<a class="where" href="${commandLink(REVEAL_COMMAND, [uri, problem.line])}"><span class="level ${problem.level}" title="${LEVEL_NAME[problem.level]}"></span>Line ${String(problem.line)}${rule}</a>
<p class="message">${escapeHtml(problem.message)}</p>
${problem.code === "" ? "" : actions(uri, problem, answer)}
</li>`;
  });
  return `<ul>\n${items.join("\n")}\n</ul>`;
}

function actions(uri: string, problem: Problem, answer: Answer | undefined): string {
  const links: string[] = [];
  let below = "";
  switch (answer?.kind) {
    case undefined:
      links.push(link(ASK_COMMAND, [uri, problem.line], "Ask Lint"));
      break;
    case "asking":
      links.push(`<span class="busy">Lint is thinking…</span>`);
      break;
    case "failed":
      links.push(link(ASK_COMMAND, [uri, problem.line], "Ask again"));
      below = `<p class="failed">${escapeHtml(answer.message)}</p>`;
      break;
    case "answered": {
      const { text, fix } = answer.explanation;
      if (fix !== "") {
        links.push(link(COPY_FIX_COMMAND, [uri, problem.line, problem.code], "Copy fix"));
      }
      below =
        `<div class="answer"><p class="label">AI explanation (may be wrong)</p>` +
        `<p>${escapeHtml(text)}</p>` +
        (fix === "" ? "" : `<p><span class="label">Fix:</span> ${escapeHtml(fix)}</p>`) +
        `</div>`;
      break;
    }
  }
  if (problem.code !== "SL001") {
    links.push(link(SILENCE_COMMAND, [uri, problem.line, problem.code], "Silence this"));
  }
  return `${below}\n<p class="actions">${links.join(" · ")}</p>`;
}

function link(command: string, args: readonly unknown[], label: string): string {
  return `<a href="${commandLink(command, args)}">${label}</a>`;
}

/** A link that runs one of the panel's commands with these arguments. */
function commandLink(command: string, args: readonly unknown[]): string {
  return escapeHtml(`command:${command}?${encodeURIComponent(JSON.stringify(args))}`);
}

function countProblems(count: number): string {
  return count === 1 ? "1 problem" : `${String(count)} problems`;
}

/** Escape text for HTML, both between tags and in attributes. */
export function escapeHtml(value: string): string {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;");
}
