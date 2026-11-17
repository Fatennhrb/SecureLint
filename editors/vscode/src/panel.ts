/**
 * The page shown in Lint's panel. Kept apart from the VS Code API so it
 * can be tested on its own.
 *
 * The page runs no script, and its Content Security Policy only lets it
 * load images from the extension itself: nothing from the network, and no
 * code. A problem in the list is a link to one command of ours, the only
 * one the panel may run, which jumps to the problem's line.
 */

import type { Problem, ProblemLevel } from "./report";
import type { FileState } from "./scan";

/** The command the panel's links run, with [file address, line]. */
export const REVEAL_COMMAND = "securelint.revealProblem";

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
li a { display: block; padding: 6px 8px; border-radius: 4px; color: inherit;
  text-decoration: none; }
li a:hover, li a:focus { background: var(--vscode-list-hoverBackground);
  outline: 1px solid var(--vscode-focusBorder); }
.where { font-weight: 600; }
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
      return {
        mood: "problem",
        title: `${countProblems(state.problems.length)} in ${name}`,
        hint: "Click one to go to its line.",
        list: problemList(view.uri, state.problems),
      };
  }
}

function problemList(uri: string, problems: readonly Problem[]): string {
  const items = problems.map((problem) => {
    const link = `command:${REVEAL_COMMAND}?${encodeURIComponent(JSON.stringify([uri, problem.line]))}`;
    const rule = problem.code === "" ? "" : ` · ${escapeHtml(problem.code)}`;
    return `<li><a href="${escapeHtml(link)}">
<span class="where"><span class="level ${problem.level}" title="${LEVEL_NAME[problem.level]}"></span>Line ${String(problem.line)}${rule}</span>
<p class="message">${escapeHtml(problem.message)}</p>
</a></li>`;
  });
  return `<ul>\n${items.join("\n")}\n</ul>`;
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
