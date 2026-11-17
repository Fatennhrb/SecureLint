import * as assert from "node:assert/strict";

import { escapeHtml, lintPanelHtml, type PanelView, REVEAL_COMMAND } from "../src/panel";
import type { Problem } from "../src/report";
import type { FileState } from "../src/scan";

const SOURCE = "https://file+.vscode-resource.vscode-cdn.net";
const resources = {
  cspSource: SOURCE,
  images: {
    clean: `${SOURCE}/media/lint-clean.svg`,
    thinking: `${SOURCE}/media/lint-thinking.svg`,
    problem: `${SOURCE}/media/lint-problem.svg`,
  },
};
const URI = "file:///c%3A/demo/risky.py";

function fileView(state: FileState | undefined, name = "risky.py"): PanelView {
  return { kind: "file", name, uri: URI, state };
}

function problem(fields: Partial<Problem> = {}): Problem {
  return {
    line: 6,
    column: 1,
    level: "error",
    code: "SL102",
    message: "os.system() runs its command through the shell.",
    ...fields,
  };
}

function lintShown(html: string): string {
  const match = /<img src="[^"]*\/lint-(\w+)\.svg" alt="([^"]*)">/.exec(html);
  assert.ok(match, "the page does not show Lint");
  assert.equal(match[2], { clean: "Lint, all clean", thinking: "Lint, thinking", problem: "Lint, found a problem" }[match[1] ?? ""]);
  return match[1] ?? "";
}

function title(html: string): string {
  return /<h1 role="status">(.*)<\/h1>/.exec(html)?.[1] ?? "";
}

const VIEWS: [string, PanelView][] = [
  ["no Python file", { kind: "idle" }],
  ["a file not checked yet", fileView(undefined)],
  ["a file being checked", fileView({ kind: "checking" })],
  ["a clean file", fileView({ kind: "done", problems: [] })],
  ["a file with problems", fileView({ kind: "done", problems: [problem()] })],
  ["SecureLint missing", fileView({ kind: "not-found", command: "securelint" })],
  ["a failed check", fileView({ kind: "failed", message: "bad settings" })],
];

describe("Lint's panel", () => {
  it("is ready when no Python file is open", () => {
    const html = lintPanelHtml(resources, { kind: "idle" });
    assert.equal(lintShown(html), "clean");
    assert.equal(title(html), "Lint is ready.");
  });

  it("thinks while the file is checked", () => {
    for (const state of [undefined, { kind: "checking" } as const]) {
      const html = lintPanelHtml(resources, fileView(state));
      assert.equal(lintShown(html), "thinking");
      assert.equal(title(html), "Lint is checking <code>risky.py</code>…");
    }
  });

  it("is all clean when the file has no problems", () => {
    const html = lintPanelHtml(resources, fileView({ kind: "done", problems: [] }));
    assert.equal(lintShown(html), "clean");
    assert.equal(title(html), "No problems in <code>risky.py</code>.");
    assert.ok(!html.includes("<ul>"));
  });

  it("lists the problems it found", () => {
    const html = lintPanelHtml(
      resources,
      fileView({
        kind: "done",
        problems: [problem(), problem({ line: 7, code: "SL103", level: "warning" })],
      }),
    );
    assert.equal(lintShown(html), "problem");
    assert.equal(title(html), "2 problems in <code>risky.py</code>");
    assert.equal(html.match(/<li>/g)?.length, 2);
    assert.ok(html.includes("Line 6 · SL102"));
    assert.ok(html.includes('class="level warning"'));
    assert.ok(html.includes("os.system() runs its command through the shell."));
  });

  it("says 1 problem, not 1 problems", () => {
    const html = lintPanelHtml(resources, fileView({ kind: "done", problems: [problem()] }));
    assert.equal(title(html), "1 problem in <code>risky.py</code>");
  });

  it("links each problem to its line through the reveal command only", () => {
    const html = lintPanelHtml(resources, fileView({ kind: "done", problems: [problem()] }));
    const links = [...html.matchAll(/href="([^"]*)"/g)].map((match) => match[1] ?? "");
    assert.equal(links.length, 1);
    const [command, query] = (links[0] ?? "").split("?");
    assert.equal(command, `command:${REVEAL_COMMAND}`);
    assert.deepEqual(JSON.parse(decodeURIComponent(query ?? "")), [URI, 6]);
  });

  it("explains how to install SecureLint when it is missing", () => {
    const html = lintPanelHtml(resources, fileView({ kind: "not-found", command: "securelint" }));
    assert.equal(lintShown(html), "problem");
    assert.ok(html.includes("<code>pip install securelint</code>"));
  });

  it("shows why a check failed", () => {
    const html = lintPanelHtml(resources, fileView({ kind: "failed", message: "bad settings" }));
    assert.equal(lintShown(html), "problem");
    assert.equal(title(html), "Lint could not check <code>risky.py</code>.");
    assert.ok(html.includes('<p class="hint">bad settings</p>'));
  });

  it("escapes file names and messages", () => {
    const html = lintPanelHtml(
      resources,
      fileView(
        {
          kind: "done",
          problems: [problem({ message: "<script>alert(1)</script>", code: "<b>" })],
        },
        "<img src=x onerror=alert(1)>.py",
      ),
    );
    assert.ok(!html.includes("<script>"));
    assert.ok(!html.includes("<img src=x"));
    assert.ok(!html.includes("<b>"));
    assert.ok(html.includes("&lt;script&gt;alert(1)&lt;/script&gt;"));
  });

  for (const [what, view] of VIEWS) {
    it(`runs no script and loads nothing from the network (${what})`, () => {
      const html = lintPanelHtml(resources, view);
      const policy = /http-equiv="Content-Security-Policy" content="([^"]*)"/.exec(html)?.[1] ?? "";
      assert.ok(policy.startsWith("default-src 'none'"));
      assert.ok(policy.includes(`img-src ${SOURCE}`));
      assert.ok(!policy.includes("script-src"));
      assert.ok(!html.includes("<script"));
      assert.ok(!/\son\w+=/.test(html));
      assert.ok(!/(src|href)="https?:\/\/(?!file\+\.vscode-resource)/.test(html));
    });
  }
});

describe("escapeHtml", () => {
  it("escapes the five special characters", () => {
    assert.equal(escapeHtml(`&"'<>`), "&amp;&quot;&#39;&lt;&gt;");
  });

  it("leaves other text alone", () => {
    assert.equal(escapeHtml("lint-clean.svg"), "lint-clean.svg");
  });
});
