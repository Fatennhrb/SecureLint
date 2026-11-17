import * as assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";

import {
  type Answer,
  answerKey,
  ASK_COMMAND,
  COPY_FIX_COMMAND,
  escapeHtml,
  isSafeDrawing,
  lintPanelHtml,
  type Mood,
  MOODS,
  PANEL_COMMANDS,
  type PanelResources,
  type PanelView,
  REVEAL_COMMAND,
  SILENCE_COMMAND,
} from "../src/panel";
import type { Problem } from "../src/report";
import type { FileState } from "../src/scan";

interface PanelLink {
  command: string;
  args: unknown;
  label: string;
}

/** Every link in the page: the command it runs, its arguments and its text. */
function linksOf(html: string): PanelLink[] {
  return [...html.matchAll(/<a[^>]*href="command:([^"?]*)\?([^"]*)"[^>]*>(.*?)<\/a>/g)].map(
    (match) => ({
      command: match[1] ?? "",
      args: JSON.parse(decodeURIComponent(match[2] ?? "")) as unknown,
      label: (match[3] ?? "").replace(/<[^>]*>/g, ""),
    }),
  );
}

/** A file with one SL102 problem on line 6, and this answer about it. */
function answered(answer: Answer): PanelView {
  return {
    kind: "file",
    name: "risky.py",
    uri: URI,
    state: { kind: "done", problems: [problem()] },
    answers: new Map([[answerKey(6, "SL102"), answer]]),
  };
}

// Lint's real drawings, from the extension's media folder (tests run from
// out/test, two folders below the extension).
function drawing(mood: Mood): string {
  return readFileSync(join(__dirname, "..", "..", "media", `lint-${mood}.svg`), "utf8");
}
const DRAWINGS: Record<Mood, string> = {
  clean: drawing("clean"),
  thinking: drawing("thinking"),
  problem: drawing("problem"),
};
const resources: PanelResources = { drawings: DRAWINGS, still: false };
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
  const match = /<div class="lint" data-mood="(\w+)">(<svg[\s\S]*?<\/svg>)\s*<\/div>/.exec(html);
  assert.ok(match, "the page does not show Lint");
  const mood = (match[1] ?? "") as Mood;
  // The drawing shown is the mood's own file, as it is.
  assert.equal(match[2], DRAWINGS[mood].trim());
  return mood;
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

  it("links a problem to its line, Ask Lint and Silence this", () => {
    const html = lintPanelHtml(resources, fileView({ kind: "done", problems: [problem()] }));
    assert.deepEqual(linksOf(html), [
      { command: REVEAL_COMMAND, args: [URI, 6], label: "Error: Line 6 · SL102" },
      { command: ASK_COMMAND, args: [URI, 6], label: "Ask Lint" },
      { command: SILENCE_COMMAND, args: [URI, 6, "SL102"], label: "Silence this" },
    ]);
  });

  it("offers no silencing for SL001, and no actions without a rule", () => {
    const html = lintPanelHtml(
      resources,
      fileView({
        kind: "done",
        problems: [problem({ code: "SL001" }), problem({ line: 9, code: "" })],
      }),
    );
    assert.deepEqual(
      linksOf(html).map((item) => item.command),
      [REVEAL_COMMAND, ASK_COMMAND, REVEAL_COMMAND],
    );
  });

  it("thinks while Lint is asked about a problem", () => {
    const html = lintPanelHtml(
      resources,
      answered({ kind: "asking" }),
    );
    assert.equal(lintShown(html), "thinking");
    assert.ok(html.includes("Lint is thinking…"));
    assert.ok(!linksOf(html).some((item) => item.command === ASK_COMMAND));
  });

  it("shows the answer, marked as possibly wrong, with Copy fix", () => {
    const html = lintPanelHtml(
      resources,
      answered({
        kind: "answered",
        explanation: { text: "The shell runs it.", fix: "Use a list of arguments." },
      }),
    );
    assert.equal(lintShown(html), "problem");
    assert.ok(html.includes("AI explanation (may be wrong)"));
    assert.ok(html.includes("<p>The shell runs it.</p>"));
    assert.ok(html.includes("Use a list of arguments."));
    const copy = linksOf(html).find((item) => item.command === COPY_FIX_COMMAND);
    // The fix itself is never put in the link: the command looks it up.
    assert.deepEqual(copy?.args, [URI, 6, "SL102"]);
  });

  it("has no Copy fix when the AI gave no fix", () => {
    const html = lintPanelHtml(
      resources,
      answered({ kind: "answered", explanation: { text: "The shell runs it.", fix: "" } }),
    );
    assert.ok(!linksOf(html).some((item) => item.command === COPY_FIX_COMMAND));
  });

  it("shows why Lint could not answer, and lets you ask again", () => {
    const html = lintPanelHtml(resources, answered({ kind: "failed", message: "no AI provider" }));
    assert.ok(html.includes('<p class="failed">no AI provider</p>'));
    assert.ok(linksOf(html).some((item) => item.label === "Ask again"));
  });

  it("escapes what the AI says", () => {
    const html = lintPanelHtml(
      resources,
      answered({
        kind: "answered",
        explanation: { text: "<img src=x onerror=alert(1)>", fix: '<a href="command:evil">x</a>' },
      }),
    );
    assert.ok(!html.includes("<img src=x"));
    assert.ok(!html.includes('href="command:evil'));
    assert.ok(html.includes("&lt;a href=&quot;command:evil&quot;&gt;"));
    assert.ok(linksOf(html).every((item) => PANEL_COMMANDS.includes(item.command)));
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
      assert.equal(policy, "default-src 'none'; style-src 'unsafe-inline'");
      assert.ok(!html.includes("<script"));
      assert.ok(!/\son\w+=/.test(html));
      assert.ok(!/\ssrc=/.test(html));
      assert.ok(!/href="(?!command:)/.test(html));
    });
  }
});

describe("Lint on dark themes", () => {
  it("gets a light circle behind it, so its dark hood stays visible", () => {
    const html = lintPanelHtml(resources, { kind: "idle" });
    assert.match(
      html,
      /\.vscode-dark \.lint, \.vscode-high-contrast:not\(\.vscode-high-contrast-light\) \.lint \{/,
    );
  });
});

describe("Lint's motion", () => {
  it("moves by default", () => {
    const html = lintPanelHtml(resources, { kind: "idle" });
    assert.ok(html.includes("<body>"));
  });

  it("stays still when VS Code is asked to reduce motion", () => {
    const html = lintPanelHtml({ ...resources, still: true }, { kind: "idle" });
    assert.ok(html.includes('<body class="still">'));
    assert.ok(html.includes(".still .lint * { animation: none !important; }"));
  });

  it("each drawing also stops by itself when the system asks for less motion", () => {
    for (const mood of MOODS) {
      assert.match(DRAWINGS[mood], /@media \(prefers-reduced-motion:reduce\)\{[^}]*animation:none\}/);
    }
  });
});

describe("isSafeDrawing", () => {
  it("accepts Lint's drawings", () => {
    for (const mood of MOODS) {
      assert.ok(isSafeDrawing(DRAWINGS[mood]), mood);
    }
  });

  const unsafe: [string, string][] = [
    ["a script", '<svg><script>alert(1)</script></svg>'],
    ["an event handler", '<svg onload="alert(1)"></svg>'],
    ["a link", '<svg><a href="https://x">x</a></svg>'],
    ["an outside picture", '<svg><image href="https://x/y.png"/></svg>'],
    ["a style from elsewhere", "<svg><style>@import 'https://x/y.css';</style></svg>"],
    ["a url() in a style", "<svg><style>g{fill:url(https://x)}</style></svg>"],
    ["HTML inside", "<svg><foreignObject><div>x</div></foreignObject></svg>"],
    ["something that is not an SVG", "<div>Lint</div>"],
  ];
  for (const [what, svg] of unsafe) {
    it(`refuses ${what}`, () => {
      assert.ok(!isSafeDrawing(svg));
    });
  }

  it("shows no drawing rather than an unsafe one", () => {
    const html = lintPanelHtml(
      { drawings: { ...DRAWINGS, clean: '<svg onload="alert(1)"></svg>' }, still: false },
      { kind: "idle" },
    );
    assert.ok(html.includes('<div class="lint" data-mood="clean"></div>'));
  });
});

describe("escapeHtml", () => {
  it("escapes the five special characters", () => {
    assert.equal(escapeHtml(`&"'<>`), "&amp;&quot;&#39;&lt;&gt;");
  });

  it("leaves other text alone", () => {
    assert.equal(escapeHtml("lint-clean.svg"), "lint-clean.svg");
  });
});
