import * as assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { errorDetail, explainLine, scanFile, type ScanRequest } from "../src/scan";

// A stand-in for SecureLint: a small Node script, started with this Node.
let folder = "";

function fake(name: string, body: string): ScanRequest {
  const script = join(folder, `${name}.js`);
  writeFileSync(script, body);
  return {
    command: process.execPath,
    prefixArgs: [script],
    file: join(folder, "app.py"),
  };
}

const CLEAN = JSON.stringify({ format_version: 1, findings: [], warnings: [], failures: [] });
const FOUND = JSON.stringify({
  format_version: 1,
  findings: [
    {
      rule_id: "SL101",
      severity: "high",
      line: 1,
      column: 1,
      message: "eval() runs its argument as Python code.",
    },
  ],
  warnings: [],
  failures: [],
});

describe("scanFile", () => {
  before(() => {
    folder = mkdtempSync(join(tmpdir(), "securelint-scan-"));
  });

  after(() => {
    rmSync(folder, { recursive: true, force: true });
  });

  it("reads a clean scan (exit code 0)", async () => {
    const outcome = await scanFile(fake("clean", `process.stdout.write(${JSON.stringify(CLEAN)});`));
    assert.deepEqual(outcome, { kind: "done", problems: [] });
  });

  it("reads findings (exit code 1)", async () => {
    const outcome = await scanFile(
      fake("found", `process.stdout.write(${JSON.stringify(FOUND)}); process.exitCode = 1;`),
    );
    if (outcome.kind !== "done") assert.fail(`the scan ended with ${outcome.kind}`);
    assert.equal(outcome.problems[0]?.code, "SL101");
  });

  it("asks for the JSON report of the file, as separate arguments", async () => {
    const request = fake(
      "args",
      `const fs = require("fs");
       fs.writeFileSync(process.argv[1] + ".args", JSON.stringify(process.argv.slice(2)));
       process.stdout.write(${JSON.stringify(CLEAN)});`,
    );
    const odd = join(folder, "my file; echo hi.py");
    await scanFile({ ...request, file: odd });
    const args = JSON.parse(readFileSync(join(folder, "args.js.args"), "utf8")) as string[];
    assert.deepEqual(args, ["scan", "--format", "json", odd]);
  });

  it("reports an error exit with what SecureLint printed", async () => {
    const outcome = await scanFile(
      fake("error", `process.stderr.write("bad settings"); process.exitCode = 2;`),
    );
    assert.deepEqual(outcome, {
      kind: "failed",
      message: "SecureLint stopped with an error: bad settings",
    });
  });

  it("reports a report it cannot read", async () => {
    const outcome = await scanFile(fake("garbage", `process.stdout.write("hello");`));
    assert.deepEqual(outcome, {
      kind: "failed",
      message: "SecureLint's report is not valid JSON.",
    });
  });

  it("says when the program does not exist", async () => {
    const outcome = await scanFile({
      command: join(folder, "no-such-securelint"),
      file: join(folder, "app.py"),
    });
    assert.equal(outcome.kind, "not-found");
  });

  it("stops a scan when asked", async () => {
    const controller = new AbortController();
    const running = scanFile({
      ...fake("slow", "setTimeout(() => {}, 20000);"),
      signal: controller.signal,
    });
    controller.abort();
    assert.deepEqual(await running, { kind: "cancelled" });
  });
});

describe("explainLine", () => {
  before(() => {
    folder = mkdtempSync(join(tmpdir(), "securelint-explain-"));
  });

  after(() => {
    rmSync(folder, { recursive: true, force: true });
  });

  it("asks SecureLint to explain one line, in JSON", async () => {
    const request = fake(
      "explain-args",
      `require("fs").writeFileSync(process.argv[1] + ".args", JSON.stringify(process.argv.slice(2)));
       process.stdout.write(${JSON.stringify(CLEAN)});`,
    );
    await explainLine(request, 6);
    const args = JSON.parse(readFileSync(join(folder, "explain-args.js.args"), "utf8")) as string[];
    assert.deepEqual(args, ["explain", request.file, "--line", "6", "--format", "json"]);
  });

  it("returns the explanation SecureLint gave", async () => {
    const report = JSON.stringify({
      format_version: 1,
      findings: [
        {
          rule_id: "SL101",
          severity: "high",
          line: 6,
          column: 1,
          message: "eval() runs its argument as Python code.",
          explanation: "Because eval. Fix: Use ast.literal_eval.",
        },
      ],
      warnings: [],
      failures: [],
    });
    const outcome = await explainLine(fake("explained", `process.stdout.write(${JSON.stringify(report)});`), 6);
    if (outcome.kind !== "done") assert.fail(`the question ended with ${outcome.kind}`);
    assert.equal(outcome.problems[0]?.explanation, "Because eval. Fix: Use ast.literal_eval.");
  });

  it("says what went wrong, without the settings lines", async () => {
    const outcome = await explainLine(
      fake(
        "no-ai",
        `process.stderr.write("securelint: using settings from pyproject.toml\\n" +
           "securelint: no explanations were added: no AI provider is set up\\n");
         process.exitCode = 2;`,
      ),
      6,
    );
    assert.deepEqual(outcome, {
      kind: "failed",
      message: "SecureLint stopped with an error: no explanations were added: no AI provider is set up",
    });
  });

  it("says when SecureLint is too old to explain", async () => {
    const outcome = await explainLine(
      fake(
        "old",
        `process.stderr.write("securelint: error: argument command: invalid choice: 'explain'");
         process.exitCode = 2;`,
      ),
      6,
    );
    assert.deepEqual(outcome, {
      kind: "failed",
      message: "Asking Lint needs SecureLint 1.1.0 or newer: pip install -U securelint",
    });
  });
});

describe("errorDetail", () => {
  it("keeps what went wrong and drops the rest", () => {
    assert.equal(
      errorDetail("securelint: using baseline x\r\nsecurelint: error: bad\n\n"),
      "error: bad",
    );
  });
});
