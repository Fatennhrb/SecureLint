import * as assert from "node:assert/strict";

import { problemsFromReport, ReportError, splitExplanation } from "../src/report";

function finding(fields: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    rule_id: "SL101",
    severity: "high",
    confidence: "high",
    path: "app.py",
    line: 2,
    column: 1,
    message: "eval() runs its argument as Python code.",
    fingerprint: "4045319bebfe8459",
    explanation: null,
    ...fields,
  };
}

function report(fields: Record<string, unknown> = {}): string {
  return JSON.stringify({
    format_version: 1,
    findings: [],
    warnings: [],
    failures: [],
    ...fields,
  });
}

describe("problemsFromReport", () => {
  it("reads a clean report", () => {
    assert.deepEqual(problemsFromReport(report()), []);
  });

  it("reads a finding", () => {
    assert.deepEqual(problemsFromReport(report({ findings: [finding()] })), [
      {
        line: 2,
        column: 1,
        level: "error",
        code: "SL101",
        message: "eval() runs its argument as Python code.",
      },
    ]);
  });

  it("shows blocking findings by severity", () => {
    const levels = problemsFromReport(
      report({
        findings: ["critical", "high", "medium", "low"].map((severity) =>
          finding({ severity }),
        ),
      }),
    ).map((problem) => problem.level);
    assert.deepEqual(levels, ["error", "error", "warning", "information"]);
  });

  it("never shows a policy warning as an error", () => {
    const levels = problemsFromReport(
      report({
        warnings: ["critical", "high", "medium", "low"].map((severity) =>
          finding({ severity }),
        ),
      }),
    ).map((problem) => problem.level);
    assert.deepEqual(levels, ["warning", "warning", "warning", "information"]);
  });

  it("shows a file that could not be scanned", () => {
    const [problem] = problemsFromReport(
      report({ failures: [{ path: "app.py", line: 3, message: "invalid syntax" }] }),
    );
    assert.equal(problem?.line, 3);
    assert.equal(problem.level, "error");
    assert.equal(problem.message, "SecureLint could not scan this file: invalid syntax");
  });

  it("puts a failure without a line on the first line", () => {
    const [problem] = problemsFromReport(
      report({ failures: [{ path: "app.py", line: null, message: "unreadable" }] }),
    );
    assert.equal(problem?.line, 1);
  });

  it("accepts a finding without a column", () => {
    const [problem] = problemsFromReport(report({ findings: [finding({ column: null })] }));
    assert.equal(problem?.column, 0);
  });

  it("does not show silenced or known findings", () => {
    const problems = problemsFromReport(
      report({ silenced: [finding()], known: [finding()], outside_change: [finding()] }),
    );
    assert.deepEqual(problems, []);
  });

  const broken: [string, string][] = [
    ["text that is not JSON", "not json"],
    ["a list instead of a report", "[]"],
    ["another format version", report({ format_version: 2 })],
    ["findings that are not a list", report({ findings: {} })],
    ["a finding that is not an object", report({ findings: ["SL101"] })],
    ["an unknown severity", report({ findings: [finding({ severity: "huge" })] })],
    ["a line of 0", report({ findings: [finding({ line: 0 })] })],
    ["a line that is text", report({ findings: [finding({ line: "2" })] })],
    ["a negative column", report({ findings: [finding({ column: -1 })] })],
    ["a message that is not text", report({ findings: [finding({ message: 5 })] })],
  ];
  for (const [what, text] of broken) {
    it(`refuses ${what}`, () => {
      assert.throws(() => problemsFromReport(text), ReportError);
    });
  }
});

describe("explanations in a report", () => {
  it("keeps the explanation SecureLint gave", () => {
    const [problem] = problemsFromReport(
      report({ findings: [finding({ explanation: "Because SL101. Fix: Use ast.literal_eval." })] }),
    );
    assert.equal(problem?.explanation, "Because SL101. Fix: Use ast.literal_eval.");
  });

  it("has no explanation when none was asked for", () => {
    const [problem] = problemsFromReport(report({ findings: [finding()] }));
    assert.ok(problem !== undefined && !("explanation" in problem));
  });

  it("refuses an explanation that is not text", () => {
    assert.throws(
      () => problemsFromReport(report({ findings: [finding({ explanation: 5 })] })),
      ReportError,
    );
  });
});

describe("splitExplanation", () => {
  it("splits the why from the fix", () => {
    assert.deepEqual(splitExplanation("The shell runs it. Fix: Pass a list."), {
      text: "The shell runs it.",
      fix: "Pass a list.",
    });
  });

  it("has an empty fix when the AI gave none", () => {
    assert.deepEqual(splitExplanation("The shell runs it."), {
      text: "The shell runs it.",
      fix: "",
    });
  });

  it("splits at the first fix only", () => {
    assert.deepEqual(splitExplanation("Why. Fix: Do A. Fix: then B."), {
      text: "Why.",
      fix: "Do A. Fix: then B.",
    });
  });
});
