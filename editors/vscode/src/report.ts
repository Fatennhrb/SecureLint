/**
 * Read SecureLint's JSON report (`securelint scan --format json`) and turn
 * it into the problems shown in the editor. Kept apart from the VS Code API
 * so it can be tested on its own.
 *
 * The report comes from another program, so every field is checked: a
 * report that does not look as expected is refused instead of being
 * half-shown.
 */

export type ProblemLevel = "error" | "warning" | "information";

export interface Problem {
  /** 1-based line, as SecureLint writes it. */
  readonly line: number;
  /** 1-based column; 0 when SecureLint gives no column. */
  readonly column: number;
  readonly level: ProblemLevel;
  /** The rule, for example SL101; empty for a file that could not be read. */
  readonly code: string;
  readonly message: string;
  /** The AI's explanation, only when SecureLint was asked for one. */
  readonly explanation?: string;
}

/** An AI explanation split into its two parts. */
export interface Explanation {
  readonly text: string;
  /** The fix the AI suggests; empty when it gave none. */
  readonly fix: string;
}

/**
 * Split an explanation into the "why" and the fix. SecureLint writes them
 * as one line: "<why> Fix: <fix>", the fix being optional.
 */
export function splitExplanation(explanation: string): Explanation {
  const at = explanation.indexOf(" Fix: ");
  if (at === -1) {
    return { text: explanation, fix: "" };
  }
  return { text: explanation.slice(0, at), fix: explanation.slice(at + " Fix: ".length).trim() };
}

export class ReportError extends Error {
  override name = "ReportError";
}

/** The only JSON format version this extension knows how to read. */
export const FORMAT_VERSION = 1;

const LEVEL_BY_SEVERITY: Readonly<Record<string, ProblemLevel>> = {
  critical: "error",
  high: "error",
  medium: "warning",
  low: "information",
};

/** Return the problems in a JSON report, in the order SecureLint wrote them. */
export function problemsFromReport(text: string): Problem[] {
  let document: unknown;
  try {
    document = JSON.parse(text);
  } catch {
    throw new ReportError("SecureLint's report is not valid JSON.");
  }
  const report = asObject(document, "the report");
  if (report.format_version !== FORMAT_VERSION) {
    throw new ReportError(
      `SecureLint's report has format version ${String(report.format_version)}; ` +
        `this extension reads version ${String(FORMAT_VERSION)}.`,
    );
  }

  const problems: Problem[] = [];
  // Findings that block: shown by how severe they are.
  for (const item of asArray(report.findings, "findings")) {
    problems.push(findingProblem(item, (severity) => LEVEL_BY_SEVERITY[severity]));
  }
  // Findings the project's policy reports without blocking: never errors.
  for (const item of asArray(report.warnings, "warnings")) {
    problems.push(
      findingProblem(item, (severity) => {
        const level = LEVEL_BY_SEVERITY[severity];
        return level === "error" ? "warning" : level;
      }),
    );
  }
  // Files that could not be scanned, for example because of a syntax error.
  for (const item of asArray(report.failures, "failures")) {
    const failure = asObject(item, "a failure");
    problems.push({
      line: failure.line === null ? 1 : asLine(failure.line, "a failure's line"),
      column: 0,
      level: "error",
      code: "",
      message: `SecureLint could not scan this file: ${asText(failure.message, "a failure's message")}`,
    });
  }
  return problems;
}

function findingProblem(
  item: unknown,
  levelOf: (severity: string) => ProblemLevel | undefined,
): Problem {
  const finding = asObject(item, "a finding");
  const severity = asText(finding.severity, "a finding's severity");
  const level = levelOf(severity);
  if (level === undefined) {
    throw new ReportError(`Unknown severity in SecureLint's report: ${severity}`);
  }
  const problem: Problem = {
    line: asLine(finding.line, "a finding's line"),
    column: finding.column === null ? 0 : asColumn(finding.column),
    level,
    code: asText(finding.rule_id, "a finding's rule"),
    message: asText(finding.message, "a finding's message"),
  };
  if (finding.explanation === undefined || finding.explanation === null) {
    return problem;
  }
  return { ...problem, explanation: asText(finding.explanation, "an explanation") };
}

function asObject(value: unknown, what: string): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new ReportError(`In SecureLint's report, ${what} is not an object.`);
  }
  return value as Record<string, unknown>;
}

function asArray(value: unknown, what: string): unknown[] {
  if (!Array.isArray(value)) {
    throw new ReportError(`In SecureLint's report, ${what} is not a list.`);
  }
  return value;
}

function asText(value: unknown, what: string): string {
  if (typeof value !== "string") {
    throw new ReportError(`In SecureLint's report, ${what} is not text.`);
  }
  return value;
}

function asLine(value: unknown, what: string): number {
  if (!Number.isSafeInteger(value) || (value as number) < 1) {
    throw new ReportError(`In SecureLint's report, ${what} is not a line number.`);
  }
  return value as number;
}

function asColumn(value: unknown): number {
  if (!Number.isSafeInteger(value) || (value as number) < 0) {
    throw new ReportError("In SecureLint's report, a finding's column is not a number.");
  }
  return value as number;
}
