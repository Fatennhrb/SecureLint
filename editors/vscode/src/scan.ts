/**
 * Run SecureLint on one file and return what it found. Kept apart from the
 * VS Code API so it can be tested on its own.
 *
 * SecureLint is started directly, never through a shell, so nothing in a
 * file name can be read as a command.
 */

import { execFile } from "node:child_process";
import * as path from "node:path";

import { type Problem, problemsFromReport } from "./report";

/** How long one scan may take before it is stopped. */
export const SCAN_TIMEOUT_MS = 30_000;

/**
 * How long explaining one line may take: the AI may be asked again when it
 * is busy or slow (see SecureLint's README), so this is much longer.
 */
export const EXPLAIN_TIMEOUT_MS = 180_000;

/** The largest report read; a bigger one is refused. */
const MAX_REPORT_BYTES = 10 * 1024 * 1024;

/** SecureLint's exit codes: 0 nothing blocks, 1 findings block. */
const EXIT_CLEAN = 0;
const EXIT_FINDINGS = 1;

export type ScanOutcome =
  | { readonly kind: "done"; readonly problems: Problem[] }
  | { readonly kind: "not-found"; readonly command: string }
  | { readonly kind: "cancelled" }
  | { readonly kind: "failed"; readonly message: string };

/** What is known about a file: being checked, or how its last check ended. */
export type FileState =
  | { readonly kind: "checking" }
  | Exclude<ScanOutcome, { readonly kind: "cancelled" }>;

export interface ScanRequest {
  /** The program to start, for example "securelint". */
  readonly command: string;
  /** Arguments put before SecureLint's own (used by tests). */
  readonly prefixArgs?: readonly string[];
  /** The absolute path of the Python file to scan. */
  readonly file: string;
  /** Stops the scan, for example when the file is saved again. */
  readonly signal?: AbortSignal;
}

/** Scan one file. Never throws: every problem is an outcome. */
export function scanFile(request: ScanRequest): Promise<ScanOutcome> {
  return run(request, ["scan", "--format", "json", request.file], SCAN_TIMEOUT_MS);
}

/**
 * Ask SecureLint to explain the findings on one line, with the project's AI
 * provider (`securelint explain`, from SecureLint 1.1.0). The problems
 * returned are that line's, each with its explanation.
 */
export function explainLine(request: ScanRequest, line: number): Promise<ScanOutcome> {
  const args = ["explain", request.file, "--line", String(line), "--format", "json"];
  return run(request, args, EXPLAIN_TIMEOUT_MS);
}

function run(request: ScanRequest, args: string[], timeout: number): Promise<ScanOutcome> {
  return new Promise((resolve) => {
    execFile(
      request.command,
      [...(request.prefixArgs ?? []), ...args],
      {
        // SecureLint finds the project's settings from the file itself.
        cwd: path.dirname(request.file),
        encoding: "utf8",
        timeout,
        maxBuffer: MAX_REPORT_BYTES,
        windowsHide: true,
        ...(request.signal ? { signal: request.signal } : {}),
      },
      (error, stdout, stderr) => {
        resolve(outcome(request.command, timeout, error, stdout, stderr));
      },
    );
  });
}

function outcome(
  command: string,
  timeout: number,
  error: (Error & { code?: unknown; killed?: boolean }) | null,
  stdout: string,
  stderr: string,
): ScanOutcome {
  if (error?.name === "AbortError") {
    return { kind: "cancelled" };
  }
  if (error?.code === "ENOENT") {
    return { kind: "not-found", command };
  }
  if (error?.killed === true) {
    return {
      kind: "failed",
      message: `SecureLint took longer than ${String(timeout / 1000)} seconds and was stopped.`,
    };
  }
  const exitCode = error === null ? EXIT_CLEAN : error.code;
  if (exitCode !== EXIT_CLEAN && exitCode !== EXIT_FINDINGS) {
    if (stderr.includes("invalid choice: 'explain'")) {
      return {
        kind: "failed",
        message: "Asking Lint needs SecureLint 1.1.0 or newer: pip install -U securelint",
      };
    }
    const detail = errorDetail(stderr) || error?.message || "no details";
    return { kind: "failed", message: `SecureLint stopped with an error: ${detail}` };
  }
  try {
    return { kind: "done", problems: problemsFromReport(stdout) };
  } catch (problem) {
    return { kind: "failed", message: (problem as Error).message };
  }
}

/**
 * What SecureLint said went wrong, without the lines that only say which
 * settings or baseline it used.
 */
export function errorDetail(stderr: string): string {
  return stderr
    .split(/\r?\n/)
    .map((line) => line.replace(/^securelint:\s*/, "").trim())
    .filter((line) => line !== "" && !line.startsWith("using "))
    .join(" ");
}
