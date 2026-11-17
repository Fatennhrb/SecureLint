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
  const args = [...(request.prefixArgs ?? []), "scan", "--format", "json", request.file];
  return new Promise((resolve) => {
    execFile(
      request.command,
      args,
      {
        // SecureLint finds the project's settings from the file itself.
        cwd: path.dirname(request.file),
        encoding: "utf8",
        timeout: SCAN_TIMEOUT_MS,
        maxBuffer: MAX_REPORT_BYTES,
        windowsHide: true,
        ...(request.signal ? { signal: request.signal } : {}),
      },
      (error, stdout, stderr) => {
        resolve(outcome(request.command, error, stdout, stderr));
      },
    );
  });
}

function outcome(
  command: string,
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
      message: `SecureLint took longer than ${String(SCAN_TIMEOUT_MS / 1000)} seconds and was stopped.`,
    };
  }
  const exitCode = error === null ? EXIT_CLEAN : error.code;
  if (exitCode !== EXIT_CLEAN && exitCode !== EXIT_FINDINGS) {
    const detail = stderr.trim() || error?.message || "no details";
    return { kind: "failed", message: `SecureLint stopped with an error: ${detail}` };
  }
  try {
    return { kind: "done", problems: problemsFromReport(stdout) };
  } catch (problem) {
    return { kind: "failed", message: (problem as Error).message };
  }
}
