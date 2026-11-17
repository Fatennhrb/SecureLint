// Runs `npm audit` and fails on any known vulnerability, except the few
// listed below. An entry stays only while there is no fixed version, and
// must say why it cannot harm the extension.
import { execFileSync } from "node:child_process";
import process from "node:process";

const ALLOWED = {
  // picomatch <= 4.0.7, ReDoS. No fixed version yet (checked 2026-11-17).
  // Only the linter uses it (typescript-eslint -> tinyglobby), to match
  // file paths from our own tsconfig. It is not in the bundled extension.
  "GHSA-fc5q-39xc-vjpf": "picomatch",
};

function runAudit() {
  // `npm run audit` gives the path of npm's own script, so npm can be
  // started through Node without a shell on every system.
  const npm = process.env.npm_execpath;
  if (!npm) throw new Error("Run this with `npm run audit`.");
  try {
    return execFileSync(process.execPath, [npm, "audit", "--json"], {
      encoding: "utf8",
    });
  } catch (error) {
    // npm audit exits with 1 when it finds something; the report is still printed.
    if (typeof error.stdout === "string" && error.stdout !== "") return error.stdout;
    throw error;
  }
}

const report = JSON.parse(runAudit());
const found = new Map();
for (const entry of Object.values(report.vulnerabilities ?? {})) {
  for (const cause of entry.via) {
    if (typeof cause === "object") {
      const id = /GHSA(-[0-9a-z]{4}){3}/.exec(cause.url)?.[0] ?? cause.url;
      found.set(id, `${cause.name}: ${cause.title} (${cause.severity})`);
    }
  }
}

const blocking = [...found].filter(([id]) => !(id in ALLOWED));
for (const [id, text] of found) {
  console.log(`${id in ALLOWED ? "allowed " : "BLOCKING"} ${id} ${text}`);
}
for (const id of Object.keys(ALLOWED)) {
  if (!found.has(id)) console.log(`${id} is gone: remove it from scripts/audit.mjs`);
}
if (blocking.length > 0) {
  console.log(`${String(blocking.length)} vulnerability(ies) to fix.`);
  process.exit(1);
}
console.log("No vulnerabilities besides the allowed ones.");
