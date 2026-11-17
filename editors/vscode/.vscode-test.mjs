// Runs the tests in test/integration inside a real VS Code.
//
// VS Code 1.100.0 is the oldest version the extension supports. With
// VSCODE_PATH set to a Code executable, that installation is used instead of
// downloading one.
import process from "node:process";

import { defineConfig } from "@vscode/test-cli";

export default defineConfig({
  files: "out/test/integration/**/*.test.js",
  version: "1.100.0",
  ...(process.env.VSCODE_PATH ? { useInstallation: { fromPath: process.env.VSCODE_PATH } } : {}),
  launchArgs: ["--disable-workspace-trust", "--disable-extensions"],
  mocha: { ui: "bdd", timeout: 90000 },
});
