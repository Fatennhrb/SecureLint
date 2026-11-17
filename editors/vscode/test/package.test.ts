import * as assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";

// Tests run from out/test, two folders below the extension.
const extension = join(__dirname, "..", "..");
const repo = join(extension, "..", "..");

interface Manifest {
  main: string;
  engines: { vscode: string };
  devDependencies: Record<string, string>;
  activationEvents: string[];
  contributes: {
    viewsContainers: { activitybar: { id: string; icon: string }[] };
    views: Record<string, { type: string; id: string; name: string }[]>;
  };
}

const manifest = JSON.parse(
  readFileSync(join(extension, "package.json"), "utf8"),
) as Manifest;

describe("the extension manifest", () => {
  it("starts from the bundled file", () => {
    assert.equal(manifest.main, "./dist/extension.js");
  });

  it("starts only for Python files", () => {
    assert.deepEqual(manifest.activationEvents, ["onLanguage:python"]);
  });

  it("gives Lint its own panel", () => {
    const container = manifest.contributes.viewsContainers.activitybar[0];
    assert.equal(container?.id, "securelint");
    assert.deepEqual(manifest.contributes.views.securelint, [
      { type: "webview", id: "securelint.lint", name: "Lint" },
    ]);
  });

  it("supports the VS Code its types describe", () => {
    const types = manifest.devDependencies["@types/vscode"];
    assert.equal(manifest.engines.vscode, `^${types ?? ""}`);
  });

  it("pins every development tool", () => {
    for (const [name, version] of Object.entries(manifest.devDependencies)) {
      assert.match(version, /^\d+\.\d+\.\d+$/, `${name} is not pinned`);
    }
  });
});

describe("Lint's drawings", () => {
  for (const mood of ["clean", "thinking", "problem"]) {
    it(`uses the same ${mood} drawing as the repository`, () => {
      const name = `lint-${mood}.svg`;
      assert.equal(
        readFileSync(join(extension, "media", name), "utf8"),
        readFileSync(join(repo, "assets", "lint", name), "utf8"),
      );
    });
  }

  it("has a one-colour icon for the activity bar", () => {
    const icon = readFileSync(join(extension, "media", "lint-icon.svg"), "utf8");
    assert.ok(!/#[0-9a-f]{3,6}\b/i.test(icon), "the icon should use currentColor only");
  });
});

describe("the package", () => {
  it("has the same license as the repository", () => {
    assert.equal(
      readFileSync(join(extension, "LICENSE"), "utf8"),
      readFileSync(join(repo, "LICENSE"), "utf8"),
    );
  });

  it("keeps only what the extension needs to run", () => {
    const kept = readFileSync(join(extension, ".vscodeignore"), "utf8")
      .split(/\r?\n/)
      .filter((line) => line !== "" && !line.startsWith("#"));
    assert.deepEqual(kept, [
      "**",
      "!dist/extension.js",
      "!media/**",
      "!package.json",
      "!README.md",
      "!LICENSE",
    ]);
  });
});
