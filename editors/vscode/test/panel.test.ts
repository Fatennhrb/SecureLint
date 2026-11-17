import * as assert from "node:assert/strict";

import { escapeAttribute, lintPanelHtml } from "../src/panel";

const resources = {
  cspSource: "https://file+.vscode-resource.vscode-cdn.net",
  lintImage: "https://file+.vscode-resource.vscode-cdn.net/ext/media/lint-clean.svg",
};

function policyOf(html: string): string {
  const match = /http-equiv="Content-Security-Policy" content="([^"]*)"/.exec(html);
  assert.ok(match?.[1], "the page has no Content Security Policy");
  return match[1];
}

describe("Lint's panel", () => {
  it("shows Lint, all clean", () => {
    const html = lintPanelHtml(resources);
    assert.ok(html.includes(`<img src="${resources.lintImage}" alt="Lint, all clean">`));
  });

  it("blocks everything the page does not need", () => {
    const policy = policyOf(lintPanelHtml(resources));
    assert.ok(policy.startsWith("default-src 'none'"));
    assert.ok(policy.includes(`img-src ${resources.cspSource}`));
    assert.ok(!policy.includes("script-src"));
  });

  it("runs no script", () => {
    const html = lintPanelHtml(resources);
    assert.ok(!html.includes("<script"));
    assert.ok(!/\son\w+=/.test(html));
  });

  it("escapes what it puts in attributes", () => {
    const html = lintPanelHtml({ cspSource: "a", lintImage: '"><script>x</script>' });
    assert.ok(!html.includes("<script>"));
    assert.ok(html.includes("&quot;&gt;&lt;script&gt;"));
  });
});

describe("escapeAttribute", () => {
  it("escapes the four special characters", () => {
    assert.equal(escapeAttribute(`&"<>`), "&amp;&quot;&lt;&gt;");
  });

  it("leaves other text alone", () => {
    assert.equal(escapeAttribute("lint-clean.svg"), "lint-clean.svg");
  });
});
