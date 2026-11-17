import * as assert from "node:assert/strict";

import { silenceEdit } from "../src/silence";

describe("silenceEdit", () => {
  it("adds a comment at the end of the line", () => {
    const line = 'os.system("ping " + host)';
    assert.deepEqual(silenceEdit(line, "SL102"), {
      kind: "append",
      column: line.length,
      text: "  # securelint: ignore[SL102] ",
    });
  });

  it("ignores spaces at the end of the line", () => {
    const edit = silenceEdit("eval(x)   ", "SL101");
    assert.equal(edit.kind === "append" ? edit.column : -1, "eval(x)".length);
  });

  it("works after another tool's comment", () => {
    const line = "eval(x)  # noqa: S307";
    assert.equal(silenceEdit(line, "SL101").kind, "append");
  });

  it("adds the rule to a silencing comment already there", () => {
    const line = "run(x)  # securelint: ignore[SL102] our own command";
    assert.deepEqual(silenceEdit(line, "SL101"), {
      kind: "insert",
      column: line.indexOf("]"),
      text: ", SL101",
    });
  });

  it("does nothing when the rule is already silenced", () => {
    const edit = silenceEdit("run(x)  # securelint: ignore[SL101, SL102] ok", "SL102");
    assert.equal(edit.kind, "refuse");
  });

  it("refuses a line that continues on the next one", () => {
    assert.equal(silenceEdit("value = a + \\", "SL101").kind, "refuse");
  });

  it("refuses a line that ends inside a multi-line string", () => {
    assert.equal(silenceEdit('query = """SELECT * FROM t', "SL105").kind, "refuse");
    assert.equal(silenceEdit("query = '''SELECT", "SL105").kind, "refuse");
  });

  it("accepts a line with a complete multi-line string", () => {
    assert.equal(silenceEdit('eval("""x""")', "SL101").kind, "append");
  });

  it("refuses SL001, which is about a silencing comment itself", () => {
    assert.equal(silenceEdit("x = 1  # securelint: ignore[SL999]", "SL001").kind, "refuse");
  });

  it("refuses anything that is not a rule id", () => {
    for (const rule of ["", "sl102", "SL102]", "SL102 x", "<b>"]) {
      assert.equal(silenceEdit("eval(x)", rule).kind, "refuse", rule);
    }
  });
});
