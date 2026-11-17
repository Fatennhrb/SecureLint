/**
 * Work out the comment that silences one finding on its line:
 * `# securelint: ignore[SL102] reason`. Kept apart from the VS Code API so
 * it can be tested on its own.
 *
 * SecureLint wants the rule named and a reason given, so the comment ends
 * with a placeholder the user types over.
 */

/** A rule id as SecureLint writes it, for example SL102. */
export const RULE_ID = /^[A-Z]+[0-9]+$/;

/** The text selected after the comment is added, for the user to replace. */
export const REASON_PLACEHOLDER = "why this is safe";

export type SilenceEdit =
  /** Add a new comment at the end of the line, with a reason to write. */
  | { readonly kind: "append"; readonly column: number; readonly text: string }
  /** Add the rule to the silencing comment already on the line. */
  | { readonly kind: "insert"; readonly column: number; readonly text: string }
  /** Nothing can or needs to be done; the reason says why. */
  | { readonly kind: "refuse"; readonly reason: string };

const EXISTING = /#\s*securelint:\s*ignore\[([^\]]*)\]/;

/** Return how to silence `rule` on a line whose text is `line`. */
export function silenceEdit(line: string, rule: string): SilenceEdit {
  if (!RULE_ID.test(rule)) {
    return { kind: "refuse", reason: "This problem has no rule to silence." };
  }
  if (rule === "SL001") {
    return {
      kind: "refuse",
      reason: "SL001 is about a silencing comment itself: fix or remove that comment instead.",
    };
  }

  const existing = EXISTING.exec(line);
  if (existing) {
    const rules = (existing[1] ?? "").split(",").map((part) => part.trim());
    if (rules.includes(rule)) {
      return { kind: "refuse", reason: `${rule} is already silenced on this line.` };
    }
    // Just before the closing bracket.
    const column = existing.index + existing[0].length - 1;
    return { kind: "insert", column, text: `, ${rule}` };
  }

  const code = line.trimEnd();
  if (code.endsWith("\\")) {
    return {
      kind: "refuse",
      reason: "This line continues on the next one, so a comment cannot be added at its end.",
    };
  }
  if (count(code, '"""') % 2 === 1 || count(code, "'''") % 2 === 1) {
    return {
      kind: "refuse",
      reason: "This line ends inside a multi-line string, so a comment would become part of it.",
    };
  }
  return {
    kind: "append",
    column: code.length,
    text: `  # securelint: ignore[${rule}] `,
  };
}

function count(text: string, part: string): number {
  return text.split(part).length - 1;
}
