/**
 * The composer's grammar: a line beginning with `/` is a command, anything
 * else is a message.
 *
 * Parsing is kept apart from acting on the result. This module knows nothing
 * about the trust store or the screen, so the whole grammar — including what
 * counts as a badly written command — is decidable from a string alone.
 */

export const VERIFY_USAGE = "usage: /verify <nick> <fingerprint>";

export type ComposerInput =
  /** Send this. */
  | { kind: "message"; body: string }
  /** Check `fingerprint` against the key stored for `nick`. */
  | { kind: "verify"; nick: string; fingerprint: string }
  /** A command that cannot be run. Told to the user; never sent to anybody —
   * a mistyped command going out as chat is how people leak what they meant
   * to type privately. */
  | { kind: "unusable"; reason: string };

export function parseComposerInput(line: string): ComposerInput {
  const trimmed = line.trim();
  if (!trimmed.startsWith("/")) return { kind: "message", body: trimmed };

  const [name = "", ...rest] = trimmed.split(/\s+/);
  if (name !== "/verify") {
    return {
      kind: "unusable",
      reason: `unknown command ${name} — the only command is /verify <nick> <fingerprint>`,
    };
  }

  const [nick, ...words] = rest;
  if (nick === undefined || words.length === 0) return { kind: "unusable", reason: VERIFY_USAGE };

  // Everything after the nickname is the fingerprint. It is eight words, so
  // reading only the next token would reject every correct spelling of it.
  return { kind: "verify", nick, fingerprint: words.join(" ") };
}
