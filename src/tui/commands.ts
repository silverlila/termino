/**
 * The composer's grammar: a line beginning with `/` is a command, anything
 * else is a message.
 *
 * Parsing is kept apart from acting on the result. This module knows nothing
 * about the session or the screen, so the whole grammar — including what counts
 * as a badly written command — is decidable from a string alone.
 */

/** What `/help` prints, and the list `parseComposerInput` recognises. */
export const COMMANDS = [
  { usage: "/help", summary: "list these commands" },
  { usage: "/exit", summary: "leave the channel and close termino" },
] as const;

export type ComposerInput =
  /** Send this. */
  | { kind: "message"; body: string }
  /** List the commands. */
  | { kind: "help" }
  /** Close the session and the program. */
  | { kind: "exit" }
  /** A command that cannot be run. Told to the user; never sent to anybody —
   * a mistyped command going out as chat is how people leak what they meant
   * to type privately. */
  | { kind: "unusable"; reason: string };

export function parseComposerInput(line: string): ComposerInput {
  const trimmed = line.trim();
  if (!trimmed.startsWith("/")) return { kind: "message", body: trimmed };

  const [name = ""] = trimmed.split(/\s+/);

  if (name === "/help") return { kind: "help" };
  if (name === "/exit") return { kind: "exit" };

  return { kind: "unusable", reason: `unknown command ${name} — /help lists them` };
}
