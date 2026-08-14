/**
 * What a legal `nick` and a legal `body` are, defined once.
 *
 * A terminal reads its input as a mixture of text and commands, so a message
 * body is not inert data: `ESC ] 52` writes to the reader's system clipboard,
 * `ESC [ 2J` clears their screen, and a single newline puts words on a line of
 * their own under whatever nickname the attacker chose. Every one of those is
 * a channel member attacking the other members' terminals, and encryption is no
 * defence — the attack arrives inside a message that opens perfectly, under a
 * key the attacker legitimately holds.
 *
 * These functions report the problem rather than throwing, because their two
 * callers raise different errors: the protocol layer a `PayloadError`, the CLI
 * a `UsageError`. Both get the same rule, which is the point of the module.
 * A `null` result means the value is legal.
 */

/** UTF-8 bytes, not characters: the cap is a budget on the wire, and
 * `String.length` counts UTF-16 code units, so an emoji-heavy body would slip
 * past one measured that way. */
export const MAX_BODY_BYTES = 1900;
export const MAX_NICK_BYTES = 32;

/**
 * C0 controls and DEL, the C1 range an 8-bit terminal may act on, the two
 * Unicode line separators, and the bidirectional overrides — which reorder
 * rendered text without being visible, and so spoof by the same route an
 * escape sequence does.
 */
const CONTROL_PATTERN = /[\u0000-\u001F\u007F-\u009F\u2028\u2029\u202A-\u202E\u2066-\u2069]/u;

/** Zero-width characters, which `/\s/u` does not match and which render as
 * nothing at all: two nicknames spelt differently look identical. */
const ZERO_WIDTH_PATTERN = /[\u200B-\u200D\u2060\uFEFF]/u;

/** Why this is not a legal message body, or `null` if it is one. */
export function bodyProblem(body: string): string | null {
  return sizeProblem("body", body, MAX_BODY_BYTES) ?? controlProblem("body", body);
}

/** Why this is not a legal nickname, or `null` if it is one. A nickname is
 * held to more than a body: it is rendered next to other people's names, so
 * anything that lets one name imitate another is out. */
export function nickProblem(nick: string): string | null {
  return (
    sizeProblem("nick", nick, MAX_NICK_BYTES) ??
    controlProblem("nick", nick) ??
    blankProblem(nick)
  );
}

function sizeProblem(field: string, value: string, maxBytes: number): string | null {
  const bytes = Buffer.byteLength(value, "utf8");
  if (bytes <= maxBytes) return null;

  return `${field} is ${bytes} UTF-8 bytes, over the limit of ${maxBytes}`;
}

function controlProblem(field: string, value: string): string | null {
  const found = CONTROL_PATTERN.exec(value);
  if (found === null) return null;

  return `${field} contains ${codePointName(found[0])}, a control or direction-override character`;
}

function blankProblem(nick: string): string | null {
  const found = /\s/u.exec(nick) ?? ZERO_WIDTH_PATTERN.exec(nick);
  if (found === null) return null;

  return `nick contains ${codePointName(found[0])}, a whitespace or zero-width character`;
}

/** Named rather than quoted. The reason travels into a notice on somebody's
 * screen, so echoing the offending character back would print the escape
 * sequence this module exists to keep off the terminal. */
function codePointName(character: string): string {
  const code = character.codePointAt(0) ?? 0;
  return `U+${code.toString(16).toUpperCase().padStart(4, "0")}`;
}
