/**
 * What a nickname and a message body are allowed to contain.
 *
 * A terminal executes what it is shown: ESC ]52 writes the reader's clipboard, ESC [2J
 * clears their screen, and a newline forges a transcript line under any nickname.
 * Encryption is no defence — the attacker legitimately holds the key.
 *
 * JavaScript's /\s/u does not match zero-width characters, so they need a pattern of
 * their own or two nicknames spelt differently render identically.
 */

export const MAX_BODY_BYTES = 1900;
export const MAX_NICK_BYTES = 32;

const CONTROL_PATTERN = /[\u0000-\u001F\u007F-\u009F\u2028\u2029\u202A-\u202E\u2066-\u2069]/u;

const ZERO_WIDTH_PATTERN = /[\u200B-\u200D\u2060\uFEFF]/u;

export function bodyProblem(body: string): string | null {
  return sizeProblem("body", body, MAX_BODY_BYTES) ?? controlProblem("body", body);
}

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

function codePointName(character: string): string {
  const code = character.codePointAt(0) ?? 0;
  return `U+${code.toString(16).toUpperCase().padStart(4, "0")}`;
}
