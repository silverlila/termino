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
export const MAX_ROOM_BYTES = 64;
export const MAX_PASSPHRASE_BYTES = 256;

// Passphrase mode stops offline guessing, not online guessing: whoever runs the relay gets
// one try per session. Too short a phrase is found in a handful of tries.
export const MIN_PASSPHRASE_CHARACTERS = 10;

const CONTROL_PATTERN = /[\u0000-\u001F\u007F-\u009F\u2028\u2029\u202A-\u202E\u2066-\u2069]/u;
const EVERY_CONTROL_PATTERN = new RegExp(CONTROL_PATTERN.source, "gu");

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

/** Text nobody vetted — an error that quotes what was pasted — made safe to draw, with
 * each control character named in its place rather than executed. */
export function visible(text: string): string {
  return text.replace(EVERY_CONTROL_PATTERN, (character) => `<${codePointName(character)}>`);
}

export function roomProblem(room: string): string | null {
  if (room.trim() === "") return "a room name is required";
  return sizeProblem("room", room, MAX_ROOM_BYTES) ?? controlProblem("room", room) ?? zeroWidthProblem(room);
}

// Normalisation keeps zero-width characters, so a room name carrying one derives another
// handle than the same name typed plainly, and each side waits alone with no sign why.
function zeroWidthProblem(room: string): string | null {
  const found = ZERO_WIDTH_PATTERN.exec(room);
  if (found === null) return null;

  return `room contains ${codePointName(found[0])}, a zero-width character`;
}

export function passphraseProblem(passphrase: string): string | null {
  // Counted as the exchange will see it: five decomposed "é" are ten code points typed
  // but five characters keyed.
  const length = graphemes(passphrase.normalize("NFKC").trim()).length;
  if (length < MIN_PASSPHRASE_CHARACTERS) {
    return `a passphrase needs at least ${MIN_PASSPHRASE_CHARACTERS} characters — a few words you both remember`;
  }
  return sizeProblem("passphrase", passphrase, MAX_PASSPHRASE_BYTES) ?? controlProblem("passphrase", passphrase);
}

/** What a person counts as one character: "👍🏽" and a decomposed "é" are one each. */
export function graphemes(text: string): string[] {
  return [...new Intl.Segmenter().segment(text)].map((part) => part.segment);
}

export function withoutControls(text: string): string {
  return text.replace(EVERY_CONTROL_PATTERN, "");
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
