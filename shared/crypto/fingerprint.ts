import { WORDLIST } from "./wordlist.ts";

/**
 * The byte-to-word codec, in both directions.
 *
 * Words are what a human can read aloud without losing their place and type
 * back without a transcription error, which is why both of the values people
 * handle — the pre-shared key in an invite, and the eight session words read
 * out to check for a man in the middle — are spelt this way. The mapping is
 * one word per byte and nothing else: no hashing, because the invite must
 * decode back to the exact bytes it was made from.
 */

/** Built once so decoding a word is a lookup rather than a scan of 256
 * entries per word. */
const BYTE_OF_WORD = new Map(WORDLIST.map((word, byte) => [word, byte]));

/** Words are joined by spaces when they are read aloud and by hyphens inside
 * an invite token, so decoding accepts either spelling. */
const SEPARATOR_PATTERN = /[\s-]+/;

/** Thrown rather than skipped: a word that is not in the list is a mistyped
 * invite or a misheard session word, and both must fail loudly. */
export class UnknownWordError extends Error {
  constructor(readonly word: string) {
    super(`not a word from the list: ${word}`);
  }
}

/** One word per byte, space-joined. Callers that need another joiner — the
 * invite uses hyphens — replace the spaces themselves. */
export function words(bytes: Uint8Array): string {
  const rendered: string[] = [];

  for (const byte of bytes) {
    const word = WORDLIST[byte];
    if (word === undefined) throw new Error(`wordlist has no entry for byte ${byte}`);

    rendered.push(word);
  }

  return rendered.join(" ");
}

/** The inverse of `words`. Surrounding whitespace is trimmed and words may be
 * separated by spaces or hyphens; anything else throws. */
export function bytesFromWords(text: string): Uint8Array {
  const tokens = text
    .trim()
    .split(SEPARATOR_PATTERN)
    .filter((token) => token.length > 0);

  const bytes = new Uint8Array(tokens.length);

  tokens.forEach((token, index) => {
    const byte = BYTE_OF_WORD.get(token);
    if (byte === undefined) throw new UnknownWordError(token);

    bytes[index] = byte;
  });

  return bytes;
}
