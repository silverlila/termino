import { WORDLIST } from "./wordlist.ts";

const BYTE_OF_WORD = new Map(WORDLIST.map((word, byte) => [word, byte]));

const SEPARATOR_PATTERN = /[\s-]+/;

export class UnknownWordError extends Error {
  constructor(word: string) {
    super(`not a word from the list: ${word}`);
  }
}

export function words(bytes: Uint8Array): string {
  const rendered: string[] = [];

  for (const byte of bytes) {
    const word = WORDLIST[byte];
    if (word === undefined) throw new Error(`wordlist has no entry for byte ${byte}`);

    rendered.push(word);
  }

  return rendered.join(" ");
}

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
