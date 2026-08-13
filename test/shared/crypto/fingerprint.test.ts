import { describe, expect, test } from "bun:test";
import {
  bytesFromWords,
  fingerprint,
  UnknownWordError,
  words,
} from "../../../shared/crypto/fingerprint.ts";
import { WORDLIST } from "../../../shared/crypto/wordlist.ts";

/** Recorded on first implementation. Pins both the byte-to-word mapping and
 * the order of the wordlist, either of which would silently change every
 * fingerprint users have already verified. */
const VECTOR = {
  publicKey: Uint8Array.from({ length: 32 }, (_, index) => index),
  words: "hobby birch site daisy hundred satin double hundred",
};

const OTHER_KEY = Uint8Array.from({ length: 32 }, (_, index) => 255 - index);

/** Computed independently of the wordlist's construction, so this test can
 * actually disagree with the list rather than restating it. */
function levenshtein(a: string, b: string): number {
  let previous = Array.from({ length: b.length + 1 }, (_, index) => index);

  for (let i = 1; i <= a.length; i++) {
    const current = [i];
    for (let j = 1; j <= b.length; j++) {
      const substitution = (previous[j - 1] ?? 0) + (a[i - 1] === b[j - 1] ? 0 : 1);
      const deletion = (previous[j] ?? 0) + 1;
      const insertion = (current[j - 1] ?? 0) + 1;
      current[j] = Math.min(substitution, deletion, insertion);
    }
    previous = current;
  }

  return previous[b.length] ?? 0;
}

describe("WORDLIST", () => {
  test("has exactly 256 entries, one per byte value", () => {
    expect(WORDLIST).toHaveLength(256);
  });

  test("contains no duplicates", () => {
    expect(new Set(WORDLIST).size).toBe(256);
  });

  test("is entirely lowercase ASCII, 4 to 7 letters", () => {
    const offenders = WORDLIST.filter((word) => !/^[a-z]{4,7}$/.test(word));

    expect(offenders).toEqual([]);
  });

  test("has no two words sharing a 3-letter prefix, so a misheard word cannot match a neighbour", () => {
    const prefixes = WORDLIST.map((word) => word.slice(0, 3));

    expect(new Set(prefixes).size).toBe(256);
  });

  test("has no two words within a Levenshtein distance of 1", () => {
    const tooClose: string[] = [];

    for (let i = 0; i < WORDLIST.length; i++) {
      for (let j = i + 1; j < WORDLIST.length; j++) {
        const a = WORDLIST[i];
        const b = WORDLIST[j];
        if (a === undefined || b === undefined) continue;
        if (levenshtein(a, b) < 2) tooClose.push(`${a}/${b}`);
      }
    }

    expect(tooClose).toEqual([]);
  });
});

describe("the byte-to-word codec", () => {
  test("renders one space-joined word per byte", () => {
    // Recorded literally rather than looked up in the wordlist, so this can
    // disagree with the list instead of restating it.
    expect(words(Uint8Array.from([0, 1, 255]))).toBe("acorn agent yoga");
  });

  test("round-trips arbitrary bytes", () => {
    const bytes = crypto.getRandomValues(new Uint8Array(8));

    expect(bytesFromWords(words(bytes))).toEqual(bytes);
  });

  test("decodes hyphen-separated words as well as spaces", () => {
    expect(bytesFromWords("acorn-agent-yoga")).toEqual(Uint8Array.from([0, 1, 255]));
  });

  test("does not hash, so eight session words decode back to their eight bytes", () => {
    const sas = Uint8Array.from([9, 8, 7, 6, 5, 4, 3, 2]);

    expect(words(sas).split(" ")).toHaveLength(8);
    expect(bytesFromWords(words(sas))).toEqual(sas);
  });

  test("throws naming the word that is not in the list", () => {
    expect(() => bytesFromWords("acorn agent yoghurt")).toThrow(UnknownWordError);
    expect(() => bytesFromWords("acorn agent yoghurt")).toThrow(/yoghurt/);
  });
});

describe("fingerprint", () => {
  test("produces the recorded known-answer words for a fixed public key", () => {
    expect(fingerprint(VECTOR.publicKey)).toBe(VECTOR.words);
  });

  test("returns exactly 8 whitespace-separated tokens", () => {
    expect(fingerprint(VECTOR.publicKey).split(/\s+/)).toHaveLength(8);
  });

  test("returns only words drawn from the wordlist, never hexadecimal", () => {
    const tokens = fingerprint(OTHER_KEY).split(/\s+/);
    const strangers = tokens.filter((token) => !WORDLIST.includes(token));

    expect(strangers).toEqual([]);
  });

  test("two different public keys produce different fingerprints", () => {
    expect(fingerprint(OTHER_KEY)).not.toBe(fingerprint(VECTOR.publicKey));
  });

  test("is deterministic for the same key", () => {
    expect(fingerprint(VECTOR.publicKey)).toBe(fingerprint(VECTOR.publicKey));
  });
});
