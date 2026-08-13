import { sha256 } from "@noble/hashes/sha2.js";
import { WORDLIST } from "./wordlist.ts";

/** Eight words is 64 bits — enough that forging a colliding key to fool a
 * human comparison is not worth attempting, and still short enough to read
 * aloud over a phone call. */
const FINGERPRINT_WORDS = 8;

/**
 * Renders a public key as eight words for humans to compare out of band.
 * Hexadecimal is unreadable aloud and invites people to check the first four
 * characters and stop; words are what make `/verify` a thing a person will
 * actually do.
 */
export function fingerprint(publicKey: Uint8Array): string {
  const digest = sha256(publicKey);
  const words: string[] = [];

  for (let index = 0; index < FINGERPRINT_WORDS; index++) {
    const byte = digest[index];
    if (byte === undefined) throw new Error("sha256 digest was too short");

    const word = WORDLIST[byte];
    if (word === undefined) throw new Error(`wordlist has no entry for byte ${byte}`);

    words.push(word);
  }

  return words.join(" ");
}
