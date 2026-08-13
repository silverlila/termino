import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex } from "@noble/hashes/utils.js";
import { bytesFromWords, words } from "./fingerprint.ts";

/**
 * The pre-shared key: the one secret two people carry to each other out of
 * band, and everything derived straight from it.
 *
 * It is generated, never chosen. A human-chosen secret would be guessable
 * offline by anyone who records one frame, because the handle travels to the
 * relay in the clear and is a function of the secret; 128 random bits are not
 * guessable at any rate, which is what lets the derivation be a plain HKDF
 * rather than a deliberately slow password hash.
 *
 * The key is not the message key. It authenticates the session — it is folded
 * into a per-session Diffie-Hellman exchange as proof of who is on the other
 * end — so obtaining it opens nothing that was recorded earlier.
 */

/** 128 bits. Rendered as one word per byte, so also the invite's word count. */
export const PSK_BYTES = 16;

/** Distinct from every other label so no two derivations from the same key
 * can produce the same bytes. */
const HANDLE_LABEL = "termino/handle/v2";

/** 16 bytes is 32 lowercase hex characters on the wire, the shape
 * `HANDLE_PATTERN` in `shared/protocol/frame.ts` accepts. */
const HANDLE_BYTES = 16;

const utf8 = (text: string) => new TextEncoder().encode(text);

/** Thrown when a value that is meant to be a pre-shared key is not one. */
export class InvalidPskError extends Error {
  constructor(readonly reason: string) {
    super(`invalid secret: ${reason}`);
  }
}

export function generatePsk(): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(PSK_BYTES));
}

/** The 16 hyphenated words an invite carries the key as. */
export function pskToWords(psk: Uint8Array): string {
  requirePskBytes(psk);

  return words(psk).replaceAll(" ", "-");
}

/** The inverse. Throws naming the offending word, or the count found, because
 * "invalid invite" leaves a person retyping 16 words with no idea which one
 * was wrong. */
export function wordsToPsk(text: string): Uint8Array {
  const spelt = text.trim();

  // Hyphens and nothing else. The secret travels inside a single-token invite,
  // so a space-separated spelling is a token that has already been broken by
  // something — a line wrap, a chat client, a shell — and accepting it would
  // make two different strings both count as the invite.
  if (/\s/.test(spelt)) {
    throw new InvalidPskError("the words of a secret are joined by hyphens, not spaces");
  }

  const psk = bytesFromWords(spelt);
  if (psk.length !== PSK_BYTES) {
    throw new InvalidPskError(`a secret is ${PSK_BYTES} words, found ${psk.length}`);
  }

  return psk;
}

/**
 * The channel address, and the only value derived from the key that the relay
 * ever sees. Deriving it from the key alone is what removes the channel name:
 * a second value to agree out of band adds no secrecy and one more way to
 * land silently in the wrong channel.
 */
export function deriveHandle(psk: Uint8Array): string {
  requirePskBytes(psk);

  return bytesToHex(hkdf(sha256, psk, undefined, utf8(HANDLE_LABEL), HANDLE_BYTES));
}

/** A short key would derive a handle and an invite that both look fine and
 * agree with nobody, so it is refused rather than padded or truncated. */
function requirePskBytes(psk: Uint8Array): void {
  if (psk.length !== PSK_BYTES) {
    throw new InvalidPskError(`a secret is ${PSK_BYTES} bytes, got ${psk.length}`);
  }
}
