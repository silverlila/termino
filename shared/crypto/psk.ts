import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex } from "@noble/hashes/utils.js";
import { bytesFromWords, words } from "./fingerprint.ts";

export const PSK_BYTES = 16;

const HANDLE_LABEL = "termino/handle/v2";

const HANDLE_BYTES = 16;

const utf8 = (text: string) => new TextEncoder().encode(text);

export class InvalidPskError extends Error {
  constructor(reason: string) {
    super(`invalid secret: ${reason}`);
  }
}

export function generatePsk(): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(PSK_BYTES));
}

export function pskToWords(psk: Uint8Array): string {
  requirePskBytes(psk);

  return words(psk).replaceAll(" ", "-");
}

export function wordsToPsk(text: string): Uint8Array {
  const spelt = text.trim();
  if (/\s/.test(spelt)) {
    throw new InvalidPskError("the words of a secret are joined by hyphens, not spaces");
  }

  const psk = bytesFromWords(spelt);
  if (psk.length !== PSK_BYTES) {
    throw new InvalidPskError(`a secret is ${PSK_BYTES} words, found ${psk.length}`);
  }

  return psk;
}

export function deriveHandle(psk: Uint8Array): string {
  requirePskBytes(psk);

  return bytesToHex(hkdf(sha256, psk, undefined, utf8(HANDLE_LABEL), HANDLE_BYTES));
}

function requirePskBytes(psk: Uint8Array): void {
  if (psk.length !== PSK_BYTES) {
    throw new InvalidPskError(`a secret is ${PSK_BYTES} bytes, got ${psk.length}`);
  }
}
