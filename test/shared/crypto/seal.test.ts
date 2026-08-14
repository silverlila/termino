import { describe, expect, test } from "bun:test";
import { bytesToHex } from "@noble/hashes/utils.js";
import { DecryptError, open, seal } from "../../../shared/crypto/seal.ts";

const utf8 = (text: string) => new TextEncoder().encode(text);
const text = (bytes: Uint8Array) => new TextDecoder().decode(bytes);

const KEY = new Uint8Array(32).fill(7);
const OTHER_KEY = new Uint8Array(32).fill(9);
const NONCE = Uint8Array.from({ length: 12 }, (_, index) => index);
const OTHER_NONCE = new Uint8Array(12).fill(3);
const PLAINTEXT = utf8("shipping it now");

describe("seal and open", () => {
  test("a sealed message opens back to the original plaintext", async () => {
    const ciphertext = await seal(KEY, NONCE, PLAINTEXT);

    expect(text(await open(KEY, NONCE, ciphertext))).toBe("shipping it now");
  });

  test("flipping a single byte of ciphertext makes open throw, not return altered plaintext", async () => {
    const ciphertext = await seal(KEY, NONCE, PLAINTEXT);

    const tampered = Uint8Array.from(ciphertext);
    const target = tampered[0];
    if (target === undefined) throw new Error("ciphertext was empty");
    tampered[0] = target ^ 0x01;

    await expect(open(KEY, NONCE, tampered)).rejects.toBeInstanceOf(DecryptError);
  });

  test("a different nonce cannot open the message", async () => {
    const ciphertext = await seal(KEY, NONCE, PLAINTEXT);

    await expect(open(KEY, OTHER_NONCE, ciphertext)).rejects.toBeInstanceOf(DecryptError);
  });

  test("a different key cannot open the message", async () => {
    const ciphertext = await seal(KEY, NONCE, PLAINTEXT);

    await expect(open(OTHER_KEY, NONCE, ciphertext)).rejects.toBeInstanceOf(DecryptError);
  });

  test("the ciphertext does not contain the plaintext", async () => {
    expect(text(await seal(KEY, NONCE, PLAINTEXT))).not.toContain("shipping");
  });

  test("a different nonce under the same key yields different ciphertext", async () => {
    // The ratchet derives one nonce per key and never reuses either. This is
    // what makes that safe rather than merely tidy: the two outputs share
    // nothing an observer could line up.
    const first = await seal(KEY, NONCE, PLAINTEXT);
    const second = await seal(KEY, OTHER_NONCE, PLAINTEXT);

    expect(bytesToHex(first)).not.toBe(bytesToHex(second));
  });

  test("pins AES-256-GCM with a known answer", async () => {
    // Recorded from this implementation and checked against the shape
    // AES-256-GCM promises: 15 bytes of plaintext plus a 16-byte tag. Under a
    // derived nonce the same key and nonce *must* produce the same bytes, so
    // this is a value the wire depends on — a change to the cipher, the tag
    // length or the argument order breaks it here rather than between two
    // clients that can no longer talk.
    const expected =
      "6be980006d60b72e57db91bc8c371b00ca3b1c37bc846b1f1eaa4f9d1dd8c9";

    expect(bytesToHex(await seal(KEY, NONCE, PLAINTEXT))).toBe(expected);
  });
});
