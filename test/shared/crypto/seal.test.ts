import { describe, expect, test } from "bun:test";
import { DecryptError, open, seal } from "../../../shared/crypto/seal.ts";

const utf8 = (text: string) => new TextEncoder().encode(text);
const text = (bytes: Uint8Array) => new TextDecoder().decode(bytes);

const KEY = new Uint8Array(32).fill(7);
const OTHER_KEY = new Uint8Array(32).fill(9);
const PLAINTEXT = utf8("shipping it now");

describe("seal and open", () => {
  test("a sealed message opens back to the original plaintext", async () => {
    const sealed = await seal(KEY, PLAINTEXT);
    const opened = await open(KEY, sealed.nonce, sealed.ciphertext);

    expect(text(opened)).toBe("shipping it now");
  });

  test("flipping a single byte of ciphertext makes open throw, not return altered plaintext", async () => {
    const sealed = await seal(KEY, PLAINTEXT);

    const tampered = Uint8Array.from(sealed.ciphertext);
    const target = tampered[0];
    if (target === undefined) throw new Error("ciphertext was empty");
    tampered[0] = target ^ 0x01;

    await expect(open(KEY, sealed.nonce, tampered)).rejects.toBeInstanceOf(DecryptError);
  });

  test("flipping a single byte of the nonce makes open throw", async () => {
    const sealed = await seal(KEY, PLAINTEXT);

    const tampered = Uint8Array.from(sealed.nonce);
    const target = tampered[0];
    if (target === undefined) throw new Error("nonce was empty");
    tampered[0] = target ^ 0x01;

    await expect(open(KEY, tampered, sealed.ciphertext)).rejects.toBeInstanceOf(DecryptError);
  });

  test("a different key cannot open the message", async () => {
    const sealed = await seal(KEY, PLAINTEXT);

    await expect(open(OTHER_KEY, sealed.nonce, sealed.ciphertext)).rejects.toBeInstanceOf(DecryptError);
  });

  test("the ciphertext does not contain the plaintext", async () => {
    const sealed = await seal(KEY, PLAINTEXT);

    expect(text(sealed.ciphertext)).not.toContain("shipping");
  });

  test("each seal uses a fresh 12-byte nonce", async () => {
    const first = await seal(KEY, PLAINTEXT);
    const second = await seal(KEY, PLAINTEXT);

    expect(first.nonce).toHaveLength(12);
    expect(second.nonce).toHaveLength(12);
    expect(Array.from(first.nonce)).not.toEqual(Array.from(second.nonce));
  });

  test("sealing the same plaintext twice yields different ciphertext", async () => {
    const first = await seal(KEY, PLAINTEXT);
    const second = await seal(KEY, PLAINTEXT);

    expect(Array.from(first.ciphertext)).not.toEqual(Array.from(second.ciphertext));
  });
});
