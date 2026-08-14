import { describe, expect, it } from "bun:test";
import {
  deriveHandle,
  generatePsk,
  InvalidPskError,
  PSK_BYTES,
  pskToWords,
  wordsToPsk,
} from "../../../shared/crypto/psk.ts";

/** Recorded on first implementation, and permanent from here: an invite
 * written on a USB stick last month has to still parse, and a handle derived
 * on one machine has to name the same channel as one derived on the other.
 * Both values change if the wordlist order, the HKDF label or the byte
 * mapping is edited, which is exactly what this vector exists to catch. */
const VECTOR = {
  psk: Uint8Array.from([
    0x00, 0xff, 0x10, 0xa5, 0x3c, 0x7b, 0x91, 0xe2, 0x04, 0x8d, 0x6f, 0x3a, 0xab, 0x5c, 0x27, 0xde,
  ]),
  words:
    "acorn-yoga-bone-phone-emerald-level-neat-theater-angle-mosaic-july-eight-polar-gutter-cube-tank",
  handle: "e2bc40acf57296f22d6d53434880e618",
};

describe("a pre-shared key", () => {
  it("is 16 bytes the software generates rather than a person choosing", () => {
    expect(generatePsk()).toHaveLength(PSK_BYTES);
    expect(generatePsk()).not.toEqual(generatePsk());
  });

  it("round-trips 16 random bytes through words", () => {
    const psk = generatePsk();

    expect(wordsToPsk(pskToWords(psk))).toEqual(psk);
  });

  it("renders as 16 hyphenated words", () => {
    expect(pskToWords(generatePsk()).split("-")).toHaveLength(16);
  });

  it("pins the word encoding with a known answer", () => {
    expect(pskToWords(VECTOR.psk)).toBe(VECTOR.words);
    expect(wordsToPsk(VECTOR.words)).toEqual(VECTOR.psk);
  });

  it("rejects a secret written with spaces instead of hyphens", () => {
    // The invite grammar is one token joined by hyphens. A spelling that only
    // arises after something has already broken the token must not read as
    // the same secret.
    const spaced = VECTOR.words.replaceAll("-", " ");

    expect(() => wordsToPsk(spaced)).toThrow(InvalidPskError);
    expect(() => wordsToPsk(spaced)).toThrow(/hyphens/);
  });

  it("rejects a word that is not in the list", () => {
    const mistyped = VECTOR.words.replace("phone", "phonee");

    expect(() => wordsToPsk(mistyped)).toThrow(/phonee/);
  });

  it("rejects the wrong number of words, saying how many it found", () => {
    const short = VECTOR.words.split("-").slice(0, 15).join("-");

    expect(() => wordsToPsk(short)).toThrow(InvalidPskError);
    expect(() => wordsToPsk(short)).toThrow(/found 15/);
  });

  it("refuses to render a key that is not 16 bytes", () => {
    expect(() => pskToWords(new Uint8Array(8))).toThrow(InvalidPskError);
  });
});

describe("the handle derived from a pre-shared key", () => {
  it("is 32 lowercase hex characters", () => {
    expect(deriveHandle(generatePsk())).toMatch(/^[0-9a-f]{32}$/);
  });

  it("is a pure function of the key, so both machines meet at one channel", () => {
    expect(deriveHandle(VECTOR.psk)).toBe(deriveHandle(Uint8Array.from(VECTOR.psk)));
  });

  it("differs for a key differing in one bit", () => {
    const flipped = Uint8Array.from(VECTOR.psk, (byte, index) => (index === 0 ? byte ^ 1 : byte));

    expect(deriveHandle(flipped)).not.toBe(deriveHandle(VECTOR.psk));
  });

  it("pins the handle derivation with a known answer", () => {
    expect(deriveHandle(VECTOR.psk)).toBe(VECTOR.handle);
  });

  it("refuses a key that is not 16 bytes", () => {
    expect(() => deriveHandle(new Uint8Array(8))).toThrow(InvalidPskError);
  });
});
