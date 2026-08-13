import { describe, expect, it } from "bun:test";
import { BUCKETS, pad, PaddingError, unpad } from "../../../shared/crypto/pad.ts";

/** Written out rather than read from the module, so this file can disagree
 * with it. These five sizes are what the relay is allowed to learn. */
const EXPECTED_BUCKETS = [256, 512, 1024, 2048, 4096];

function bytesOf(length: number): Uint8Array {
  return Uint8Array.from({ length }, (_, index) => (index % 255) + 1);
}

describe("buckets", () => {
  it("pads to one of five sizes", () => {
    expect([...BUCKETS]).toEqual(EXPECTED_BUCKETS);
  });

  it("pads two different lengths in one bucket to the same size", () => {
    // The point of the whole module: "yes" and a paragraph look alike.
    expect(pad(bytesOf(3)).length).toBe(256);
    expect(pad(bytesOf(200)).length).toBe(256);
  });

  it("round-trips every bucket boundary", () => {
    for (const bucket of EXPECTED_BUCKETS) {
      // The last input that fits this bucket, and the first that does not.
      const largest = bucket - 2;
      expect(pad(bytesOf(largest)).length).toBe(bucket);
      expect(unpad(pad(bytesOf(largest)))).toEqual(bytesOf(largest));

      if (bucket === 4096) continue;
      expect(pad(bytesOf(largest + 1)).length).toBe(bucket * 2);
      expect(unpad(pad(bytesOf(largest + 1)))).toEqual(bytesOf(largest + 1));
    }
  });

  it("round-trips an empty input", () => {
    expect(unpad(pad(new Uint8Array(0)))).toEqual(new Uint8Array(0));
  });

  it("round-trips a payload whose own bytes are zero", () => {
    // Zero is also the fill byte, so a length prefix is what tells the two
    // apart — a trailing sentinel scheme would not survive this case.
    const zeros = new Uint8Array(40);
    expect(unpad(pad(zeros))).toEqual(zeros);
  });

  it("pad throws on input larger than the largest bucket", () => {
    // 4094 is the top bucket less the two-byte length prefix.
    expect(pad(bytesOf(4094)).length).toBe(4096);
    expect(() => pad(bytesOf(4095))).toThrow(PaddingError);
  });
});

describe("malformed padding", () => {
  it("unpad throws on a buffer that is not exactly one bucket long", () => {
    expect(() => unpad(new Uint8Array(255))).toThrow(PaddingError);
    expect(() => unpad(new Uint8Array(257))).toThrow(PaddingError);
    expect(() => unpad(new Uint8Array(0))).toThrow(PaddingError);
  });

  it("unpad throws on a length prefix that exceeds the buffer", () => {
    const padded = pad(bytesOf(10));
    // 0x0400 = 1024, well past the 256-byte bucket it claims to describe.
    padded[0] = 0x04;
    padded[1] = 0x00;

    expect(() => unpad(padded)).toThrow(PaddingError);
  });

  it("unpad throws on non-zero bytes in the fill region", () => {
    const padded = pad(bytesOf(10));
    padded[200] = 1;

    expect(() => unpad(padded)).toThrow(PaddingError);
  });
});
