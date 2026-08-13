import { describe, expect, it } from "bun:test";
import {
  decodeFrame,
  encodeFrame,
  errFrame,
  FrameError,
  fromBase64,
  isClientFrame,
  MAX_FRAME_BYTES,
  msgFrame,
  presenceFrame,
  subFrame,
  toBase64,
} from "../../../shared/protocol/frame.ts";

const HANDLE = "63402012e8d78d978a4ab491cf2e5ae9";
const NONCE = Uint8Array.from({ length: 12 }, (_, index) => index);
const CIPHERTEXT = new TextEncoder().encode("not really ciphertext, but opaque to the relay");

describe("subscribe frames", () => {
  it("round-trips a subscribe frame", () => {
    const decoded = decodeFrame(encodeFrame(subFrame(HANDLE)));
    expect(decoded).toEqual({ v: 1, t: "sub", h: HANDLE });
  });
});

describe("message frames", () => {
  it("round-trips a message frame, preserving the ciphertext exactly", () => {
    const decoded = decodeFrame(encodeFrame(msgFrame(HANDLE, NONCE, CIPHERTEXT)));

    expect(decoded.t).toBe("msg");
    if (decoded.t !== "msg") throw new Error("expected a msg frame");
    expect(fromBase64(decoded.c)).toEqual(CIPHERTEXT);
    expect(fromBase64(decoded.n)).toEqual(NONCE);
  });

  it("carries exactly the five wire fields and nothing else", () => {
    expect(Object.keys(msgFrame(HANDLE, NONCE, CIPHERTEXT)).sort()).toEqual([
      "c",
      "h",
      "n",
      "t",
      "v",
    ]);
  });

  it("rejects a nonce that is not 12 bytes", () => {
    const short = { v: 1, t: "msg", h: HANDLE, n: toBase64(new Uint8Array(8)), c: "AAAA" };
    expect(() => decodeFrame(JSON.stringify(short))).toThrow(FrameError);
  });

  it("rejects an empty ciphertext", () => {
    const empty = { v: 1, t: "msg", h: HANDLE, n: toBase64(NONCE), c: "" };
    expect(() => decodeFrame(JSON.stringify(empty))).toThrow(FrameError);
  });
});

describe("version checking", () => {
  it("rejects a frame announcing version 2", () => {
    const future = JSON.stringify({ v: 2, t: "sub", h: HANDLE });
    expect(() => decodeFrame(future)).toThrow(FrameError);
  });

  it("rejects a frame with no version at all", () => {
    const versionless = JSON.stringify({ t: "sub", h: HANDLE });
    expect(() => decodeFrame(versionless)).toThrow(FrameError);
  });

  it("rejects a version sent as a string rather than an integer", () => {
    const stringy = JSON.stringify({ v: "1", t: "sub", h: HANDLE });
    expect(() => decodeFrame(stringy)).toThrow(FrameError);
  });
});

describe("size limits", () => {
  it("caps a frame at 8192 bytes", () => {
    // Written out rather than derived: the ceiling is a wire-contract value,
    // so this must be able to disagree with the module.
    expect(MAX_FRAME_BYTES).toBe(8192);
  });

  it("accepts a frame just under the limit", () => {
    const padding = "A".repeat(1000);
    const frame = encodeFrame(msgFrame(HANDLE, NONCE, new TextEncoder().encode(padding)));

    expect(Buffer.byteLength(frame)).toBeLessThan(MAX_FRAME_BYTES);
    expect(decodeFrame(frame).t).toBe("msg");
  });

  it("rejects a frame larger than 8192 bytes before parsing it", () => {
    const oversized = encodeFrame(
      msgFrame(HANDLE, NONCE, new TextEncoder().encode("A".repeat(MAX_FRAME_BYTES))),
    );

    expect(Buffer.byteLength(oversized)).toBeGreaterThan(MAX_FRAME_BYTES);
    expect(() => decodeFrame(oversized)).toThrow(FrameError);
  });

  it("measures the limit in bytes, not characters", () => {
    // Four bytes of UTF-8 per astral character: a frame that looks half the
    // limit by string length is over it on the wire.
    const wide = "\u{1F510}".repeat(MAX_FRAME_BYTES / 3);
    const frame = JSON.stringify({ v: 1, t: "sub", h: wide });

    expect(frame.length).toBeLessThan(MAX_FRAME_BYTES);
    expect(() => decodeFrame(frame)).toThrow(FrameError);
  });
});

describe("handle validation", () => {
  const invalid: Record<string, string> = {
    "uppercase hex": "63402012E8D78D978A4AB491CF2E5AE9",
    "too short": "63402012e8d78d978a4ab491cf2e5ae",
    "too long": "63402012e8d78d978a4ab491cf2e5ae9a",
    "non-hex characters": "63402012e8d78d978a4ab491cf2e5azz",
    empty: "",
  };

  for (const [description, handle] of Object.entries(invalid)) {
    it(`rejects a handle with ${description}`, () => {
      expect(() => decodeFrame(JSON.stringify({ v: 1, t: "sub", h: handle }))).toThrow(FrameError);
    });
  }

  it("rejects a handle that is not a string", () => {
    expect(() => decodeFrame(JSON.stringify({ v: 1, t: "sub", h: 42 }))).toThrow(FrameError);
  });
});

describe("malformed input", () => {
  it("rejects text that is not JSON", () => {
    expect(() => decodeFrame("{not json")).toThrow(FrameError);
  });

  it("rejects a JSON array", () => {
    expect(() => decodeFrame("[1, 2, 3]")).toThrow(FrameError);
  });

  it("rejects JSON null", () => {
    expect(() => decodeFrame("null")).toThrow(FrameError);
  });

  it("rejects an unknown frame type", () => {
    expect(() => decodeFrame(JSON.stringify({ v: 1, t: "shutdown" }))).toThrow(FrameError);
  });

  it("decodes a frame delivered as bytes rather than a string", () => {
    const bytes = new TextEncoder().encode(encodeFrame(subFrame(HANDLE)));
    expect(decodeFrame(bytes)).toEqual({ v: 1, t: "sub", h: HANDLE });
  });
});

describe("relay-originated frames", () => {
  it("round-trips a presence frame", () => {
    expect(decodeFrame(encodeFrame(presenceFrame(3)))).toEqual({ v: 1, t: "presence", n: 3 });
  });

  it("rejects a presence count that is not a non-negative integer", () => {
    expect(() => decodeFrame(JSON.stringify({ v: 1, t: "presence", n: -1 }))).toThrow(FrameError);
    expect(() => decodeFrame(JSON.stringify({ v: 1, t: "presence", n: 1.5 }))).toThrow(FrameError);
  });

  it("round-trips each error code", () => {
    for (const code of ["rate_limited", "bad_frame", "not_subscribed"] as const) {
      expect(decodeFrame(encodeFrame(errFrame(code)))).toEqual({ v: 1, t: "err", code });
    }
  });

  it("rejects an unknown error code", () => {
    expect(() => decodeFrame(JSON.stringify({ v: 1, t: "err", code: "teapot" }))).toThrow(
      FrameError,
    );
  });

  it("separates the frames a client may send from the ones only a relay sends", () => {
    expect(isClientFrame(subFrame(HANDLE))).toBe(true);
    expect(isClientFrame(msgFrame(HANDLE, NONCE, CIPHERTEXT))).toBe(true);
    expect(isClientFrame(presenceFrame(2))).toBe(false);
    expect(isClientFrame(errFrame("bad_frame"))).toBe(false);
  });
});

describe("base64", () => {
  it("round-trips arbitrary bytes", () => {
    const bytes = Uint8Array.from({ length: 256 }, (_, index) => index);
    expect(fromBase64(toBase64(bytes))).toEqual(bytes);
  });

  it("rejects characters outside the alphabet instead of silently dropping them", () => {
    expect(() => fromBase64("abc$def")).toThrow(FrameError);
  });
});
