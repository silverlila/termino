import { describe, expect, it } from "bun:test";
import {
  decodeFrame,
  encodeFrame,
  errFrame,
  FrameError,
  fromBase64,
  helloFrame,
  isClientFrame,
  MAX_FRAME_BYTES,
  msgFrame,
  PROTOCOL_VERSION,
  subFrame,
  toBase64,
} from "../../../shared/protocol/frame.ts";

const HANDLE = "63402012e8d78d978a4ab491cf2e5ae9";
const PUBLIC_KEY = Uint8Array.from({ length: 32 }, (_, index) => index);
const CIPHERTEXT = new TextEncoder().encode("not really ciphertext, but opaque to the relay");

describe("the protocol version", () => {
  it("is 2", () => {
    // Written out rather than compared to the constant: this is the value two
    // clients must agree on, so the test has to be able to disagree with it.
    expect(PROTOCOL_VERSION).toBe(2);
  });

  it("rejects a version 1 frame rather than trying to read it", () => {
    expect(() => decodeFrame(JSON.stringify({ v: 1, t: "sub", h: HANDLE }))).toThrow(FrameError);
  });

  it("rejects a frame with no version at all", () => {
    expect(() => decodeFrame(JSON.stringify({ t: "sub", h: HANDLE }))).toThrow(FrameError);
  });

  it("rejects a version sent as a string rather than an integer", () => {
    expect(() => decodeFrame(JSON.stringify({ v: "2", t: "sub", h: HANDLE }))).toThrow(FrameError);
  });
});

describe("subscribe frames", () => {
  it("round-trips a subscribe frame", () => {
    expect(decodeFrame(encodeFrame(subFrame(HANDLE)))).toEqual({ v: 2, t: "sub", h: HANDLE });
  });
});

describe("hello frames", () => {
  it("round-trips the public key exactly", () => {
    const decoded = decodeFrame(encodeFrame(helloFrame(HANDLE, PUBLIC_KEY)));

    expect(decoded.t).toBe("hello");
    if (decoded.t !== "hello") throw new Error("expected a hello frame");
    expect(fromBase64(decoded.k)).toEqual(PUBLIC_KEY);
  });

  it("carries exactly the four wire fields and nothing else", () => {
    expect(Object.keys(helloFrame(HANDLE, PUBLIC_KEY)).sort()).toEqual(["h", "k", "t", "v"]);
  });

  it("rejects a public key that is not 32 bytes", () => {
    const short = { v: 2, t: "hello", h: HANDLE, k: toBase64(new Uint8Array(16)) };
    expect(() => decodeFrame(JSON.stringify(short))).toThrow(FrameError);
  });

  it("rejects a public key that is not a string", () => {
    expect(() => decodeFrame(JSON.stringify({ v: 2, t: "hello", h: HANDLE, k: 42 }))).toThrow(
      FrameError,
    );
  });
});

describe("message frames", () => {
  it("round-trips a message frame, preserving the ciphertext exactly", () => {
    const decoded = decodeFrame(encodeFrame(msgFrame(HANDLE, 7, CIPHERTEXT)));

    expect(decoded.t).toBe("msg");
    if (decoded.t !== "msg") throw new Error("expected a msg frame");
    expect(fromBase64(decoded.c)).toEqual(CIPHERTEXT);
    expect(decoded.i).toBe(7);
  });

  it("carries exactly the four wire fields and nothing else", () => {
    // No `n`: the nonce is derived from the chain, so there is nothing to send
    // and nothing to validate.
    expect(Object.keys(msgFrame(HANDLE, 0, CIPHERTEXT)).sort()).toEqual(["c", "h", "i", "t", "v"]);
  });

  it("rejects a nonce field left over from version 1", () => {
    const withNonce = {
      v: 2,
      t: "msg",
      h: HANDLE,
      n: toBase64(new Uint8Array(12)),
      c: toBase64(CIPHERTEXT),
    };

    // The nonce is not merely ignored — a frame carrying one has no counter,
    // and a frame with no counter cannot be opened.
    expect(() => decodeFrame(JSON.stringify(withNonce))).toThrow(FrameError);
  });

  it("rejects an empty ciphertext", () => {
    const empty = { v: 2, t: "msg", h: HANDLE, i: 0, c: "" };
    expect(() => decodeFrame(JSON.stringify(empty))).toThrow(FrameError);
  });

  const badCounters: Record<string, unknown> = {
    negative: -1,
    fractional: 1.5,
    "a string": "3",
    "past 2^32 - 1": 4294967296,
    missing: undefined,
  };

  for (const [description, counter] of Object.entries(badCounters)) {
    it(`rejects a counter that is ${description}`, () => {
      const frame = { v: 2, t: "msg", h: HANDLE, i: counter, c: toBase64(CIPHERTEXT) };
      expect(() => decodeFrame(JSON.stringify(frame))).toThrow(FrameError);
    });
  }

  it("accepts the highest counter the wire allows", () => {
    const decoded = decodeFrame(encodeFrame(msgFrame(HANDLE, 4294967295, CIPHERTEXT)));

    expect(decoded.t).toBe("msg");
    if (decoded.t !== "msg") throw new Error("expected a msg frame");
    expect(decoded.i).toBe(4294967295);
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
    const frame = encodeFrame(msgFrame(HANDLE, 1, new TextEncoder().encode(padding)));

    expect(Buffer.byteLength(frame)).toBeLessThan(MAX_FRAME_BYTES);
    expect(decodeFrame(frame).t).toBe("msg");
  });

  it("rejects a frame larger than 8192 bytes before parsing it", () => {
    const oversized = encodeFrame(
      msgFrame(HANDLE, 1, new TextEncoder().encode("A".repeat(MAX_FRAME_BYTES))),
    );

    expect(Buffer.byteLength(oversized)).toBeGreaterThan(MAX_FRAME_BYTES);
    expect(() => decodeFrame(oversized)).toThrow(FrameError);
  });

  it("measures the limit in bytes, not characters", () => {
    // Four bytes of UTF-8 per astral character: a frame that looks half the
    // limit by string length is over it on the wire.
    const wide = "\u{1F510}".repeat(MAX_FRAME_BYTES / 3);
    const frame = JSON.stringify({ v: 2, t: "sub", h: wide });

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
      expect(() => decodeFrame(JSON.stringify({ v: 2, t: "sub", h: handle }))).toThrow(FrameError);
    });
  }

  it("rejects a handle that is not a string", () => {
    expect(() => decodeFrame(JSON.stringify({ v: 2, t: "sub", h: 42 }))).toThrow(FrameError);
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
    expect(() => decodeFrame(JSON.stringify({ v: 2, t: "shutdown" }))).toThrow(FrameError);
  });

  it("rejects the presence frame version 1 used to carry", () => {
    expect(() => decodeFrame(JSON.stringify({ v: 2, t: "presence", n: 2 }))).toThrow(FrameError);
  });

  it("decodes a frame delivered as bytes rather than a string", () => {
    const bytes = new TextEncoder().encode(encodeFrame(subFrame(HANDLE)));
    expect(decodeFrame(bytes)).toEqual({ v: 2, t: "sub", h: HANDLE });
  });
});

describe("relay-originated frames", () => {
  it("round-trips each error code, including channel_full", () => {
    for (const code of ["rate_limited", "bad_frame", "not_subscribed", "channel_full"] as const) {
      expect(decodeFrame(encodeFrame(errFrame(code)))).toEqual({ v: 2, t: "err", code });
    }
  });

  it("rejects an unknown error code", () => {
    expect(() => decodeFrame(JSON.stringify({ v: 2, t: "err", code: "teapot" }))).toThrow(
      FrameError,
    );
  });

  it("separates the frames a client may send from the one only a relay sends", () => {
    expect(isClientFrame(subFrame(HANDLE))).toBe(true);
    expect(isClientFrame(helloFrame(HANDLE, PUBLIC_KEY))).toBe(true);
    expect(isClientFrame(msgFrame(HANDLE, 0, CIPHERTEXT))).toBe(true);
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
