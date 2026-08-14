import { describe, expect, it } from "bun:test";
import { BUCKETS, pad, PaddingError } from "../../../shared/crypto/pad.ts";
import type { MessageKey } from "../../../shared/crypto/ratchet.ts";
import { DecryptError, seal } from "../../../shared/crypto/seal.ts";
import { fromBase64, msgFrame } from "../../../shared/protocol/frame.ts";
import { MAX_BODY_BYTES } from "../../../shared/protocol/text.ts";
import {
  openMessage,
  payloadProblem,
  PayloadError,
  sealMessage,
  type Payload,
} from "../../../shared/protocol/message.ts";

/**
 * The inner payload: the part the relay never sees. Everything here is about
 * shape and rules — that a `text`, a `ping` and a `confirm` survive the round
 * trip, that nothing else does, and that a hostile body cannot get through in
 * either direction.
 */

const HANDLE = "63402012e8d78d978a4ab491cf2e5ae9";

const KEY: MessageKey = {
  key: new Uint8Array(32).fill(11),
  nonce: Uint8Array.from({ length: 12 }, (_, index) => index),
};

const OTHER_KEY: MessageKey = {
  key: new Uint8Array(32).fill(22),
  nonce: KEY.nonce,
};

const utf8 = (text: string) => new TextEncoder().encode(text);

/** Written as escapes rather than the raw bytes: a literal ESC or zero-width
 * space in a source file is invisible to every reader and one careless copy
 * away from being lost. */
const ESC = "\u001B";
const ZERO_WIDTH_SPACE = "\u200B";

const TEXT: Payload = { t: "text", nick: "alice", body: "shipping it now" };

/** A frame built without going through `sealMessage`, so the cases below can
 * put on the wire what an honest client refuses to send. */
async function frameOf(value: unknown, key = KEY) {
  const ciphertext = await seal(key.key, key.nonce, pad(utf8(JSON.stringify(value))));
  return msgFrame(HANDLE, 0, ciphertext);
}

describe("the three payload types", () => {
  it("round-trips a text payload", async () => {
    expect(await openMessage(KEY, await sealMessage(KEY, HANDLE, 0, TEXT))).toEqual(TEXT);
  });

  it("round-trips a ping payload", async () => {
    const ping: Payload = { t: "ping", nick: "alice" };

    expect(await openMessage(KEY, await sealMessage(KEY, HANDLE, 3, ping))).toEqual(ping);
  });

  it("round-trips a confirm payload", async () => {
    const confirm: Payload = { t: "confirm", nick: "alice" };

    expect(await openMessage(KEY, await sealMessage(KEY, HANDLE, 0, confirm))).toEqual(confirm);
  });

  it("puts the counter it was given on the frame", async () => {
    expect((await sealMessage(KEY, HANDLE, 42, TEXT)).i).toBe(42);
  });
});

describe("a payload type that is not one of the three", () => {
  it("is rejected rather than ignored", async () => {
    const frame = await frameOf({ t: "shutdown", nick: "alice" });

    await expect(openMessage(KEY, frame)).rejects.toBeInstanceOf(PayloadError);
    await expect(openMessage(KEY, frame)).rejects.toThrow(/unknown payload type/);
  });

  it("is rejected when the type is missing entirely", async () => {
    await expect(openMessage(KEY, await frameOf({ nick: "alice", body: "hi" }))).rejects.toThrow(
      PayloadError,
    );
  });
});

describe("the fields version 1 carried", () => {
  it("no longer parses a signed v1 payload at all, because it has no type", async () => {
    const v1 = {
      from: "00".repeat(32),
      nick: "alice",
      body: "shipping it now",
      ts: 1786531200000,
      sig: "A".repeat(88),
    };

    await expect(openMessage(KEY, await frameOf(v1))).rejects.toBeInstanceOf(PayloadError);
  });

  it("drops a from and a ts that arrive alongside a valid payload", async () => {
    const frame = await frameOf({ ...TEXT, from: "00".repeat(32), ts: 1786531200000 });

    // Rebuilt field by field on the way in, so nothing the sender invented
    // travels on as if this layer had checked it.
    expect(await openMessage(KEY, frame)).toEqual(TEXT);
  });

  it("does not put a ts on what it sends", async () => {
    const opened = await openMessage(KEY, await sealMessage(KEY, HANDLE, 0, TEXT));

    expect(Object.keys(opened).sort()).toEqual(["body", "nick", "t"]);
  });
});

describe("what cannot be sent", () => {
  it("refuses a body carrying a control character", () => {
    const problem = payloadProblem({ t: "text", nick: "alice", body: `hi${ESC}[2J` });

    expect(problem).toContain("U+001B");
  });

  it("refuses a nickname carrying a control character", () => {
    expect(payloadProblem({ t: "ping", nick: `al${ESC}ice` })).toContain("U+001B");
  });

  it("refuses an over-long body", () => {
    const problem = payloadProblem({ t: "text", nick: "alice", body: "a".repeat(MAX_BODY_BYTES + 1) });

    expect(problem).toContain("over the limit");
  });

  it("accepts an ordinary text payload", () => {
    expect(payloadProblem(TEXT)).toBeNull();
  });

  it("throws rather than sealing a payload it would refuse", async () => {
    const hostile: Payload = { t: "text", nick: "alice", body: `hi${ESC}]52;c;cGF3bmVk` };

    await expect(sealMessage(KEY, HANDLE, 0, hostile)).rejects.toBeInstanceOf(PayloadError);
  });
});

describe("what cannot be received", () => {
  it("refuses a body carrying a control character, however it was sealed", async () => {
    const frame = await frameOf({ t: "text", nick: "bob", body: "ok\n00:00 alice  forged" });

    await expect(openMessage(KEY, frame)).rejects.toBeInstanceOf(PayloadError);
  });

  it("refuses a nickname carrying a zero-width character", async () => {
    const frame = await frameOf({ t: "text", nick: `al${ZERO_WIDTH_SPACE}ice`, body: "hi" });

    await expect(openMessage(KEY, frame)).rejects.toBeInstanceOf(PayloadError);
  });

  it("refuses a body on a payload that has no business carrying one", async () => {
    const frame = await frameOf({ t: "ping", nick: "alice", body: "smuggled" });

    await expect(openMessage(KEY, frame)).rejects.toThrow(/carries no body/);
  });

  it("refuses a text payload with no body", async () => {
    await expect(openMessage(KEY, await frameOf({ t: "text", nick: "alice" }))).rejects.toThrow(
      PayloadError,
    );
  });

  it("refuses something that is not JSON at all", async () => {
    const ciphertext = await seal(KEY.key, KEY.nonce, pad(utf8("not json")));

    await expect(openMessage(KEY, msgFrame(HANDLE, 0, ciphertext))).rejects.toThrow(PayloadError);
  });

  it("refuses a plaintext that was never padded", async () => {
    const ciphertext = await seal(KEY.key, KEY.nonce, utf8(JSON.stringify(TEXT)));

    await expect(openMessage(KEY, msgFrame(HANDLE, 0, ciphertext))).rejects.toBeInstanceOf(
      PaddingError,
    );
  });

  it("refuses a frame sealed under another key", async () => {
    await expect(openMessage(KEY, await frameOf(TEXT, OTHER_KEY))).rejects.toBeInstanceOf(
      DecryptError,
    );
  });
});

describe("padding", () => {
  it("hides the length of what was said", async () => {
    const short = await sealMessage(KEY, HANDLE, 0, TEXT);
    const long = await sealMessage(KEY, HANDLE, 0, {
      t: "text",
      nick: "alice",
      body: "a".repeat(120),
    });

    expect(fromBase64(short.c).length).toBe(fromBase64(long.c).length);
  });

  it("seals a bucket-sized plaintext, so the relay reads one of five lengths", async () => {
    const sealed = await sealMessage(KEY, HANDLE, 0, TEXT);
    const tagBytes = 16;

    expect(BUCKETS).toContain(fromBase64(sealed.c).length - tagBytes);
  });
});
