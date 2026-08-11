import { describe, expect, it } from "bun:test";
import { ed25519 } from "@noble/curves/ed25519.js";
import { bytesToHex } from "@noble/hashes/utils.js";
import { DecryptError, open, seal } from "../../src/crypto/seal.ts";
import { fromBase64, msgFrame } from "../../src/protocol/frame.ts";
import {
  openMessage,
  PayloadError,
  sealMessage,
  sign,
  signedBytes,
  SignatureError,
  verify,
  type Payload,
  type SignedPayload,
} from "../../src/protocol/message.ts";

const HANDLE = "63402012e8d78d978a4ab491cf2e5ae9";
const MSG_KEY = new Uint8Array(32).fill(11);
const OTHER_MSG_KEY = new Uint8Array(32).fill(22);

const SECRET_KEY = Uint8Array.from({ length: 32 }, (_, index) => index + 1);
const PUBLIC_KEY_HEX = bytesToHex(ed25519.getPublicKey(SECRET_KEY));

const OTHER_SECRET_KEY = Uint8Array.from({ length: 32 }, (_, index) => 200 - index);

function payloadFrom(overrides: Partial<Payload> = {}): Payload {
  return {
    from: PUBLIC_KEY_HEX,
    nick: "alice",
    body: "shipping it now",
    ts: 1786531200000,
    ...overrides,
  };
}

describe("signed bytes", () => {
  // Written out by hand rather than derived from the payload, so this test can
  // disagree with the implementation instead of restating it. Changing this
  // string invalidates every signature Termino has ever produced.
  const FIXED_PAYLOAD: Payload = {
    from: "0123456789abcdef".repeat(4),
    nick: "alice",
    body: "shipping it now",
    ts: 1786531200000,
  };
  const EXPECTED_JSON =
    '["0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",' +
    '"alice","shipping it now",1786531200000]';

  it("signs the array form recorded in the wire format", () => {
    expect(new TextDecoder().decode(signedBytes(FIXED_PAYLOAD))).toBe(EXPECTED_JSON);
  });

  it("matches the serialization named in the spec", () => {
    const { from, nick, body, ts } = FIXED_PAYLOAD;
    expect(signedBytes(FIXED_PAYLOAD)).toEqual(
      new TextEncoder().encode(JSON.stringify([from, nick, body, ts])),
    );
  });

  it("does not depend on the key order of the payload object", () => {
    const reordered: Payload = {
      ts: FIXED_PAYLOAD.ts,
      body: FIXED_PAYLOAD.body,
      nick: FIXED_PAYLOAD.nick,
      from: FIXED_PAYLOAD.from,
    };
    expect(signedBytes(reordered)).toEqual(signedBytes(FIXED_PAYLOAD));
  });
});

describe("signing and verifying", () => {
  it("verifies a payload it just signed", () => {
    expect(verify(sign(payloadFrom(), SECRET_KEY))).toBe(true);
  });

  it("rejects a payload whose body was modified after signing", () => {
    const signed = sign(payloadFrom(), SECRET_KEY);
    const tampered: SignedPayload = { ...signed, body: "cancel the deploy" };

    expect(verify(tampered)).toBe(false);
  });

  it("rejects a payload whose nick was modified after signing", () => {
    const signed = sign(payloadFrom(), SECRET_KEY);
    expect(verify({ ...signed, nick: "bob" })).toBe(false);
  });

  it("rejects a payload whose timestamp was modified after signing", () => {
    const signed = sign(payloadFrom(), SECRET_KEY);
    expect(verify({ ...signed, ts: signed.ts + 1 })).toBe(false);
  });

  it("rejects a signature made by a different key than the one claimed", () => {
    const impostor = sign(payloadFrom(), OTHER_SECRET_KEY);
    // `from` still names the honest key, so this is an impersonation attempt.
    expect(verify(impostor)).toBe(false);
  });

  it("still verifies when the payload object is rebuilt in a different key order", () => {
    const signed = sign(payloadFrom(), SECRET_KEY);
    const reordered: SignedPayload = {
      sig: signed.sig,
      ts: signed.ts,
      body: signed.body,
      nick: signed.nick,
      from: signed.from,
    };

    expect(verify(reordered)).toBe(true);
  });

  it("treats a malformed signature as unverified rather than throwing", () => {
    const signed = sign(payloadFrom(), SECRET_KEY);
    expect(verify({ ...signed, sig: "!!!not base64!!!" })).toBe(false);
    expect(verify({ ...signed, sig: "" })).toBe(false);
  });
});

describe("sealing and opening", () => {
  it("round-trips a message through the wire format", async () => {
    const frame = await sealMessage({
      msgKey: MSG_KEY,
      handle: HANDLE,
      payload: payloadFrom(),
      secretKey: SECRET_KEY,
    });

    const opened = await openMessage(MSG_KEY, frame);

    expect(opened.body).toBe("shipping it now");
    expect(opened.nick).toBe("alice");
    expect(opened.from).toBe(PUBLIC_KEY_HEX);
  });

  it("fails to open with the wrong channel key", async () => {
    const frame = await sealMessage({
      msgKey: MSG_KEY,
      handle: HANDLE,
      payload: payloadFrom(),
      secretKey: SECRET_KEY,
    });

    await expect(openMessage(OTHER_MSG_KEY, frame)).rejects.toBeInstanceOf(DecryptError);
  });

  it("rejects a message signed by a key other than the one it claims", async () => {
    // Someone inside the channel — they hold msgKey — forging a message from
    // alice. The channel password authenticates nobody; the device key does.
    const forged = await sealMessage({
      msgKey: MSG_KEY,
      handle: HANDLE,
      payload: payloadFrom({ nick: "alice" }),
      secretKey: OTHER_SECRET_KEY,
    });

    await expect(openMessage(MSG_KEY, forged)).rejects.toBeInstanceOf(SignatureError);
  });

  it("rejects ciphertext that decrypts to something that is not a payload", async () => {
    const junk = new TextEncoder().encode(JSON.stringify({ hello: "world" }));
    const { nonce, ciphertext } = await seal(MSG_KEY, junk);

    await expect(openMessage(MSG_KEY, msgFrame(HANDLE, nonce, ciphertext))).rejects.toBeInstanceOf(
      PayloadError,
    );
  });
});

describe("sign-before-encrypt ordering", () => {
  it("keeps the signature inside the envelope, invisible to the relay", async () => {
    const frame = await sealMessage({
      msgKey: MSG_KEY,
      handle: HANDLE,
      payload: payloadFrom(),
      secretKey: SECRET_KEY,
    });

    // What the relay sees: a routing label and an opaque blob. No signature,
    // no nickname, no public key.
    expect(Object.keys(frame).sort()).toEqual(["c", "h", "n", "t", "v"]);
    expect(frame).not.toHaveProperty("sig");
    expect(JSON.stringify(frame)).not.toContain(PUBLIC_KEY_HEX);
    expect(JSON.stringify(frame)).not.toContain("alice");

    // What is actually inside it: the signature, sealed along with everything
    // it covers. This is what makes the ordering a demonstrated fact.
    const plaintext = await open(MSG_KEY, fromBase64(frame.n), fromBase64(frame.c));
    const inner = JSON.parse(new TextDecoder().decode(plaintext));

    expect(inner).toHaveProperty("sig");
    expect(inner.from).toBe(PUBLIC_KEY_HEX);
    expect(inner.nick).toBe("alice");
  });

  it("produces a different frame each time the same message is sealed", async () => {
    const input = {
      msgKey: MSG_KEY,
      handle: HANDLE,
      payload: payloadFrom(),
      secretKey: SECRET_KEY,
    };
    const first = await sealMessage(input);
    const second = await sealMessage(input);

    expect(first.n).not.toBe(second.n);
    expect(first.c).not.toBe(second.c);
  });
});
