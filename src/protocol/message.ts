import { ed25519 } from "@noble/curves/ed25519.js";
import { hexToBytes } from "@noble/hashes/utils.js";
import { open, seal } from "../crypto/seal.ts";
import { fromBase64, msgFrame, toBase64, type MsgFrame } from "./frame.ts";

/**
 * The inner payload: what actually gets encrypted, and what the relay never
 * sees. Signing happens *before* sealing, so the signature travels inside the
 * envelope — the relay cannot tell who wrote a message, only that one moved.
 */

const PUBLIC_KEY_PATTERN = /^[0-9a-f]{64}$/;

const utf8 = (text: string) => new TextEncoder().encode(text);

export interface Payload {
  /** The sender's Ed25519 public key, hex. Who the message claims to be from. */
  from: string;
  nick: string;
  body: string;
  /** Milliseconds since the epoch, set by the sender. Nothing trusts it. */
  ts: number;
}

export interface SignedPayload extends Payload {
  /** Base64 Ed25519 signature over `signedBytes(payload)`. */
  sig: string;
}

/** Thrown when a payload does not have the shape a payload must have. */
export class PayloadError extends Error {
  constructor(readonly reason: string) {
    super(`invalid payload: ${reason}`);
  }
}

/** Thrown when a payload is well-formed but its signature does not verify
 * against the key it claims to be from. The message is discarded. */
export class SignatureError extends Error {
  constructor() {
    super("message signature did not verify");
  }
}

/**
 * The exact bytes that are signed and verified.
 *
 * An array, not the object: JSON object key order is an implementation detail
 * of whoever built the object, so signing `JSON.stringify(payload)` would make
 * a signature that verifies on the sender's machine and fails on the
 * recipient's. Positional order here is part of the wire contract — reordering
 * these four values invalidates every signature ever produced.
 */
export function signedBytes(payload: Payload): Uint8Array {
  return utf8(JSON.stringify([payload.from, payload.nick, payload.body, payload.ts]));
}

export function sign(payload: Payload, secretKey: Uint8Array): SignedPayload {
  const signature = ed25519.sign(signedBytes(payload), secretKey);
  return { ...payload, sig: toBase64(signature) };
}

/**
 * Checks a payload against the public key it names in `from`. That proves the
 * body was not altered and that whoever sent it holds that key; whether that
 * key belongs to the person the `nick` claims is a separate question, answered
 * by the trust store.
 */
export function verify(signed: SignedPayload): boolean {
  try {
    const signature = fromBase64(signed.sig);
    const publicKey = hexToBytes(signed.from);
    return ed25519.verify(signature, signedBytes(signed), publicKey);
  } catch {
    // A malformed signature or key is a failed verification, not a crash.
    return false;
  }
}

/** Signs, then encrypts, then wraps in the outer frame — in that order. */
export async function sealMessage(input: {
  msgKey: Uint8Array;
  handle: string;
  payload: Payload;
  secretKey: Uint8Array;
}): Promise<MsgFrame> {
  const signed = sign(input.payload, input.secretKey);
  const { nonce, ciphertext } = await seal(input.msgKey, utf8(JSON.stringify(signed)));
  return msgFrame(input.handle, nonce, ciphertext);
}

/**
 * Decrypts and verifies an inbound frame. Throws `DecryptError` if the
 * ciphertext does not authenticate, `PayloadError` if it decrypts to something
 * that is not a payload, and `SignatureError` if the signature does not match
 * the key it claims. Only a fully verified payload is ever returned.
 */
export async function openMessage(msgKey: Uint8Array, frame: MsgFrame): Promise<SignedPayload> {
  const plaintext = await open(msgKey, fromBase64(frame.n), fromBase64(frame.c));
  const signed = parsePayload(new TextDecoder().decode(plaintext));

  if (!verify(signed)) throw new SignatureError();

  return signed;
}

function parsePayload(text: string): SignedPayload {
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new PayloadError("not JSON");
  }

  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    throw new PayloadError("not a JSON object");
  }

  const fields = parsed as Record<string, unknown>;

  return {
    from: readPublicKey(fields.from),
    nick: readText(fields.nick, "nick"),
    body: readText(fields.body, "body"),
    ts: readTimestamp(fields.ts),
    sig: readText(fields.sig, "sig"),
  };
}

function readPublicKey(value: unknown): string {
  if (typeof value !== "string" || !PUBLIC_KEY_PATTERN.test(value)) {
    throw new PayloadError("from is not a 64-character hex public key");
  }
  return value;
}

function readText(value: unknown, field: string): string {
  if (typeof value !== "string") throw new PayloadError(`${field} is not a string`);
  return value;
}

function readTimestamp(value: unknown): number {
  if (typeof value !== "number" || !Number.isInteger(value)) {
    throw new PayloadError("ts is not an integer");
  }
  return value;
}
