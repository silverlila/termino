/**
 * The outer frame: what the relay can see. Nothing here is derived from plaintext.
 *
 * Node/Bun's `Buffer.from(text, "base64")` silently drops characters outside the alphabet
 * instead of failing, so every base64 field is shape-checked before it is decoded.
 *
 * The version check runs before any other field is inspected.
 */

export const PROTOCOL_VERSION = 2;

export const MAX_FRAME_BYTES = 8192;

const PUBLIC_KEY_BYTES = 32;

const MAX_COUNTER = 0xffffffff;

const HANDLE_PATTERN = /^[0-9a-f]{32}$/;
const BASE64_PATTERN = /^[A-Za-z0-9+/]*={0,2}$/;

const ERROR_CODES = [
  "rate_limited",
  "bad_frame",
  "not_subscribed",
  "channel_full",
] as const;
export type ErrorCode = (typeof ERROR_CODES)[number];

export interface SubFrame {
  v: typeof PROTOCOL_VERSION;
  t: "sub";
  h: string;
}

export interface HelloFrame {
  v: typeof PROTOCOL_VERSION;
  t: "hello";
  h: string;
  k: string;
}

export interface MsgFrame {
  v: typeof PROTOCOL_VERSION;
  t: "msg";
  h: string;
  i: number;
  c: string;
}

export interface ErrFrame {
  v: typeof PROTOCOL_VERSION;
  t: "err";
  code: ErrorCode;
}

export type ClientFrame = SubFrame | HelloFrame | MsgFrame;
export type Frame = ClientFrame | ErrFrame;

export class FrameError extends Error {
  constructor(reason: string) {
    super(`invalid frame: ${reason}`);
  }
}

export function toBase64(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64");
}

export function fromBase64(text: string): Uint8Array {
  if (!BASE64_PATTERN.test(text)) throw new FrameError("not valid base64");
  return new Uint8Array(Buffer.from(text, "base64"));
}

export function subFrame(handle: string): SubFrame {
  return { v: PROTOCOL_VERSION, t: "sub", h: handle };
}

export function helloFrame(handle: string, publicKey: Uint8Array): HelloFrame {
  return { v: PROTOCOL_VERSION, t: "hello", h: handle, k: toBase64(publicKey) };
}

export function msgFrame(handle: string, counter: number, ciphertext: Uint8Array): MsgFrame {
  return { v: PROTOCOL_VERSION, t: "msg", h: handle, i: counter, c: toBase64(ciphertext) };
}

export function errFrame(code: ErrorCode): ErrFrame {
  return { v: PROTOCOL_VERSION, t: "err", code };
}

export function encodeFrame(frame: Frame): string {
  return JSON.stringify(frame);
}

export function isClientFrame(frame: Frame): frame is ClientFrame {
  return frame.t === "sub" || frame.t === "hello" || frame.t === "msg";
}

export function decodeFrame(raw: string | Uint8Array): Frame {
  const size = typeof raw === "string" ? Buffer.byteLength(raw, "utf8") : raw.byteLength;
  if (size > MAX_FRAME_BYTES) throw new FrameError(`larger than ${MAX_FRAME_BYTES} bytes`);

  const text = typeof raw === "string" ? raw : Buffer.from(raw).toString("utf8");

  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new FrameError("not JSON");
  }

  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    throw new FrameError("not a JSON object");
  }

  const fields = parsed as Record<string, unknown>;

  if (fields.v !== PROTOCOL_VERSION) {
    throw new FrameError(`unsupported version ${JSON.stringify(fields.v)}`);
  }

  switch (fields.t) {
    case "sub":
      return subFrame(readHandle(fields.h));
    case "hello":
      return {
        v: PROTOCOL_VERSION,
        t: "hello",
        h: readHandle(fields.h),
        k: readPublicKey(fields.k),
      };
    case "msg":
      return {
        v: PROTOCOL_VERSION,
        t: "msg",
        h: readHandle(fields.h),
        i: readCounter(fields.i),
        c: readCiphertext(fields.c),
      };
    case "err":
      return errFrame(readErrorCode(fields.code));
    default:
      throw new FrameError(`unknown type ${JSON.stringify(fields.t)}`);
  }
}

function readHandle(value: unknown): string {
  if (typeof value !== "string") throw new FrameError("handle is not a string");
  if (!HANDLE_PATTERN.test(value)) {
    throw new FrameError("handle is not 32 lowercase hex characters");
  }
  return value;
}

function readPublicKey(value: unknown): string {
  if (typeof value !== "string") throw new FrameError("public key is not a string");
  if (fromBase64(value).length !== PUBLIC_KEY_BYTES) {
    throw new FrameError(`public key is not ${PUBLIC_KEY_BYTES} bytes`);
  }
  return value;
}

function readCounter(value: unknown): number {
  if (typeof value !== "number" || !Number.isInteger(value) || value < 0 || value > MAX_COUNTER) {
    throw new FrameError(`counter is not an integer from 0 to ${MAX_COUNTER}`);
  }
  return value;
}

function readCiphertext(value: unknown): string {
  if (typeof value !== "string") throw new FrameError("ciphertext is not a string");
  if (fromBase64(value).length === 0) throw new FrameError("ciphertext is empty");
  return value;
}

function readErrorCode(value: unknown): ErrorCode {
  const known = ERROR_CODES.find((code) => code === value);
  if (known === undefined) throw new FrameError(`unknown error code ${JSON.stringify(value)}`);
  return known;
}
