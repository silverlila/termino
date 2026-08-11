/**
 * The outer frame: everything the relay is allowed to see. A handle to route
 * on, and an opaque blob to forward.
 *
 * This module must never import from `src/crypto/`. The relay imports it, and
 * "the relay cannot decrypt" is meant to be a structural fact rather than a
 * promise — `bun run check:relay-pure` enforces the server half of that, and
 * this comment is the client half.
 */

/** Bumped only for a breaking change. Unknown versions are rejected, not ignored. */
export const PROTOCOL_VERSION = 1;

/** A frame larger than this is dropped before it is parsed. Bodies are short;
 * anything approaching this size is an amplification attempt. */
export const MAX_FRAME_BYTES = 64 * 1024;

/** Duplicated from `crypto/seal.ts` rather than imported, because this module
 * may not depend on crypto. The two must agree. */
const NONCE_BYTES = 12;

const HANDLE_PATTERN = /^[0-9a-f]{32}$/;
const BASE64_PATTERN = /^[A-Za-z0-9+/]*={0,2}$/;

export const ERROR_CODES = ["rate_limited", "bad_frame", "not_subscribed"] as const;
export type ErrorCode = (typeof ERROR_CODES)[number];

/** Client → relay, the first frame on a connection. */
export interface SubFrame {
  v: typeof PROTOCOL_VERSION;
  t: "sub";
  h: string;
}

/** Client → relay → every other subscriber to the same handle. */
export interface MsgFrame {
  v: typeof PROTOCOL_VERSION;
  t: "msg";
  /** Handle: 32 lowercase hex characters. */
  h: string;
  /** Base64 12-byte nonce. */
  n: string;
  /** Base64 AES-GCM ciphertext. The relay forwards this byte for byte. */
  c: string;
}

/** Relay → client. `n` counts the connections subscribed to the handle,
 * including the recipient. */
export interface PresenceFrame {
  v: typeof PROTOCOL_VERSION;
  t: "presence";
  n: number;
}

/** Relay → one client. Never broadcast. */
export interface ErrFrame {
  v: typeof PROTOCOL_VERSION;
  t: "err";
  code: ErrorCode;
}

/** The two frames a client may send. */
export type ClientFrame = SubFrame | MsgFrame;
/** The two frames the relay originates. Neither carries anything derived from
 * ciphertext. */
export type RelayFrame = PresenceFrame | ErrFrame;
export type Frame = ClientFrame | RelayFrame;

/**
 * Thrown by `decodeFrame`. The relay catches this and answers `bad_frame`
 * rather than closing the connection: one malformed frame is a bug or a probe,
 * not a reason to disconnect somebody mid-conversation.
 */
export class FrameError extends Error {
  constructor(readonly reason: string) {
    super(`invalid frame: ${reason}`);
  }
}

export function toBase64(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64");
}

/**
 * `Buffer.from(text, "base64")` silently discards characters outside the
 * alphabet, so a corrupt nonce would decode to a plausible-looking short one.
 * The shape is checked first so corruption fails here instead of surfacing as
 * a decryption error later.
 */
export function fromBase64(text: string): Uint8Array {
  if (!BASE64_PATTERN.test(text)) throw new FrameError("not valid base64");
  return new Uint8Array(Buffer.from(text, "base64"));
}

export function subFrame(handle: string): SubFrame {
  return { v: PROTOCOL_VERSION, t: "sub", h: handle };
}

export function msgFrame(handle: string, nonce: Uint8Array, ciphertext: Uint8Array): MsgFrame {
  return {
    v: PROTOCOL_VERSION,
    t: "msg",
    h: handle,
    n: toBase64(nonce),
    c: toBase64(ciphertext),
  };
}

export function presenceFrame(subscriberCount: number): PresenceFrame {
  return { v: PROTOCOL_VERSION, t: "presence", n: subscriberCount };
}

export function errFrame(code: ErrorCode): ErrFrame {
  return { v: PROTOCOL_VERSION, t: "err", code };
}

export function encodeFrame(frame: Frame): string {
  return JSON.stringify(frame);
}

/** True for the two frames a relay accepts. The relay drops `presence` and
 * `err` arriving from a client: it originates those, it never receives them. */
export function isClientFrame(frame: Frame): frame is ClientFrame {
  return frame.t === "sub" || frame.t === "msg";
}

/**
 * Parses and fully validates one frame off the wire. Throws `FrameError` on
 * anything malformed; a returned frame is safe for the caller to use without
 * further checking.
 */
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

  // Checked before anything else about the body, so that a future version can
  // change every other field freely.
  if (fields.v !== PROTOCOL_VERSION) {
    throw new FrameError(`unsupported version ${JSON.stringify(fields.v)}`);
  }

  switch (fields.t) {
    case "sub":
      return subFrame(readHandle(fields.h));
    case "msg":
      return {
        v: PROTOCOL_VERSION,
        t: "msg",
        h: readHandle(fields.h),
        n: readNonce(fields.n),
        c: readCiphertext(fields.c),
      };
    case "presence":
      return presenceFrame(readSubscriberCount(fields.n));
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

function readNonce(value: unknown): string {
  if (typeof value !== "string") throw new FrameError("nonce is not a string");
  if (fromBase64(value).length !== NONCE_BYTES) {
    throw new FrameError(`nonce is not ${NONCE_BYTES} bytes`);
  }
  return value;
}

function readCiphertext(value: unknown): string {
  if (typeof value !== "string") throw new FrameError("ciphertext is not a string");
  if (fromBase64(value).length === 0) throw new FrameError("ciphertext is empty");
  return value;
}

function readSubscriberCount(value: unknown): number {
  if (typeof value !== "number" || !Number.isInteger(value) || value < 0) {
    throw new FrameError("presence count is not a non-negative integer");
  }
  return value;
}

function readErrorCode(value: unknown): ErrorCode {
  const known = ERROR_CODES.find((code) => code === value);
  if (known === undefined) throw new FrameError(`unknown error code ${JSON.stringify(value)}`);
  return known;
}
