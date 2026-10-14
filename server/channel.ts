/**
 * The rules for one channel, shared by both relays: the Bun server in relay.ts and the
 * Cloudflare Durable Object in cloudflare/worker.ts. Pure — each relay owns its sockets
 * and acts on the decision this returns.
 *
 * A connection is pinned to one handle by the path it dialled, `/<handle>`, because a
 * Durable Object has to be chosen before any frame arrives. Every frame it sends must
 * then name that handle: the relay routes on the handle the connection subscribed to,
 * never the handle inside the frame, and a mismatch is answered `bad_frame`.
 *
 * Every frame costs a token, malformed or not: a frame the relay has to read is work
 * whatever it turns out to say, and on Cloudflare it is billed. A sender over budget is
 * told once per stretch of being over it, not once per frame, so the relay cannot be
 * made to answer a flood with a flood.
 */

import {
  decodeFrame,
  FrameError,
  isClientFrame,
  isHandle,
  type ClientFrame,
  type ErrorCode,
} from "../shared/protocol/frame.ts";

export const RATE_LIMIT_MESSAGES = 5;
export const RATE_LIMIT_WINDOW_MS = 10_000;

export const MAX_SUBSCRIBERS_PER_HANDLE = 2;

export const IDLE_TIMEOUT_SECONDS = 120;

const TOKENS_PER_MS = RATE_LIMIT_MESSAGES / RATE_LIMIT_WINDOW_MS;

export interface TokenBucket {
  tokens: number;
  updatedAt: number;
}

export interface Member {
  handle: string;
  subscribed: boolean;
  bucket: TokenBucket;
  limited: boolean;
}

export type Action =
  | { kind: "reject"; code: ErrorCode }
  | { kind: "subscribe" }
  | { kind: "forward" }
  | { kind: "nothing" };

export type Admission = { ok: true; handle: string } | { ok: false; reason: string };

export function fullBucket(now: number): TokenBucket {
  return { tokens: RATE_LIMIT_MESSAGES, updatedAt: now };
}

export function takeToken(bucket: TokenBucket, now: number): { bucket: TokenBucket; allowed: boolean } {
  const elapsed = Math.max(0, now - bucket.updatedAt);
  const refilled = Math.min(RATE_LIMIT_MESSAGES, bucket.tokens + elapsed * TOKENS_PER_MS);

  if (refilled < 1) return { bucket: { tokens: refilled, updatedAt: now }, allowed: false };

  return { bucket: { tokens: refilled - 1, updatedAt: now }, allowed: true };
}

export function newMember(handle: string, now: number): Member {
  return { handle, subscribed: false, bucket: fullBucket(now), limited: false };
}

// Browsers attach an Origin header to a WebSocket handshake; the CLI never does.
export function admit(url: URL, headers: Headers): Admission {
  const handle = url.pathname.slice(1);
  if (!isHandle(handle) || url.search !== "") return { ok: false, reason: "only /<handle> is served" };

  if (headers.has("origin")) return { ok: false, reason: "no browser clients" };

  return { ok: true, handle };
}

export function route(
  member: Member,
  raw: string | Uint8Array,
  subscribers: number,
  now: number,
): { member: Member; action: Action } {
  const limit = takeToken(member.bucket, now);
  if (!limit.allowed) {
    const action: Action = member.limited ? { kind: "nothing" } : reject("rate_limited");
    return { member: { ...member, bucket: limit.bucket, limited: true }, action };
  }

  const charged = { ...member, bucket: limit.bucket, limited: false };

  const frame = parse(raw);
  if (frame === null) return { member: charged, action: reject("bad_frame") };

  if (frame.h !== member.handle) return { member: charged, action: reject("bad_frame") };

  if (frame.t === "sub") {
    if (member.subscribed) return { member: charged, action: { kind: "nothing" } };
    if (subscribers >= MAX_SUBSCRIBERS_PER_HANDLE) {
      return { member: charged, action: reject("channel_full") };
    }
    return { member: { ...charged, subscribed: true }, action: { kind: "subscribe" } };
  }

  if (!member.subscribed) return { member: charged, action: reject("not_subscribed") };

  return { member: charged, action: { kind: "forward" } };
}

function parse(raw: string | Uint8Array): ClientFrame | null {
  try {
    const frame = decodeFrame(raw);
    return isClientFrame(frame) ? frame : null;
  } catch (error) {
    if (error instanceof FrameError) return null;
    throw error;
  }
}

function reject(code: ErrorCode): Action {
  return { kind: "reject", code };
}
