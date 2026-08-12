import {
  decodeFrame,
  encodeFrame,
  errFrame,
  FrameError,
  isClientFrame,
  presenceFrame,
  type ErrorCode,
  type MsgFrame,
  type SubFrame,
} from "../shared/protocol/frame.ts";

/**
 * The relay. It learns a handle and forwards an opaque blob to everyone else
 * carrying the same handle. That is the whole job.
 *
 * This file imports `protocol/frame.ts` and nothing else from the application.
 * It has no access to a key and no way to obtain one, so "the relay cannot
 * read your messages" is a property of the import graph rather than a promise
 * — `bun run check:relay-pure` fails the build if that ever stops being true.
 */

export const DEFAULT_PORT = 8787;

/** Five frames per ten seconds, keyed on the connection. Never on anything
 * the client supplies: the previous implementation keyed on a username the
 * client could change at will, which made the limit decorative. */
export const RATE_LIMIT_MESSAGES = 5;
export const RATE_LIMIT_WINDOW_MS = 10_000;

const TOKENS_PER_MS = RATE_LIMIT_MESSAGES / RATE_LIMIT_WINDOW_MS;

export interface TokenBucket {
  tokens: number;
  updatedAt: number;
}

export function fullBucket(now: number): TokenBucket {
  return { tokens: RATE_LIMIT_MESSAGES, updatedAt: now };
}

/**
 * Pure: takes a bucket and a timestamp, returns the next bucket and whether
 * the message may pass. Kept free of any socket so the limiter can be tested
 * as arithmetic rather than through a live connection.
 */
export function takeToken(bucket: TokenBucket, now: number): { bucket: TokenBucket; allowed: boolean } {
  const elapsed = Math.max(0, now - bucket.updatedAt);
  const refilled = Math.min(RATE_LIMIT_MESSAGES, bucket.tokens + elapsed * TOKENS_PER_MS);

  if (refilled < 1) return { bucket: { tokens: refilled, updatedAt: now }, allowed: false };

  return { bucket: { tokens: refilled - 1, updatedAt: now }, allowed: true };
}

interface Connection {
  /** The handle this connection subscribed to, or null before its first
   * `sub`. Messages are routed by this rather than by the handle in each
   * frame, so a connection can only ever speak into the channel it joined. */
  handle: string | null;
  bucket: TokenBucket;
}

export interface RelayOptions {
  port?: number;
  /** Injectable so tests can advance past the rate-limit window instead of
   * sleeping ten real seconds, which would exceed Bun's per-test timeout. */
  now?: () => number;
}

export function startRelay(options: RelayOptions = {}) {
  const now = options.now ?? Date.now;

  const server = Bun.serve<Connection, {}>({
    port: options.port ?? DEFAULT_PORT,

    fetch(request, server) {
      const connection: Connection = { handle: null, bucket: fullBucket(now()) };
      if (server.upgrade(request, { data: connection })) return undefined;

      return new Response("termino relay: websocket only\n", { status: 426 });
    },

    websocket: {
      message(ws, raw) {
        const frame = parse(raw);

        if (frame === null) return reject(ws, "bad_frame");

        // Every frame the relay acts on costs a token, not just `msg`. A `sub`
        // is cheap to send and expensive to serve: each accepted one announces
        // presence to both the handle being left and the one being joined, so
        // charging only `msg` left a client free to toggle between two handles
        // and turn a small frame into a fan-out across every other member.
        const limit = takeToken(ws.data.bucket, now());
        ws.data.bucket = limit.bucket;
        if (!limit.allowed) return reject(ws, "rate_limited");

        if (frame.t === "sub") return subscribe(ws, frame);
        return forward(ws, frame, raw);
      },

      close(ws) {
        // Bun has already removed this socket from the topic by the time close
        // runs, so the count is the post-departure one the survivors want.
        announcePresence(ws.data.handle);
      },
    },
  });

  function parse(raw: string | Buffer): SubFrame | MsgFrame | null {
    try {
      const frame = decodeFrame(raw);
      // `presence` and `err` are frames the relay originates. A client sending
      // one is confused or probing; either way it is not something to act on.
      return isClientFrame(frame) ? frame : null;
    } catch (error) {
      if (error instanceof FrameError) return null;
      throw error;
    }
  }

  function subscribe(ws: Bun.ServerWebSocket<Connection>, frame: SubFrame): void {
    const previous = ws.data.handle;
    if (previous === frame.h) return;

    if (previous !== null) {
      ws.unsubscribe(previous);
      announcePresence(previous);
    }

    ws.data.handle = frame.h;
    ws.subscribe(frame.h);
    announcePresence(frame.h);
  }

  function forward(ws: Bun.ServerWebSocket<Connection>, frame: MsgFrame, raw: string | Buffer): void {
    const handle = ws.data.handle;
    if (handle === null) return reject(ws, "not_subscribed");
    if (frame.h !== handle) return reject(ws, "bad_frame");

    // The raw bytes go out untouched. Re-encoding would work today and would
    // silently start rewriting ciphertext the moment the frame type gains a
    // field this version does not know about.
    ws.publish(handle, raw);
  }

  /** Errors go to one connection. They are never published to a handle: an
   * error is about a sender's frame, not about the channel. */
  function reject(ws: Bun.ServerWebSocket<Connection>, code: ErrorCode): void {
    ws.send(encodeFrame(errFrame(code)));
  }

  function announcePresence(handle: string | null): void {
    if (handle === null) return;
    server.publish(handle, encodeFrame(presenceFrame(server.subscriberCount(handle))));
  }

  return server;
}
