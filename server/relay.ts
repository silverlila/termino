/**
 * The relay: routes frames between two clients by handle, rate-limits, and caps
 * connections. It holds no key and can decrypt nothing.
 *
 * Bun specifics this file is shaped around: an exception escaping a fetch or socket
 * handler is printed with a stack trace, and the frame, handle and sender address are
 * in scope when it is — which is why failures here report nothing about whom. `fetch`
 * returning undefined means "the upgrade handshake was the response"; every other path
 * must return a Response. `websocket.idleTimeout` is in seconds, defaults to 120 and is
 * capped at 960.
 *
 * Browsers attach an Origin header to a WebSocket handshake; the CLI never does.
 *
 * `onError` takes no arguments by design: the relay may report that something failed,
 * never anything about who it happened to.
 */

import {
  decodeFrame,
  encodeFrame,
  errFrame,
  FrameError,
  isClientFrame,
  type ClientFrame,
  type ErrorCode,
  type SubFrame,
} from "../shared/protocol/frame.ts";

const DEFAULT_PORT = 8787;

export const RATE_LIMIT_MESSAGES = 5;
export const RATE_LIMIT_WINDOW_MS = 10_000;

const MAX_CONNECTIONS = 1000;
const MAX_CONNECTIONS_PER_IP = 10;

export const MAX_SUBSCRIBERS_PER_HANDLE = 2;

export const IDLE_TIMEOUT_SECONDS = 120;

const UNKNOWN_SOURCE = "unknown";

const TOKENS_PER_MS = RATE_LIMIT_MESSAGES / RATE_LIMIT_WINDOW_MS;

export interface TokenBucket {
  tokens: number;
  updatedAt: number;
}

export function fullBucket(now: number): TokenBucket {
  return { tokens: RATE_LIMIT_MESSAGES, updatedAt: now };
}

export function takeToken(bucket: TokenBucket, now: number): { bucket: TokenBucket; allowed: boolean } {
  const elapsed = Math.max(0, now - bucket.updatedAt);
  const refilled = Math.min(RATE_LIMIT_MESSAGES, bucket.tokens + elapsed * TOKENS_PER_MS);

  if (refilled < 1) return { bucket: { tokens: refilled, updatedAt: now }, allowed: false };

  return { bucket: { tokens: refilled - 1, updatedAt: now }, allowed: true };
}

interface Connection {
  handle: string | null;
  source: string;
  bucket: TokenBucket;
}

export interface RelayOptions {
  port?: number;
  now?: () => number;
  maxConnections?: number;
  maxConnectionsPerIp?: number;
  onError?: () => void;
}

export function startRelay(options: RelayOptions = {}) {
  const now = options.now ?? Date.now;
  const onError = options.onError ?? (() => {});
  const maxConnections = options.maxConnections ?? MAX_CONNECTIONS;
  const maxConnectionsPerIp = options.maxConnectionsPerIp ?? MAX_CONNECTIONS_PER_IP;

  let openConnections = 0;
  const openPerSource = new Map<string, number>();

  const server = Bun.serve<Connection, {}>({
    port: options.port ?? DEFAULT_PORT,

    fetch(request) {
      try {
        return admitRequest(request);
      } catch {
        attempt(onError);
        return refuse("request refused");
      }
    },

    websocket: {
      idleTimeout: IDLE_TIMEOUT_SECONDS,

      message(ws, raw) {
        try {
          route(ws, raw);
        } catch {
          attempt(() => reject(ws, "bad_frame"));
          attempt(onError);
        }
      },

      close(ws) {
        release(ws.data.source);
      },
    },
  });

  function attempt(work: () => void): void {
    try {
      work();
    } catch {}
  }

  function admitRequest(request: Request): Response | undefined {
    if (new URL(request.url).pathname !== "/") return refuse("only / is served");

    if (request.headers.has("origin")) return refuse("no browser clients");

    const source = server.requestIP(request)?.address ?? UNKNOWN_SOURCE;
    if (openConnections >= maxConnections) return refuse("too many connections");
    if ((openPerSource.get(source) ?? 0) >= maxConnectionsPerIp) {
      return refuse("too many connections from this address");
    }

    const connection: Connection = { handle: null, source, bucket: fullBucket(now()) };

    admit(source);
    let upgraded = false;
    try {
      upgraded = server.upgrade(request, { data: connection });
    } finally {
      if (!upgraded) release(source);
    }

    if (upgraded) return undefined;
    return new Response("termino relay: websocket only\n", { status: 426 });
  }

  function refuse(reason: string): Response {
    return new Response(`termino relay: ${reason}\n`, { status: 429 });
  }

  function admit(source: string): void {
    openConnections += 1;
    openPerSource.set(source, (openPerSource.get(source) ?? 0) + 1);
  }

  function release(source: string): void {
    openConnections -= 1;

    const remaining = (openPerSource.get(source) ?? 1) - 1;
    if (remaining > 0) openPerSource.set(source, remaining);
    else openPerSource.delete(source);
  }

  function route(ws: Bun.ServerWebSocket<Connection>, raw: string | Buffer): void {
    const frame = parse(raw);

    if (frame === null) return reject(ws, "bad_frame");

    const limit = takeToken(ws.data.bucket, now());
    ws.data.bucket = limit.bucket;
    if (!limit.allowed) return reject(ws, "rate_limited");

    if (frame.t === "sub") return subscribe(ws, frame);
    return forward(ws, frame, raw);
  }

  function parse(raw: string | Buffer): ClientFrame | null {
    try {
      const frame = decodeFrame(raw);
      return isClientFrame(frame) ? frame : null;
    } catch (error) {
      if (error instanceof FrameError) return null;
      throw error;
    }
  }

  function subscribe(ws: Bun.ServerWebSocket<Connection>, frame: SubFrame): void {
    const previous = ws.data.handle;
    if (previous === frame.h) return;

    if (server.subscriberCount(frame.h) >= MAX_SUBSCRIBERS_PER_HANDLE) {
      return reject(ws, "channel_full");
    }

    if (previous !== null) ws.unsubscribe(previous);

    ws.data.handle = frame.h;
    ws.subscribe(frame.h);
  }

  function forward(
    ws: Bun.ServerWebSocket<Connection>,
    frame: ClientFrame,
    raw: string | Buffer,
  ): void {
    const handle = ws.data.handle;
    if (handle === null) return reject(ws, "not_subscribed");
    if (frame.h !== handle) return reject(ws, "bad_frame");

    ws.publish(handle, raw);
  }

  function reject(ws: Bun.ServerWebSocket<Connection>, code: ErrorCode): void {
    ws.send(encodeFrame(errFrame(code)));
  }

  return server;
}
