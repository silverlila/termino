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

/** The token bucket limits what a connection may say; without these, opening
 * connections is free, so ten thousand of them cost an attacker nothing. */
export const MAX_CONNECTIONS = 1000;
export const MAX_CONNECTIONS_PER_IP = 10;

/** A conversation is between exactly two people, so a third connection to a
 * handle is refused. This is a convenience rather than a defence — the relay is
 * the untrusted party, and nothing stops whoever runs it from lifting the cap.
 * The defence is in the client, which accepts exactly one peer `hello`. */
export const MAX_SUBSCRIBERS_PER_HANDLE = 2;

/** Seconds — Bun's unit for this option, which it caps at 960. Bun's own
 * default is 120 today, so this changes no behaviour; it is stated so the time
 * a dead connection holds a slot lives in this file rather than in whichever
 * Bun version happens to be installed. */
export const IDLE_TIMEOUT_SECONDS = 120;

/** Every request whose source Bun cannot name shares one key rather than being
 * exempt, so a transport with no address cannot be used to slip the per-IP cap. */
const UNKNOWN_SOURCE = "unknown";

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
  /** Remembered from `fetch`, where `server.requestIP` is available, so that
   * `close` can give the per-source slot back. */
  source: string;
  bucket: TokenBucket;
}

export interface RelayOptions {
  port?: number;
  /** Injectable so tests can advance past the rate-limit window instead of
   * sleeping ten real seconds, which would exceed Bun's per-test timeout. */
  now?: () => number;
  /** Injectable for the same reason: proving a cap holds must not mean opening
   * a thousand sockets. The two are separate because every test connection
   * arrives from one address, so only an independent global cap can be shown
   * to be the thing that refused. */
  maxConnections?: number;
  maxConnectionsPerIp?: number;
  /** Called when serving a frame fails in a way this file did not anticipate.
   * It takes no arguments and returns nothing on purpose: the relay must be
   * able to report *that* something went wrong without being able to say
   * anything about whom it happened to. Whoever wants that fact printed prints
   * it in the entrypoint — `bun run check:relay-silent` forbids this file from
   * writing anything at all. */
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
      // `now` is injectable and fallible, and this is one of its two call
      // sites: a clock that throws here would take the whole request with it.
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
          // Answering the sender and telling the caller are attempted
          // separately, so a failure in one still leaves the other done, and
          // neither may throw: `onError` is the caller's code and `ws.send`
          // depends on a socket that may be closing.
          attempt(() => reject(ws, "bad_frame"));
          attempt(onError);
        }
      },

      close(ws) {
        release(ws.data.source);
      },
    },
  });

  /**
   * Runs `work` and gives up quietly if it throws — the only place in this
   * file allowed to do that, and the reason is the whole point of the file.
   * An exception escaping one of Bun's handlers is printed by Bun with a stack
   * trace, and the frame, the handle and the sender's address are all in scope
   * when it does. Every step of failing therefore runs through here: answering
   * a sender goes through a socket that may already be closing, and reporting
   * goes through `onError`, which belongs to the caller and can fail like
   * anything else. When reporting itself is what failed there is nowhere left
   * to report to, which is where the relay stops.
   */
  function attempt(work: () => void): void {
    try {
      work();
    } catch {}
  }

  /** Returns undefined once the socket is upgraded — Bun reads that as "the
   * handshake is the response". */
  function admitRequest(request: Request): Response | undefined {
    if (new URL(request.url).pathname !== "/") return refuse("only / is served");

    // The CLI sends no Origin header. One arriving means a browser page is
    // driving the socket, which is not a client this relay serves.
    if (request.headers.has("origin")) return refuse("no browser clients");

    const source = server.requestIP(request)?.address ?? UNKNOWN_SOURCE;
    if (openConnections >= maxConnections) return refuse("too many connections");
    if ((openPerSource.get(source) ?? 0) >= maxConnectionsPerIp) {
      return refuse("too many connections from this address");
    }

    const connection: Connection = { handle: null, source, bucket: fullBucket(now()) };

    // Counted before the upgrade rather than in `open`, so a burst of
    // simultaneous requests cannot all pass a check that nothing has
    // incremented yet. The slot is given straight back if this turns out not to
    // be a WebSocket request at all — or if the upgrade throws, since the
    // caller answers 429 and no `close` will ever arrive to free it.
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

  /** A refusal before the upgrade has no `err` frame available — that frame
   * type only exists over an established WebSocket — so it answers 429, which
   * is distinct from the 426 a non-WebSocket request gets. */
  function refuse(reason: string): Response {
    return new Response(`termino relay: ${reason}\n`, { status: 429 });
  }

  function admit(source: string): void {
    openConnections += 1;
    openPerSource.set(source, (openPerSource.get(source) ?? 0) + 1);
  }

  function release(source: string): void {
    openConnections -= 1;

    // Deleted at zero rather than left there: the key comes from the network,
    // so an entry kept per address ever seen is its own slow leak.
    const remaining = (openPerSource.get(source) ?? 1) - 1;
    if (remaining > 0) openPerSource.set(source, remaining);
    else openPerSource.delete(source);
  }

  /** Parse, charge, act — in that order, for every frame type alike. */
  function route(ws: Bun.ServerWebSocket<Connection>, raw: string | Buffer): void {
    const frame = parse(raw);

    if (frame === null) return reject(ws, "bad_frame");

    // Every frame the relay acts on costs a token, not just `msg`. A `sub`
    // is cheap to send and expensive to serve, so charging only `msg` left
    // a client free to toggle between two handles and make the relay do
    // subscription work for nothing.
    const limit = takeToken(ws.data.bucket, now());
    ws.data.bucket = limit.bucket;
    if (!limit.allowed) return reject(ws, "rate_limited");

    if (frame.t === "sub") return subscribe(ws, frame);
    return forward(ws, frame, raw);
  }

  function parse(raw: string | Buffer): ClientFrame | null {
    try {
      const frame = decodeFrame(raw);
      // `err` is a frame the relay originates. A client sending one is confused
      // or probing; either way it is not something to act on.
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

  /** `hello` and `msg` travel the same way. The relay is told nothing about
   * what either means, and routes both by the handle the *connection*
   * subscribed to rather than by the one inside the frame. */
  function forward(
    ws: Bun.ServerWebSocket<Connection>,
    frame: ClientFrame,
    raw: string | Buffer,
  ): void {
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

  return server;
}
