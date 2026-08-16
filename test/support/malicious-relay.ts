import { decodeFrame } from "../../shared/protocol/frame.ts";

/**
 * A relay that misbehaves on purpose.
 *
 * The relay is the party this protocol is designed to defend against, and
 * every honest test in this suite runs against a relay that behaves. This one
 * sits where the honest one does — two clients dial it, it forwards between
 * them — and does what an attacker on the path can do instead: drop a frame,
 * hold frames back and let them out in another order, rewrite the bytes,
 * invent a frame of its own, deliver one twice, or stop carrying traffic in
 * either direction.
 *
 * It is driven synchronously from the test rather than on timers: a policy is
 * a decision made about the frame in hand, so a test that sets one before the
 * frame it means to catch cannot race it.
 *
 * It forwards rather than proxying to `server/relay.ts` on purpose. There is
 * no rate limit, no subscriber cap and no clock in here — a test about what
 * the *client* does with a hostile network should not also have to keep the
 * honest relay's limiter happy.
 */

/** Which of the two connections a frame came from. Assigned in connection
 * order, so a test that means "everything alice sends" starts alice first. */
export type Side = "a" | "b";

export type Partition = "none" | "a-to-b" | "b-to-a" | "both";

export interface RelayPolicy {
  /** Return null to drop, a different string to rewrite, or `raw` unchanged.
   *  Frames travel as JSON strings — `encodeFrame` is `JSON.stringify`. */
  onFrame?(raw: string, from: Side): string | null;
  /** Hold frames instead of forwarding, so a test can release them out of order. */
  hold?: boolean;
  /** Stop forwarding in one or both directions. */
  partition?: Partition;
}

export interface MaliciousRelay {
  /** What a client dials. */
  url: string;
  /** Mutated in place by the test: `relay.policy.hold = true`. */
  policy: RelayPolicy;
  /** How many clients are connected. Both sides of a v2 session block until
   * the other answers, so a test starts them together — this is how it waits
   * for the first one to arrive before starting the second, which is what
   * makes `"a"` a known person rather than whichever socket won the race. */
  connections(): number;
  /** Frames currently held, in arrival order. */
  held(): readonly string[];
  /** Forward held frames by index — `release([1, 0])` delivers the second
   * first. With no argument, everything held, in arrival order. */
  release(indexes?: number[]): void;
  /** A frame of the relay's own, straight to one client. Bypasses the policy:
   * this frame was not forwarded from anywhere, which is the point of it. */
  inject(raw: string, to: Side): void;
  close(): void;
}

interface Connection {
  /** Null only between the upgrade and `open`, which nothing reads. */
  side: Side | null;
}

interface HeldFrame {
  raw: string;
  to: Side;
}

export function startMaliciousRelay(): MaliciousRelay {
  const policy: RelayPolicy = {};
  const sockets = new Map<Side, Bun.ServerWebSocket<Connection>>();
  const holding: HeldFrame[] = [];

  const server = Bun.serve<Connection, {}>({
    port: 0,

    fetch(request, server) {
      if (server.upgrade(request, { data: { side: null } })) return undefined;
      return new Response("malicious relay: websocket only\n", { status: 426 });
    },

    websocket: {
      open(ws) {
        const side = freeSide();

        // A conversation has room for two here as well. A third connection is
        // not a case any of these tests drive, and accepting one silently
        // would make a stray socket look like a delivery bug.
        if (side === null) return ws.close();

        ws.data.side = side;
        sockets.set(side, ws);
      },

      message(ws, raw) {
        route(ws.data.side, String(raw));
      },

      close(ws) {
        const side = ws.data.side;
        if (side !== null && sockets.get(side) === ws) sockets.delete(side);
      },
    },
  });

  function freeSide(): Side | null {
    if (!sockets.has("a")) return "a";
    if (!sockets.has("b")) return "b";
    return null;
  }

  /**
   * One frame, from one client.
   *
   * A subscription is addressed to the relay itself and is read before the
   * policy sees it, exactly as the honest relay consumes `sub` rather than
   * forwarding it — otherwise a policy that corrupts everything would put a
   * frame on the wire that no relay ever sends, and the client would be being
   * tested against a case that cannot happen.
   */
  function route(from: Side | null, raw: string): void {
    if (from === null || isSubscription(raw)) return;

    const rewritten = policy.onFrame === undefined ? raw : policy.onFrame(raw, from);
    if (rewritten === null) return;
    if (isPartitioned(from)) return;

    const to: Side = from === "a" ? "b" : "a";
    if (policy.hold === true) {
      holding.push({ raw: rewritten, to });
      return;
    }

    deliver(to, rewritten);
  }

  function isPartitioned(from: Side): boolean {
    const partition = policy.partition ?? "none";
    if (partition === "both") return true;
    return partition === (from === "a" ? "a-to-b" : "b-to-a");
  }

  function deliver(to: Side, raw: string): void {
    sockets.get(to)?.send(raw);
  }

  function release(indexes?: number[]): void {
    const order = indexes ?? holding.map((_, index) => index);
    const chosen = order.map((index) => {
      const frame = holding[index];
      // Loudly, rather than delivering nothing: an index that names no frame
      // means the test is holding a different set than it thinks it is.
      if (frame === undefined) throw new Error(`no frame is held at index ${index}`);
      return frame;
    });

    // Emptied before anything goes out, so a policy that is still holding
    // appends behind this batch rather than reshuffling the one being drained.
    for (const frame of chosen) holding.splice(holding.indexOf(frame), 1);
    for (const frame of chosen) deliver(frame.to, frame.raw);
  }

  return {
    url: `ws://localhost:${server.port}/`,
    policy,
    connections: () => sockets.size,
    held: () => holding.map((frame) => frame.raw),
    release,
    inject: (raw, to) => deliver(to, raw),
    close: () => server.stop(true),
  };
}

/** Anything that does not decode is not a `sub`, and is forwarded — a client
 * that sends a frame this cannot read is a case worth carrying to the far end
 * rather than swallowing here. */
function isSubscription(raw: string): boolean {
  try {
    return decodeFrame(raw).t === "sub";
  } catch {
    return false;
  }
}
