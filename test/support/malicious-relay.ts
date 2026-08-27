import { decodeFrame } from "../../shared/protocol/frame.ts";

/**
 * A relay that misbehaves on purpose. It forwards between exactly two clients
 * and does whatever `policy` says to each frame on the way through, so a test
 * can put the client in front of a hostile network without a hostile peer.
 *
 * Bun wants the per-connection data at `server.upgrade`, before any socket
 * exists, but a side can only be claimed once one does — which is why `side`
 * starts null and is assigned in `open`.
 */

/** Which of the two connections a frame came from. Assigned in connection
 * order, so a test that means "everything alice sends" starts alice first. */
type Side = "a" | "b";

type Partition = "none" | "both";

interface RelayPolicy {
  /** Return null to drop, a different string to rewrite, or `raw` unchanged.
   *  Frames travel as JSON strings — `encodeFrame` is `JSON.stringify`. */
  onFrame?(raw: string, from: Side): string | null;
  hold?: boolean;
  partition?: Partition;
}

export interface MaliciousRelay {
  url: string;
  policy: RelayPolicy;
  /** How many clients are connected. Both sides of a v2 session block until
   * the other answers, so a test starts them together — this is how it waits
   * for the first one to arrive before starting the second, which is what
   * makes `"a"` a known person rather than whichever socket won the race. */
  connections(): number;
  held(): readonly string[];
  release(indexes: number[]): void;
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
    if (isPartitioned()) return;

    const to: Side = from === "a" ? "b" : "a";
    if (policy.hold === true) {
      holding.push({ raw: rewritten, to });
      return;
    }

    deliver(to, rewritten);
  }

  function isPartitioned(): boolean {
    return (policy.partition ?? "none") === "both";
  }

  function deliver(to: Side, raw: string): void {
    sockets.get(to)?.send(raw);
  }

  function release(indexes: number[]): void {
    const chosen = indexes.map((index) => {
      const frame = holding[index];
      if (frame === undefined) throw new Error(`no frame is held at index ${index}`);
      return frame;
    });

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

function isSubscription(raw: string): boolean {
  try {
    return decodeFrame(raw).t === "sub";
  } catch {
    return false;
  }
}
