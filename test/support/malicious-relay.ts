/**
 * A relay that misbehaves on purpose: it forwards between exactly two clients and does
 * whatever `policy` says to each frame on the way through.
 *
 * Bun.serve fixes per-connection data at `server.upgrade`, before any socket exists, so
 * `side` is null until `open` assigns it.
 */

import { decodeFrame } from "../../shared/protocol/frame.ts";

type Side = "a" | "b";

type Partition = "none" | "both";

interface RelayPolicy {
  onFrame?(raw: string, from: Side): string | null;
  hold?: boolean;
  partition?: Partition;
}

export interface MaliciousRelay {
  url: string;
  policy: RelayPolicy;
  connections(): number;
  held(): readonly string[];
  release(indexes: number[]): void;
  inject(raw: string, to: Side): void;
  close(): void;
}

interface Connection {
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
