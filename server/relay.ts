/**
 * Bun specifics this file is shaped around: an exception escaping a fetch or socket
 * handler is printed with a stack trace, and the frame, handle and sender address are
 * in scope when it is — which is why failures here report nothing about whom. `fetch`
 * returning undefined means "the upgrade handshake was the response"; every other path
 * must return a Response. `websocket.idleTimeout` is in seconds, defaults to 120 and is
 * capped at 960.
 *
 * `onError` takes no arguments by design: the relay may report that something failed,
 * never anything about who it happened to.
 */

import { encodeFrame, errFrame, type ErrorCode } from "../shared/protocol/frame.ts";
import { admit as admitPath, IDLE_TIMEOUT_SECONDS, newMember, route, type Member } from "./channel.ts";

const DEFAULT_PORT = 8787;

const MAX_CONNECTIONS = 1000;
const MAX_CONNECTIONS_PER_IP = 10;

const UNKNOWN_SOURCE = "unknown";

interface Connection {
  member: Member;
  source: string;
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
          deliver(ws, raw);
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
    const admission = admitPath(new URL(request.url), request.headers);
    if (!admission.ok) return refuse(admission.reason);

    const source = server.requestIP(request)?.address ?? UNKNOWN_SOURCE;
    if (openConnections >= maxConnections) return refuse("too many connections");
    if ((openPerSource.get(source) ?? 0) >= maxConnectionsPerIp) {
      return refuse("too many connections from this address");
    }

    const connection: Connection = { member: newMember(admission.handle, now()), source };

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

  function deliver(ws: Bun.ServerWebSocket<Connection>, raw: string | Buffer): void {
    const { member } = ws.data;
    const decided = route(member, raw, server.subscriberCount(member.handle), now());
    ws.data.member = decided.member;

    const { action } = decided;
    if (action.kind === "reject") return reject(ws, action.code);
    if (action.kind === "subscribe") ws.subscribe(member.handle);
    if (action.kind === "forward") ws.publish(member.handle, raw);
  }

  function reject(ws: Bun.ServerWebSocket<Connection>, code: ErrorCode): void {
    ws.send(encodeFrame(errFrame(code)));
  }

  return server;
}
