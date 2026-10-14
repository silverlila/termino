/**
 * The relay on Cloudflare: one Durable Object per channel, chosen by the handle in the
 * path, applying channel.ts's rules to the sockets it holds. Like the Bun relay it holds
 * no key, decrypts nothing and writes nothing about anyone — no console, and
 * observability is off in wrangler.jsonc.
 *
 * Sockets are accepted through the hibernation API, so an idle channel is evicted from
 * memory and costs nothing while its sockets stay open. Eviction runs the constructor
 * again and loses every field, which is why each socket's state lives in its attachment
 * and nothing lives on `this`.
 *
 * Date.now() inside a Worker stands still while code runs and moves only across I/O,
 * so it reads as the time the event arrived — fine for a bucket refilling over seconds.
 *
 * A Durable Object sees one channel, so the per-address limit relay.ts keeps as a count
 * of open sockets is here a rate of new connections, kept by Cloudflare's rate-limit
 * binding before any Durable Object is touched. Cloudflare documents that binding as
 * approximate — counts sync between machines after a few seconds — so it bounds a flood
 * rather than counting exactly. Each channel holds at most MAX_SOCKETS_PER_CHANNEL
 * sockets, subscribed or not.
 *
 * An exception escaping a handler is recorded by Cloudflare with the request URL, and the
 * URL carries the handle, so every handler catches everything.
 */

import { DurableObject } from "cloudflare:workers";
import { encodeFrame, errFrame, type ErrorCode } from "../../shared/protocol/frame.ts";
import { admit, IDLE_TIMEOUT_SECONDS, newMember, route, type Member } from "../channel.ts";

// Two participants, a third to be told channel_full, and one spare for a reconnect
// racing the close of the socket it replaces.
const MAX_SOCKETS_PER_CHANNEL = 4;

interface Env {
  CHANNEL: DurableObjectNamespace<Channel>;
  CONNECTIONS_PER_ADDRESS: RateLimit;
  // Set only by the test environment in wrangler.jsonc, so idle reaping can be observed
  // without waiting two minutes.
  IDLE_TIMEOUT_SECONDS?: string;
}

interface Attachment {
  member: Member;
  lastHeard: number;
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    try {
      const admission = admit(new URL(request.url), request.headers);
      if (!admission.ok) return refuse(admission.reason);

      const address = request.headers.get("cf-connecting-ip") ?? "unknown";
      const { success } = await env.CONNECTIONS_PER_ADDRESS.limit({ key: address });
      if (!success) return refuse("too many connections from this address");

      if (request.headers.get("upgrade")?.toLowerCase() !== "websocket") {
        return new Response("termino relay: websocket only\n", { status: 426 });
      }

      return await env.CHANNEL.getByName(admission.handle).fetch(request);
    } catch {
      return new Response("termino relay: unavailable\n", { status: 503 });
    }
  },
} satisfies ExportedHandler<Env>;

export class Channel extends DurableObject<Env> {
  override async fetch(request: Request): Promise<Response> {
    try {
      const admission = admit(new URL(request.url), request.headers);
      if (!admission.ok) return refuse(admission.reason);

      const now = Date.now();
      this.forgetIdle(now);
      if (this.live().length >= MAX_SOCKETS_PER_CHANNEL) {
        return refuse("this channel has no room");
      }

      const { 0: client, 1: server } = new WebSocketPair();
      this.ctx.acceptWebSocket(server);
      attach(server, { member: newMember(admission.handle, now), lastHeard: now });

      return new Response(null, { status: 101, webSocket: client });
    } catch {
      return new Response("termino relay: unavailable\n", { status: 503 });
    }
  }

  override async webSocketMessage(ws: WebSocket, raw: string | ArrayBuffer): Promise<void> {
    try {
      this.deliver(ws, raw);
    } catch {
      attempt(() => reject(ws, "bad_frame"));
    }
  }

  override async webSocketClose(ws: WebSocket, code: number, reason: string): Promise<void> {
    attempt(() => ws.close(code, reason));
  }

  override async webSocketError(ws: WebSocket): Promise<void> {
    attempt(() => ws.close(1011, "socket error"));
  }

  private deliver(ws: WebSocket, raw: string | ArrayBuffer): void {
    const now = Date.now();
    const state = attachmentOf(ws);
    const frame = typeof raw === "string" ? raw : new Uint8Array(raw);

    // A stale subscriber holds a place a new one might be asking for. The sender has
    // just been heard from, so it is not one of them.
    this.forgetIdle(now, ws);
    // Only a subscribed sender is forwarded for, so this list already holds it then.
    const subscribers = this.subscribers();
    const decided = route(state.member, frame, subscribers.length, now);
    attach(ws, { member: decided.member, lastHeard: now });

    const { action } = decided;
    if (action.kind === "reject") return reject(ws, action.code);
    if (action.kind !== "forward") return;

    for (const other of subscribers) {
      if (other !== ws) attempt(() => other.send(raw));
    }
  }

  private subscribers(): WebSocket[] {
    return this.live().filter((socket) => attachmentOf(socket).member.subscribed);
  }

  // A socket this object closed stays in getWebSockets() until the close handshake
  // finishes, and must not hold a place in the meantime.
  private live(): WebSocket[] {
    return this.ctx.getWebSockets().filter((socket) => socket.readyState === WebSocket.OPEN);
  }

  // A client pings every fifteen seconds, so silence for the idle timeout means a
  // connection that died without closing. The Bun relay has Bun's idleTimeout for this;
  // here it is checked whenever the channel is next touched, which costs nothing while
  // nobody is.
  private forgetIdle(now: number, heard?: WebSocket): void {
    const idleMs = Number(this.env.IDLE_TIMEOUT_SECONDS ?? IDLE_TIMEOUT_SECONDS) * 1000;

    for (const socket of this.live()) {
      if (socket !== heard && now - attachmentOf(socket).lastHeard > idleMs) {
        attempt(() => socket.close(1001, "idle"));
      }
    }
  }
}

function attach(ws: WebSocket, state: Attachment): void {
  ws.serializeAttachment(state);
}

function attachmentOf(ws: WebSocket): Attachment {
  const state = ws.deserializeAttachment() as Attachment | null;
  if (state === null) throw new Error("a socket was accepted without its state");
  return state;
}

function reject(ws: WebSocket, code: ErrorCode): void {
  ws.send(encodeFrame(errFrame(code)));
}

function refuse(reason: string): Response {
  return new Response(`termino relay: ${reason}\n`, { status: 429 });
}

function attempt(work: () => void): void {
  try {
    work();
  } catch {}
}
