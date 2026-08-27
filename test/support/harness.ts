/**
 * Shared test scaffolding: an ephemeral-port relay, a wait helper, and a hostile-peer
 * stand-in.
 *
 * Bun types `Server.port` as optional; on a listening server it never is, so `portOf`
 * fails here rather than letting undefined reach a relay URL.
 */

import { pad } from "../../shared/crypto/pad.ts";
import { completeHandshake, startHandshake } from "../../shared/crypto/handshake.ts";
import { deriveHandle } from "../../shared/crypto/psk.ts";
import { nextKey } from "../../shared/crypto/ratchet.ts";
import { seal } from "../../shared/crypto/seal.ts";
import {
  decodeFrame,
  encodeFrame,
  fromBase64,
  helloFrame,
  msgFrame,
  subFrame,
} from "../../shared/protocol/frame.ts";
import { startRelay, RATE_LIMIT_WINDOW_MS, type RelayOptions } from "../../server/relay.ts";

export const wait = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

export interface TestRelay {
  server: ReturnType<typeof startRelay>;
  port: number;
  url: string;
}

export function portOf(server: ReturnType<typeof startRelay>): number {
  const port = server.port;
  if (port === undefined) throw new Error("the test relay is not listening");
  return port;
}

export function startTestRelay(options: Pick<RelayOptions, "now"> = {}): TestRelay {
  const server = startRelay({ port: 0, ...options });
  const port = portOf(server);

  return { server, port, url: `ws://localhost:${port}/` };
}

export function unlimitedClock(): () => number {
  let clock = 0;
  return () => (clock += RATE_LIMIT_WINDOW_MS);
}

const utf8 = (text: string) => new TextEncoder().encode(text);

export interface HostilePeer {
  confirm(): Promise<void>;
  send(payload: unknown): Promise<void>;
  sendNoise(): void;
  skipCounter(): void;
  sendSecondHello(): void;
  close(): void;
}

export async function openHostilePeer(relayUrl: string, psk: Uint8Array): Promise<HostilePeer> {
  const handle = deriveHandle(psk);
  const ephemeral = startHandshake();
  const socket = new WebSocket(relayUrl);

  await new Promise<void>((resolve) => socket.addEventListener("open", () => resolve()));

  const peerHello = new Promise<Uint8Array>((resolve) => {
    socket.addEventListener("message", (event) => {
      const frame = decodeFrame(String(event.data));
      if (frame.t !== "hello") return;

      socket.send(encodeFrame(helloFrame(handle, ephemeral.publicKey)));
      resolve(fromBase64(frame.k));
    });
  });

  socket.send(encodeFrame(subFrame(handle)));
  socket.send(encodeFrame(helloFrame(handle, ephemeral.publicKey)));

  const keys = completeHandshake(psk, ephemeral, await peerHello);
  let chain = keys.sendChain;
  let counter = 0;

  async function send(payload: unknown): Promise<void> {
    const advance = nextKey(chain);
    chain = advance.chain;

    const ciphertext = await seal(advance.key, advance.nonce, pad(utf8(JSON.stringify(payload))));
    socket.send(encodeFrame(msgFrame(handle, counter, ciphertext)));
    counter += 1;
  }

  return {
    confirm: () => send({ t: "confirm", nick: "mallory" }),
    send,

    sendNoise(): void {
      const noise = crypto.getRandomValues(new Uint8Array(64));
      socket.send(encodeFrame(msgFrame(handle, counter, noise)));
      counter += 1;

      chain = nextKey(chain).chain;
    },

    skipCounter(): void {
      counter += 1;
      chain = nextKey(chain).chain;
    },

    sendSecondHello(): void {
      socket.send(encodeFrame(helloFrame(handle, startHandshake().publicKey)));
    },

    close: () => socket.close(),
  };
}
