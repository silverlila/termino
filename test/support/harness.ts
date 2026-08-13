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

/**
 * Scaffolding shared by the tests that need a live relay, and by the ones that
 * need somebody hostile on the other end of it.
 *
 * It lives outside the mirrored directories on purpose: the rest of `test/`
 * matches `src/` and `shared/` file for file, and this matches neither.
 */

export const wait = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

export interface TestRelay {
  server: ReturnType<typeof startRelay>;
  /** The ephemeral port it bound, for a test that needs to sit in front of it. */
  port: number;
  /** What a session connects to. */
  url: string;
}

/**
 * Bun types `Server.port` as optional; on a listening server it never is, and
 * a URL built from `undefined` fails much further downstream.
 */
export function portOf(server: ReturnType<typeof startRelay>): number {
  const port = server.port;
  if (port === undefined) throw new Error("the test relay is not listening");
  return port;
}

/**
 * Starts a relay on an ephemeral port, so a suite run never collides with a
 * relay somebody left running on 8787. Stop it with `server.stop(true)`.
 */
export function startTestRelay(options: Pick<RelayOptions, "now"> = {}): TestRelay {
  const server = startRelay({ port: 0, ...options });
  const port = portOf(server);

  return { server, port, url: `ws://localhost:${port}/` };
}

/**
 * A clock for a relay whose limiter is not what is under test.
 *
 * The bucket is five frames per ten seconds and a v2 session spends three of
 * them on its handshake, so a suite about the protocol would otherwise spend
 * its time counting frames. Jumping a whole window per frame keeps the bucket
 * full without switching the limiter off, and it only ever moves forward.
 */
export function unlimitedClock(): () => number {
  let clock = 0;
  return () => (clock += RATE_LIMIT_WINDOW_MS);
}

const utf8 = (text: string) => new TextEncoder().encode(text);

/**
 * A peer that holds the secret, completes a real handshake, and then sends
 * whatever it is told to.
 *
 * Everything an honest client refuses to put on the wire — a body full of
 * escape sequences, a payload that is not one, ciphertext that opens under no
 * key — goes out from here. Going through `startSession` instead would leave
 * such a probe passing because nothing was ever sent.
 */
export interface HostilePeer {
  /** The one honest frame it has: counter 0, a confirm, the payload that
   * establishes the session. Left to the caller so that a peer which never
   * sends one can be written by simply not calling this. */
  confirm(): Promise<void>;
  /** Seals and sends any JSON value as the inner payload, at the next counter
   * on its sending chain. No text rules, no payload shape. */
  send(payload: unknown): Promise<void>;
  /** A frame that takes a real counter and opens under no key at all. */
  sendNoise(): void;
  /** Burns a counter without sending anything, which is what a message lost on
   * the way looks like from the far end. */
  skipCounter(): void;
  /** A second hello, under a key the peer has not seen. On an established
   * session that is somebody else arriving. */
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

      // Answered with one of our own, as an honest client does: the relay
      // keeps nothing, so the hello sent below is lost if it goes out before
      // the other side has subscribed.
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

      // The chain still advances on this side, so the next real frame lands
      // where the receiver expects it rather than as a gap.
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
