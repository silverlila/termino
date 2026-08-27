/**
 * The headless client core: connects, runs the handshake, ratchets outbound, opens
 * inbound, and reports through callbacks. It prints nothing.
 *
 * The relay is live pub/sub with no buffer: a frame sent before the other side has
 * subscribed is dropped, never delivered later.
 *
 * `WebSocket.send()` on a closed socket neither throws nor delivers — it silently
 * discards — so a send racing teardown has to be caught by our own flag.
 *
 * `close()` returns the buffers it zeroed, which exists so the wiping can be checked from
 * outside; `onDecryptError` fires for any refused inbound frame, not only decryption
 * failures.
 */

import { completeHandshake, startHandshake } from "../shared/crypto/handshake.ts";
import { deriveHandle } from "../shared/crypto/psk.ts";
import { nextKey, startReceiving, type MessageKey, type ReceivingChain } from "../shared/crypto/ratchet.ts";
import {
  decodeFrame,
  encodeFrame,
  fromBase64,
  helloFrame,
  subFrame,
  type ErrorCode,
  type Frame,
  type HelloFrame,
  type MsgFrame,
} from "../shared/protocol/frame.ts";
import {
  openMessage,
  payloadProblem,
  PayloadError,
  sealMessage,
  type Payload,
} from "../shared/protocol/message.ts";

export interface IncomingMessage {
  nick: string;
  body: string;
  ts: number;
}

export interface OutgoingMessage {
  nick: string;
  body: string;
  ts: number;
}

export type ConnectionState = "connecting" | "open" | "closed";

export interface SessionHandlers {
  onMessage?(message: IncomingMessage): void;
  onPeerJoined?(sasWords: string): void;
  onPeerGone?(): void;
  onGap?(nick: string, count: number): void;
  onThirdParty?(): void;
  onDecryptError?(error: Error): void;
  onRelayError?(code: ErrorCode): void;
  onConnectionChange?(state: ConnectionState): void;
}

export interface SessionOptions {
  psk: Uint8Array;
  nick: string;
  relayUrl: string;
  handlers?: SessionHandlers;
  handshakeTimeoutMs?: number;
  pingIntervalMs?: number;
  presenceExpiryMs?: number;
}

export interface Session {
  handle: string;
  sasWords: string;
  send(body: string): Promise<OutgoingMessage>;
  close(): Uint8Array[];
}

export class SessionClosedError extends Error {
  constructor() {
    super("the session is closed — the message was not sent");
  }
}

export const HANDSHAKE_TIMEOUT_MS = 20_000;

export const PING_INTERVAL_MS = 15_000;

export const PRESENCE_EXPIRY_MS = 45_000;

const NOBODY_HERE = "could not establish a session — nobody else is here yet";
const IN_THE_MIDDLE =
  "could not establish a session — wrong invite, or somebody is in the middle";

export async function startSession(options: SessionOptions): Promise<Session> {
  const handlers = options.handlers ?? {};
  const { nick, psk } = options;
  const handshakeTimeoutMs = options.handshakeTimeoutMs ?? HANDSHAKE_TIMEOUT_MS;
  const pingIntervalMs = options.pingIntervalMs ?? PING_INTERVAL_MS;
  const presenceExpiryMs = options.presenceExpiryMs ?? PRESENCE_EXPIRY_MS;
  const handle = deriveHandle(psk);

  handlers.onConnectionChange?.("connecting");
  const socket = new WebSocket(options.relayUrl);

  await new Promise<void>((resolve, reject) => {
    socket.addEventListener("open", () => resolve(), { once: true });
    socket.addEventListener("error", () => reject(new Error("could not reach the relay")), {
      once: true,
    });
  });

  const ephemeral = startHandshake();

  let peerPublicKey: Uint8Array | null = null;
  let sendChain: Uint8Array | null = null;
  let receiving: ReceivingChain | null = null;
  let sasWords = "";
  let sendCounter = 0;
  let peerNick: string | null = null;
  let established = false;
  let closed = false;

  let peerPresent = false;
  let peerLastHeard = 0;

  const reportedGaps = new Set<number>();

  let sending = Promise.resolve();

  let confirm!: () => void;
  let abandon!: (error: Error) => void;
  const confirmed = new Promise<void>((resolve, reject) => {
    confirm = resolve;
    abandon = reject;
  });

  const timer = setTimeout(
    () => abandon(new Error(peerPublicKey === null ? NOBODY_HERE : IN_THE_MIDDLE)),
    handshakeTimeoutMs,
  );

  socket.addEventListener("close", () => {
    handlers.onConnectionChange?.("closed");
    abandon(new Error("the relay closed the connection"));
  });

  let inOrder = Promise.resolve();
  socket.addEventListener("message", (event) => {
    const raw = String(event.data);
    inOrder = inOrder.then(() => receive(raw));
  });

  socket.send(encodeFrame(subFrame(handle)));
  socket.send(encodeFrame(helloFrame(handle, ephemeral.publicKey)));

  async function receive(raw: string): Promise<void> {
    let frame: Frame;
    try {
      frame = decodeFrame(raw);
    } catch (error) {
      return handlers.onDecryptError?.(asError(error));
    }

    if (frame.t === "err") {
      handlers.onRelayError?.(frame.code);

      if (frame.code === "channel_full") {
        abandon(new Error("could not join — this channel already has two participants"));
      }
      return;
    }
    if (frame.h !== handle) return;

    if (frame.t === "hello") return onHello(frame);
    if (frame.t === "msg") return await onMessage(frame);
  }

  function onHello(frame: HelloFrame): void {
    const theirPublicKey = fromBase64(frame.k);

    if (peerPublicKey !== null) {
      if (sameBytes(peerPublicKey, theirPublicKey)) return;
      return handlers.onThirdParty?.();
    }

    peerPublicKey = theirPublicKey;

    socket.send(encodeFrame(helloFrame(handle, ephemeral.publicKey)));

    try {
      const keys = completeHandshake(psk, ephemeral, theirPublicKey);

      sendChain = keys.sendChain;
      receiving = startReceiving(keys.recvChain);
      sasWords = keys.sasWords;
      keys.root.fill(0);
    } catch (error) {
      return abandon(asError(error));
    }

    void send({ t: "confirm", nick }).catch((error: unknown) => abandon(asError(error)));
  }

  async function onMessage(frame: MsgFrame): Promise<void> {
    const chain = receiving;
    if (chain === null) {
      return handlers.onDecryptError?.(
        new Error("a message arrived before this session had a key to open it with"),
      );
    }

    const gapsBefore = chain.skipped();

    let messageKey: MessageKey;
    try {
      messageKey = chain.take(frame.i);
    } catch (error) {
      return handlers.onDecryptError?.(asError(error));
    }

    let payload: Payload;
    try {
      payload = await openMessage(messageKey, frame);
    } catch (error) {
      return handlers.onDecryptError?.(asError(error));
    } finally {
      messageKey.key.fill(0);
      messageKey.nonce.fill(0);
    }

    if (!established && payload.t !== "confirm") {
      return handlers.onDecryptError?.(
        new Error("a message arrived before the session was established"),
      );
    }

    deliver(payload);

    reportGaps(gapsBefore);
  }

  function deliver(payload: Payload): void {
    peerNick = payload.nick;

    peerLastHeard = Date.now();

    if (payload.t === "confirm") establish();

    markPeerPresent();

    if (payload.t === "text") {
      handlers.onMessage?.({ nick: payload.nick, body: payload.body, ts: Date.now() });
    }

  }

  function establish(): void {
    if (established) return;

    established = true;
    clearTimeout(timer);
    handlers.onConnectionChange?.("open");
    confirm();
  }

  function markPeerPresent(): void {
    if (peerPresent) return;

    peerPresent = true;
    handlers.onPeerJoined?.(sasWords);
  }

  function beat(): void {
    if (peerPresent && Date.now() - peerLastHeard > presenceExpiryMs) {
      peerPresent = false;
      handlers.onPeerGone?.();
    }

    void send({ t: "ping", nick }).catch(() => undefined);
  }

  function reportGaps(gapsBefore: number[]): void {
    if (gapsBefore.length === 0 || receiving === null) return;

    const stillOpen = new Set(receiving.skipped());
    const missed = gapsBefore.filter(
      (counter) => stillOpen.has(counter) && !reportedGaps.has(counter),
    );
    if (missed.length === 0) return;

    for (const counter of missed) reportedGaps.add(counter);

    if (peerNick !== null) handlers.onGap?.(peerNick, missed.length);
  }

  function send(payload: Payload): Promise<void> {
    const sent = sending.then(() => transmit(payload));

    sending = sent.catch(() => undefined);

    return sent;
  }

  async function transmit(payload: Payload): Promise<void> {
    if (closed) throw new SessionClosedError();

    const chain = sendChain;
    if (chain === null) throw new Error("the session has no keys yet");

    const problem = payloadProblem(payload);
    if (problem !== null) throw new PayloadError(problem);

    const advance = nextKey(chain);
    sendChain = advance.chain;

    const counter = sendCounter;
    sendCounter += 1;

    const frame = await sealMessage(advance, handle, counter, payload);
    advance.key.fill(0);
    advance.nonce.fill(0);

    if (closed) throw new SessionClosedError();

    socket.send(encodeFrame(frame));
  }

  function wipe(): Uint8Array[] {
    const overwritten: Uint8Array[] = [];
    closed = true;

    if (sendChain !== null) {
      overwritten.push(sendChain);
      sendChain.fill(0);
    }
    if (receiving !== null) overwritten.push(...receiving.wipe());

    return overwritten;
  }

  try {
    await confirmed;
  } catch (error) {
    clearTimeout(timer);
    wipe();
    socket.close();
    throw error;
  }

  const heartbeat = setInterval(beat, pingIntervalMs);

  return {
    handle,
    sasWords,

    async send(body: string): Promise<OutgoingMessage> {
      await send({ t: "text", nick, body });
      return { nick, body, ts: Date.now() };
    },

    close(): Uint8Array[] {
      clearTimeout(timer);
      clearInterval(heartbeat);
      const overwritten = wipe();
      socket.close();
      return overwritten;
    },
  };
}

function asError(error: unknown): Error {
  return error instanceof Error ? error : new Error(String(error));
}

function sameBytes(left: Uint8Array, right: Uint8Array): boolean {
  return left.length === right.length && left.every((byte, index) => byte === right[index]);
}
