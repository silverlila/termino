import { deriveChannelKeys, type ChannelKeys } from "../crypto/derive.ts";
import type { Identity } from "../crypto/identity.ts";
import {
  decodeFrame,
  encodeFrame,
  subFrame,
  type ErrorCode,
  type Frame,
} from "../protocol/frame.ts";
import { openMessage, sealMessage } from "../protocol/message.ts";
import {
  loadTrustRecords,
  observe,
  saveTrustRecords,
  type TrustRecords,
  type TrustState,
} from "./trust.ts";

/**
 * The client core: connect, subscribe, seal outbound, open and verify
 * inbound. It reports through callbacks and prints nothing, so the TUI on top
 * of it is a view layer with no protocol knowledge of its own — and so this
 * whole layer is testable with no terminal involved.
 */

export interface IncomingMessage {
  /** Hex public key that actually signed this. Verified before you see it. */
  from: string;
  nick: string;
  body: string;
  ts: number;
  trust: TrustState;
  /** Whether a human has confirmed this key out of band. */
  verified: boolean;
}

export interface OutgoingMessage {
  from: string;
  nick: string;
  body: string;
  ts: number;
}

export interface TrustEvent {
  nick: string;
  pubkey: string;
  /** Only ever `NEW` or `CHANGED`; `KNOWN` is every other message and would
   * drown the interesting case in noise. */
  state: TrustState;
}

export type ConnectionState = "connecting" | "open" | "closed";

export interface SessionHandlers {
  onMessage?(message: IncomingMessage): void;
  onPresence?(count: number): void;
  onTrustEvent?(event: TrustEvent): void;
  /** Fires for any inbound message that could not be accepted: wrong key,
   * tampered ciphertext, malformed payload, or a signature that did not
   * verify. The message is discarded either way. */
  onDecryptError?(error: Error): void;
  onRelayError?(code: ErrorCode): void;
  onConnectionChange?(state: ConnectionState): void;
}

export interface SessionOptions {
  /** Pre-derived. Derivation costs ~850 ms and is pure, so it is kept out of
   * here: the CLI completes it before starting a renderer, and tests can hold
   * a handle fixed while varying the message key. */
  keys: ChannelKeys;
  nick: string;
  identity: Identity;
  /** Required rather than defaulted: the CLI owns the default, so the address
   * a session connects to is never implicit. */
  relayUrl: string;
  handlers?: SessionHandlers;
  /** Where the trust store lives. A parameter so tests do not touch `~`. */
  terminoDir?: string;
  now?: () => number;
}

export interface Session {
  /** The routing label this session subscribed to. Not a secret. */
  handle: string;
  /** Seals, signs and sends. Returns the message so the caller can display
   * its own traffic — the relay does not echo it back. */
  send(body: string): Promise<OutgoingMessage>;
  /** Trust records as they currently stand, for rendering markers. */
  trustRecords(): TrustRecords;
  close(): void;
}

/** Derives the channel keys, then connects. Blocks ~850 ms in argon2id. */
export async function joinChannel(
  options: Omit<SessionOptions, "keys"> & { channel: string; password: string },
): Promise<Session> {
  const { channel, password, ...rest } = options;
  return await startSession({ ...rest, keys: deriveChannelKeys(channel, password) });
}

export async function startSession(options: SessionOptions): Promise<Session> {
  const now = options.now ?? Date.now;
  const handlers = options.handlers ?? {};
  const { handle, msgKey } = options.keys;
  const { identity, nick } = options;

  let records = loadTrustRecords(options.terminoDir);

  handlers.onConnectionChange?.("connecting");
  const socket = new WebSocket(options.relayUrl);

  await new Promise<void>((resolve, reject) => {
    socket.addEventListener("open", () => resolve(), { once: true });
    socket.addEventListener("error", () => reject(new Error("could not reach the relay")), {
      once: true,
    });
  });

  socket.send(encodeFrame(subFrame(handle)));
  handlers.onConnectionChange?.("open");
  socket.addEventListener("close", () => handlers.onConnectionChange?.("closed"), { once: true });

  // Opening a message is async, so handling events as they fire would let a
  // slow message be overtaken by the one behind it. Chaining keeps delivery in
  // the order the relay sent them.
  let inOrder = Promise.resolve();
  socket.addEventListener("message", (event) => {
    const raw = String(event.data);
    inOrder = inOrder.then(() => receive(raw));
  });

  async function receive(raw: string): Promise<void> {
    const frame = parse(raw);
    if (frame === null) return;

    if (frame.t === "presence") return handlers.onPresence?.(frame.n);
    if (frame.t === "err") return handlers.onRelayError?.(frame.code);
    if (frame.t !== "msg" || frame.h !== handle) return;

    let opened;
    try {
      opened = await openMessage(msgKey, frame);
    } catch (error) {
      handlers.onDecryptError?.(error instanceof Error ? error : new Error(String(error)));
      return;
    }

    const seen = observe(records, opened.nick, opened.from, now());
    if (seen.records !== records) {
      records = seen.records;
      saveTrustRecords(records, options.terminoDir);
      handlers.onTrustEvent?.({ nick: opened.nick, pubkey: opened.from, state: seen.state });
    }

    handlers.onMessage?.({
      from: opened.from,
      nick: opened.nick,
      body: opened.body,
      ts: opened.ts,
      trust: seen.state,
      verified: seen.record.verified,
    });
  }

  return {
    handle,

    async send(body: string): Promise<OutgoingMessage> {
      const payload = { from: identity.publicKeyHex, nick, body, ts: now() };
      const frame = await sealMessage({
        msgKey,
        handle,
        payload,
        secretKey: identity.secretKey,
      });

      socket.send(encodeFrame(frame));
      return payload;
    },

    trustRecords: () => records,
    close: () => socket.close(),
  };
}

/** The relay only ever sends well-formed frames. One that is not means
 * something upstream is broken or hostile; there is nothing useful to do with
 * it but drop it. */
function parse(raw: string): Frame | null {
  try {
    return decodeFrame(raw);
  } catch {
    return null;
  }
}
