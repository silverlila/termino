import type { ChannelKeys } from "../shared/crypto/derive.ts";
import type { Identity } from "../shared/crypto/identity.ts";
import {
  decodeFrame,
  encodeFrame,
  subFrame,
  type ErrorCode,
  type Frame,
} from "../shared/protocol/frame.ts";
import { openMessage, sealMessage } from "../shared/protocol/message.ts";
import { admit, type SeenMessages } from "./replay.ts";
import {
  loadTrustRecords,
  observe,
  saveTrustRecords,
  verifyPeer,
  type TrustRecords,
  type TrustState,
  type VerifyOutcome,
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
}

export interface OutgoingMessage {
  from: string;
  nick: string;
  body: string;
  ts: number;
}

/** A message that decrypted and verified but was not shown. */
export interface DiscardedMessage {
  nick: string;
  reason: "replayed" | "stale";
}

export interface TrustEvent {
  nick: string;
  pubkey: string;
  /** Only ever `NEW` or `CHANGED`; `KNOWN` is every other message and would
   * drown the interesting case in noise. */
  state: TrustState;
  /** The whole store as it now stands. Carried on the event rather than left
   * for the listener to fetch, so a view rendering trust markers cannot read
   * a copy from before this event was applied. */
  records: TrustRecords;
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
  /** Fires for an inbound message that was genuine and still not shown: a
   * repeat of one already delivered, or one dated outside the freshness
   * window. Announced rather than dropped quietly, because a replay is
   * somebody's deliberate act and a stale one usually means a wrong clock. */
  onDiscardedMessage?(discarded: DiscardedMessage): void;
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
  /**
   * Applies `/verify <nick> <fingerprint>`, persists the result, and hands
   * back what happened along with the store as it now stands — so a view
   * rendering trust markers never has to ask twice.
   *
   * Verification lives behind the session rather than beside it because the
   * session is the only thing that writes `known_keys.json`. A second writer
   * holding its own copy of the store would overwrite this flag the next time
   * any nickname arrived with an unfamiliar key, and the loss would not show
   * up until the next launch.
   */
  verify(nick: string, fingerprint: string): VerifyOutcome;
  close(): void;
}

export async function startSession(options: SessionOptions): Promise<Session> {
  const now = options.now ?? Date.now;
  const handlers = options.handlers ?? {};
  const { handle, msgKey } = options.keys;
  const { identity, nick } = options;

  let records = loadTrustRecords(options.terminoDir);
  let seen: SeenMessages = new Map();

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

    // Before the trust store, not after: a recording of a key somebody used
    // last month would otherwise raise KEY CHANGED against the key they hold
    // today, which is an alarm an attacker could ring at will.
    const admission = admit(seen, opened.sig, opened.ts, now());
    if (admission.freshness !== "fresh") {
      handlers.onDiscardedMessage?.({ nick: opened.nick, reason: admission.freshness });
      return;
    }
    seen = admission.seen;

    const observed = observe(records, opened.nick, opened.from, now());
    if (observed.records !== records) {
      records = observed.records;
      saveTrustRecords(records, options.terminoDir);
      handlers.onTrustEvent?.({
        nick: opened.nick,
        pubkey: opened.from,
        state: observed.state,
        records,
      });
    }

    handlers.onMessage?.({
      from: opened.from,
      nick: opened.nick,
      body: opened.body,
      ts: opened.ts,
      trust: observed.state,
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

    verify(nick: string, claimed: string): VerifyOutcome {
      // `verifyPeer` returns the store unchanged unless it granted something,
      // so the caller reads `records` the same way whatever the result was.
      const outcome = verifyPeer(records, nick, claimed);
      if (outcome.result !== "verified") return outcome;

      records = outcome.records;
      saveTrustRecords(records, options.terminoDir);
      return outcome;
    },

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
