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

/**
 * The client core: connect, exchange ephemeral keys, ratchet outbound, open
 * inbound. It reports through callbacks and prints nothing, so the TUI on top
 * of it is a view layer with no protocol knowledge of its own — and so this
 * whole layer is testable with no terminal involved.
 *
 * Nothing here touches the disk. There is no identity to store, no trust store
 * to keep and no replay window to remember: a message key is used exactly once,
 * which makes a second copy of a message unopenable rather than merely
 * recognised.
 */

export interface IncomingMessage {
  nick: string;
  body: string;
  /** When this client received it. The sender's clock is not carried and would
   * not be believed if it were; this is the only clock this client can vouch
   * for. */
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
  /** The peer is here: their confirm opened, or they spoke again after having
   * been reported gone. Carries the eight words both people read aloud to each
   * other, which do not change for the life of the session. */
  onPeerJoined?(sasWords: string): void;
  /** A whole expiry has passed with nothing authenticated opening. Said from
   * the absence of the peer's own pings, so a relay that withholds traffic
   * shows up as the peer going quiet rather than being able to assert they are
   * still there. */
  onPeerGone?(): void;
  /** Messages that were stepped over and never turned up, counted once the
   * message after them has arrived. */
  onGap?(nick: string, count: number): void;
  /** A second, different `hello` on an established session. Ignored, and said
   * out loud: it means somebody else is trying to join a conversation that has
   * room for exactly two. */
  onThirdParty?(): void;
  /** Fires for any inbound message that could not be accepted: a counter that
   * cannot be serviced, ciphertext that does not authenticate, or a payload
   * that is not one. The message is discarded either way. */
  onDecryptError?(error: Error): void;
  onRelayError?(code: ErrorCode): void;
  onConnectionChange?(state: ConnectionState): void;
}

export interface SessionOptions {
  /** The 16 bytes carried out of band. Folded into the handshake as proof of
   * who is on the other end; it is not the message key. */
  psk: Uint8Array;
  nick: string;
  /** Required rather than defaulted: the CLI owns the default, so the address
   * a session connects to is never implicit. */
  relayUrl: string;
  handlers?: SessionHandlers;
  /** Injectable so a test of the failure paths does not sleep twenty seconds. */
  handshakeTimeoutMs?: number;
  /** Both injectable for the same reason: presence is measured in tens of
   * seconds, and a test of it would otherwise be spent asleep. */
  pingIntervalMs?: number;
  presenceExpiryMs?: number;
}

export interface Session {
  /** The routing label this session subscribed to. Not a secret. */
  handle: string;
  /** The eight words for this session, identical on both ends and different
   * every time. Reading them aloud is what rules out a man in the middle. */
  sasWords: string;
  /** Seals and sends. Returns the message so the caller can display its own
   * traffic — the relay does not echo it back. */
  send(body: string): Promise<OutgoingMessage>;
  /**
   * Zeroes both chain keys and every cached message key, then closes the
   * socket — in that order, so a crash between the two leaves no key
   * reachable.
   *
   * Hands back the buffers it overwrote, all of them now zeros. Nothing in the
   * interface reads them; they exist because "the keys are gone at teardown" is
   * a security claim, and one that cannot be looked at cannot be checked.
   */
  close(): Uint8Array[];
}

/**
 * Thrown by `send` when the session was closed before the message reached the
 * socket — whether it was already closed on the way in, or was closed while
 * this message was being sealed. Either way nothing went out, and the caller
 * is told so rather than left to assume it did.
 */
export class SessionClosedError extends Error {
  constructor() {
    super("the session is closed — the message was not sent");
  }
}

/** Long enough for somebody to be slow opening a second terminal, short enough
 * that a wrong invite does not look like a hang. */
export const HANDSHAKE_TIMEOUT_MS = 20_000;

/** How often this client says it is still here. */
export const PING_INTERVAL_MS = 15_000;

/** How long the peer's silence runs before they are reported gone. Three
 * intervals of grace, so a couple of pings lost on the way do not read as
 * somebody leaving the conversation. */
export const PRESENCE_EXPIRY_MS = 45_000;

/** The two ways a handshake ends badly, said apart on purpose: one is a
 * conversation nobody has joined yet, the other is an alarm. They travel on the
 * error, so a caller reads them the same way it reads any other failure. */
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

  /** Whether the peer counts as here, and when they were last heard from.
   * Both move only on a payload that opened, which is the whole point: the
   * relay can delay or drop one, and cannot write one. */
  let peerPresent = false;
  let peerLastHeard = 0;

  /** Gaps already counted, so the same missing message is reported once and
   * not again on every message that follows it. */
  const reportedGaps = new Set<number>();

  /** Everything already on its way out. One payload finishes reaching the
   * socket before the next takes its counter. */
  let sending = Promise.resolve();

  let confirm!: () => void;
  let abandon!: (error: Error) => void;
  const confirmed = new Promise<void>((resolve, reject) => {
    confirm = resolve;
    abandon = reject;
  });

  // Which message the timeout gives decides how the failure reads, and the two
  // are not the same event: nobody answering is ordinary, somebody answering
  // with keys that do not check out is not.
  const timer = setTimeout(
    () => abandon(new Error(peerPublicKey === null ? NOBODY_HERE : IN_THE_MIDDLE)),
    handshakeTimeoutMs,
  );

  socket.addEventListener("close", () => {
    handlers.onConnectionChange?.("closed");
    abandon(new Error("the relay closed the connection"));
  });

  // Opening a message is async, so handling events as they fire would let a
  // slow message be overtaken by the one behind it. Chaining keeps delivery in
  // the order the relay sent them — which the handshake depends on, because a
  // peer's confirm follows its hello down the same connection.
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
      // An honest relay forwards a message byte for byte, so a frame that does
      // not decode is one somebody cut, padded or rewrote on the way. It is
      // announced rather than dropped in silence because it may have been a
      // message: the counter it carried is never taken, so nothing else here
      // will notice it went missing until a later message steps over it — and
      // a corrupted `hello` would produce no news at all until the handshake
      // gave up.
      return handlers.onDecryptError?.(asError(error));
    }

    if (frame.t === "err") {
      handlers.onRelayError?.(frame.code);

      // The one relay error a session cannot carry on through: there is
      // already a conversation here, and waiting out the handshake timeout
      // would report it as nobody being home.
      if (frame.code === "channel_full") {
        abandon(new Error("could not join — this channel already has two participants"));
      }
      return;
    }
    // A `sub` never comes back from the relay, and a frame for another handle
    // is not something this connection asked for.
    if (frame.h !== handle) return;

    if (frame.t === "hello") return onHello(frame);
    if (frame.t === "msg") return await onMessage(frame);
  }

  function onHello(frame: HelloFrame): void {
    const theirPublicKey = fromBase64(frame.k);

    if (peerPublicKey !== null) {
      // The same key again is the peer answering our hello, or answering a
      // hello of ours it had already seen. A different one is a third party.
      if (sameBytes(peerPublicKey, theirPublicKey)) return;
      return handlers.onThirdParty?.();
    }

    peerPublicKey = theirPublicKey;

    // The relay keeps nothing, so a hello sent before the other side
    // subscribed is gone for good. Answering every peer hello with our own is
    // what completes the earlier joiner's exchange, and costs one frame.
    socket.send(encodeFrame(helloFrame(handle, ephemeral.publicKey)));

    try {
      const keys = completeHandshake(psk, ephemeral, theirPublicKey);

      sendChain = keys.sendChain;
      receiving = startReceiving(keys.recvChain);
      sasWords = keys.sasWords;
      // Everything that will ever be derived from it has been. Holding it any
      // longer would keep a value that recomputes both chains.
      keys.root.fill(0);
    } catch (error) {
      return abandon(asError(error));
    }

    // Counter 0 of our sending chain, the first thing the peer can open.
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

    // A peer's confirm is counter 0 of its chain and everything else comes
    // after it, so anything that opens before the session is established is a
    // peer that skipped the one payload proving both ends agree. Said out
    // loud rather than shown: it opened, and it is still not something to put
    // on screen under somebody's name.
    //
    // A ping is no exception, and deliberately so. It would be the one payload
    // that reaches nothing visible, which makes it exactly the one worth
    // letting through — and letting it through would let a peer that never
    // confirmed advertise itself as present. Presence is a claim about a peer
    // that has been established, so it waits for the confirm like everything
    // else. A ping refused here costs nothing: the next one is one interval
    // away.
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

    // Whatever it says, it opened under the receiving chain, and only the peer
    // holds the other end of that. That is the whole of authenticated
    // presence — and it is why a `text` counts for it as much as a `ping`
    // does: somebody typing is not somebody who has gone.
    peerLastHeard = Date.now();

    // Establishing comes first, and the order is the contract: a caller told
    // the peer is here — and handed the words to read aloud — must not still
    // be reading this session as connecting. Everything else can only arrive
    // once the session is established, because the guard above refuses it.
    if (payload.t === "confirm") establish();

    markPeerPresent();

    if (payload.t === "text") {
      handlers.onMessage?.({ nick: payload.nick, body: payload.body, ts: Date.now() });
    }

    // A ping carries nothing but the fact that it opened, which is recorded
    // above and is the only reason it was sent.
  }

  /** The peer's confirm, opened: the one payload that proves both ends reached
   * the same keys, and the point at which this session exists. A second one
   * changes nothing — a peer sends exactly one, at counter 0. */
  function establish(): void {
    if (established) return;

    established = true;
    clearTimeout(timer);
    handlers.onConnectionChange?.("open");
    confirm();
  }

  /** The peer, here. Coming back after having been reported gone is the same
   * event as arriving — the session is the one that was already running, and
   * the words to read aloud are the ones it started with. */
  function markPeerPresent(): void {
    if (peerPresent) return;

    peerPresent = true;
    handlers.onPeerJoined?.(sasWords);
  }

  /**
   * Every interval: say we are still here, and ask whether they still are.
   *
   * One timer, because presence is one fact read from both directions, and
   * checking on the ping interval is what bounds how late the news can be: a
   * peer that goes quiet is reported within one interval of their expiry
   * lapsing, rather than whenever something else happens to arrive.
   *
   * A ping spends a counter on the sending chain like any other payload. That
   * is intended: an idle session keeps ratcheting, and every key it steps over
   * is one nobody can recompute.
   */
  function beat(): void {
    if (peerPresent && Date.now() - peerLastHeard > presenceExpiryMs) {
      peerPresent = false;
      handlers.onPeerGone?.();
    }

    // A ping that cannot leave needs no announcement of its own: the far end's
    // own expiry reports it, which is the same news said to the side that can
    // do something about it.
    void send({ t: "ping", nick }).catch(() => undefined);
  }

  /**
   * A gap that the message just delivered did not fill, and that has not been
   * counted before. A gap filled out of order is silent, which is the point of
   * caching the key rather than discarding it.
   */
  function reportGaps(gapsBefore: number[]): void {
    if (gapsBefore.length === 0 || receiving === null) return;

    const stillOpen = new Set(receiving.skipped());
    const missed = gapsBefore.filter(
      (counter) => stillOpen.has(counter) && !reportedGaps.has(counter),
    );
    if (missed.length === 0) return;

    for (const counter of missed) reportedGaps.add(counter);

    // The nickname comes from the peer's confirm, which is the first payload
    // that ever opens, so it is known by the time any gap can be reported.
    if (peerNick !== null) handlers.onGap?.(peerNick, missed.length);
  }

  /**
   * Queues one payload behind everything already going out.
   *
   * Sealing is asynchronous, so two callers that do not wait for each other —
   * the confirm below, and every keypress the interface turns into a message —
   * would otherwise take their counters in one order and reach the socket in
   * another. The receiver reads the counter as the order, so the two would
   * arrive transposed and nothing would say so: a message that overtakes
   * another is exactly the case the skip cache is built to fill silently.
   *
   * No test can currently fail without this queue: counters are taken before
   * the first await, and Bun's WebCrypto happens to resolve concurrent seals
   * in the order they were called. That is a property of today's runtime and
   * not one anything promises, which is the reason the ordering is enforced
   * here rather than left to it. Do not delete this on the strength of a green
   * suite.
   */
  function send(payload: Payload): Promise<void> {
    const sent = sending.then(() => transmit(payload));

    // The queue carries on after a refused payload. It is the caller's
    // rejection to handle, and dropping it here would make the *next* message
    // fail for somebody else's reason.
    sending = sent.catch(() => undefined);

    return sent;
  }

  async function transmit(payload: Payload): Promise<void> {
    if (closed) throw new SessionClosedError();

    const chain = sendChain;
    if (chain === null) throw new Error("the session has no keys yet");

    // Checked before the chain moves. A counter cannot be handed back, and one
    // spent on a message that was never sent arrives at the far end as a hole
    // in the conversation.
    const problem = payloadProblem(payload);
    if (problem !== null) throw new PayloadError(problem);

    const advance = nextKey(chain);
    sendChain = advance.chain;

    const counter = sendCounter;
    sendCounter += 1;

    const frame = await sealMessage(advance, handle, counter, payload);
    advance.key.fill(0);
    advance.nonce.fill(0);

    // Checked again on the far side of the await: close() may have run while
    // this message was being sealed. `WebSocket.send` on a closed socket
    // neither throws nor delivers, so without this the caller would be told
    // its message had gone out — and would show it in its own transcript —
    // when nothing left the machine.
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

  // Started only once there is somebody to be present to, and cleared in
  // close() — an interval nobody clears keeps the process alive after the
  // conversation has ended.
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
