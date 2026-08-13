import { afterEach, beforeEach, describe, expect, it } from "bun:test";
import { startHandshake } from "../shared/crypto/handshake.ts";
import { deriveHandle, generatePsk } from "../shared/crypto/psk.ts";
import { decodeFrame, encodeFrame, helloFrame, subFrame } from "../shared/protocol/frame.ts";
import { startTestRelay, unlimitedClock, wait, type TestRelay } from "./support/harness.ts";
import {
  HANDSHAKE_TIMEOUT_MS,
  SessionClosedError,
  startSession,
  type ConnectionState,
  type IncomingMessage,
  type Session,
  type SessionHandlers,
} from "../src/session.ts";

/**
 * The client core against a live relay, and against a network that is not
 * behaving: a stand-in that swaps the keys travelling through it, one that
 * drops a frame, one that reorders two.
 *
 * The relay under these tests runs on a clock that jumps a rate-limit window
 * per frame. A v2 session spends three frames establishing itself, and what is
 * under test here is the protocol rather than the limiter — `relay.test.ts`
 * owns that.
 */

/** One secret for the whole file. Both ends of a conversation share it, and a
 * session key still comes out different every time, because it comes from the
 * exchange rather than from the secret. */
const PSK = generatePsk();
const OTHER_PSK = generatePsk();

/** Short enough that the failure paths finish in milliseconds. Every test that
 * expects a session to be established uses the default. */
const IMPATIENT = 80;

/** For the failures that have to let a real exchange happen first: still a
 * fraction of a second, and still nothing like the twenty-second default. */
const PATIENT = 500;

let relay: TestRelay;
let sessions: Session[] = [];
let rawSockets: WebSocket[] = [];

async function until(condition: () => boolean, timeoutMs = 5000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (!condition()) {
    if (Date.now() > deadline) throw new Error("timed out waiting for the session");
    await wait(5);
  }
}

/** Long enough for anything in flight to land, before asserting absence. */
const settle = () => wait(150);

interface Recorded {
  messages: IncomingMessage[];
  joined: string[];
  gaps: { nick: string; count: number }[];
  thirdParties: number;
  decryptErrors: Error[];
  connection: ConnectionState[];
}

function recorder(): { handlers: SessionHandlers; got: Recorded } {
  const got: Recorded = {
    messages: [],
    joined: [],
    gaps: [],
    thirdParties: 0,
    decryptErrors: [],
    connection: [],
  };

  return {
    got,
    handlers: {
      onMessage: (message) => got.messages.push(message),
      onPeerJoined: (sasWords) => got.joined.push(sasWords),
      onGap: (nick, count) => got.gaps.push({ nick, count }),
      onThirdParty: () => (got.thirdParties += 1),
      onDecryptError: (error) => got.decryptErrors.push(error),
      onConnectionChange: (state) => got.connection.push(state),
    },
  };
}

interface Peer {
  session: Session;
  got: Recorded;
}

async function joinAs(nick: string, url = relay.url, psk = PSK): Promise<Peer> {
  const { handlers, got } = recorder();
  const session = await startSession({ psk, nick, relayUrl: url, handlers });

  sessions.push(session);
  return { session, got };
}

/** Both ends of one conversation, established. */
async function pair(url = relay.url): Promise<{ alice: Peer; bob: Peer }> {
  const [alice, bob] = await Promise.all([joinAs("alice", url), joinAs("bob", url)]);
  return { alice: alice!, bob: bob! };
}

/**
 * A connection that speaks the wire format directly, for the frames a session
 * would never produce.
 *
 * Closed from `afterEach` rather than at the end of the test that opened it — a
 * failing assertion returns through neither, and one socket left open outlives
 * the whole file.
 */
async function openRawSocket(): Promise<WebSocket> {
  const socket = new WebSocket(relay.url);
  await new Promise<void>((resolve) => socket.addEventListener("open", () => resolve()));
  rawSockets.push(socket);
  return socket;
}

/**
 * Somebody who answers a hello with a hello of their own and then says nothing
 * else — a wrong secret, or a relay pretending to be a peer.
 *
 * It waits to be greeted rather than greeting first: the relay keeps nothing,
 * so a hello sent before the other side subscribed is gone, and this is the
 * same re-send rule an honest client follows.
 */
async function openSilentPeer(handle: string): Promise<void> {
  const socket = await openRawSocket();
  let answered = false;

  socket.addEventListener("message", (event) => {
    if (answered || decodeFrame(String(event.data)).t !== "hello") return;

    answered = true;
    socket.send(encodeFrame(helloFrame(handle, startHandshake().publicKey)));
  });

  socket.send(encodeFrame(subFrame(handle)));
  await settle();
}

interface Meddler {
  url: string;
  stop(): void;
  /** Sends a frame to every client connected through this stand-in, as though
   * the relay had delivered it. */
  inject(raw: string): void;
}

interface Pipe {
  upstream: WebSocket | null;
  pending: string[];
}

/**
 * A relay stand-in: every client dials this instead, and it opens its own
 * connection to the real relay for each of them. What passes through can be
 * changed, dropped, held back or invented, which is exactly what an attacker
 * on the path can do.
 */
function startMeddler(
  targetPort: number,
  options: {
    fromClient?(raw: string, forward: (raw: string) => void): void;
    toClient?(raw: string, deliver: (raw: string) => void): void;
  } = {},
): Meddler {
  const downstream = new Set<Bun.ServerWebSocket<Pipe>>();

  const proxy = Bun.serve<Pipe, {}>({
    port: 0,
    fetch(request, server) {
      if (server.upgrade(request, { data: { upstream: null, pending: [] } })) return undefined;
      return new Response("websocket only", { status: 426 });
    },
    websocket: {
      open(ws) {
        downstream.add(ws);
        const upstream = new WebSocket(`ws://localhost:${targetPort}/`);

        upstream.addEventListener("open", () => {
          for (const text of ws.data.pending) upstream.send(text);
          ws.data.pending = [];
        });
        upstream.addEventListener("message", (event) => {
          const raw = String(event.data);
          const deliver = (text: string) => ws.send(text);

          if (options.toClient === undefined) deliver(raw);
          else options.toClient(raw, deliver);
        });

        ws.data.upstream = upstream;
      },
      message(ws, raw) {
        const forward = (text: string) => {
          const upstream = ws.data.upstream;
          if (upstream !== null && upstream.readyState === WebSocket.OPEN) upstream.send(text);
          else ws.data.pending.push(text);
        };

        const text = String(raw);
        if (options.fromClient === undefined) forward(text);
        else options.fromClient(text, forward);
      },
      close(ws) {
        downstream.delete(ws);
        ws.data.upstream?.close();
      },
    },
  });

  return {
    url: `ws://localhost:${proxy.port}/`,
    inject: (raw) => {
      for (const ws of downstream) ws.send(raw);
    },
    stop: () => proxy.stop(true),
  };
}

beforeEach(() => {
  sessions = [];
  rawSockets = [];
  relay = startTestRelay({ now: unlimitedClock() });
});

afterEach(() => {
  for (const session of sessions) session.close();
  for (const socket of rawSockets) socket.close();
  relay.server.stop(true);
});

describe("two people who share an invite", () => {
  it("delivers a message with its nickname and body intact", async () => {
    const { alice, bob } = await pair();

    await alice.session.send("shipping it now");
    await until(() => bob.got.messages.length === 1);

    const [received] = bob.got.messages;
    expect(received?.body).toBe("shipping it now");
    expect(received?.nick).toBe("alice");
    // Nothing else could have written it: it opened under bob's receiving
    // chain, which only alice holds the other end of.
    expect(bob.got.messages).toHaveLength(1);
  });

  it("delivers in both directions", async () => {
    const { alice, bob } = await pair();

    await bob.session.send("on my way");
    await until(() => alice.got.messages.length === 1);

    expect(alice.got.messages[0]?.body).toBe("on my way");
    expect(alice.got.messages[0]?.nick).toBe("bob");
  });

  it("lands both sides on the same session words, and different ones next time", async () => {
    const { alice, bob } = await pair();

    expect(alice.session.sasWords).toBe(bob.session.sasWords);
    expect(alice.session.sasWords.split(" ")).toHaveLength(8);

    // The same two people, the same secret, a second conversation. The words
    // come from the exchange rather than from the secret, so there is nothing
    // to memorise and nothing worth writing down.
    alice.session.close();
    bob.session.close();
    await settle();

    const again = await pair();
    expect(again.alice.session.sasWords).not.toBe(alice.session.sasWords);
  });

  it("derives the same handle from the secret alone", async () => {
    const { alice, bob } = await pair();

    expect(alice.session.handle).toBe(deriveHandle(PSK));
    expect(bob.session.handle).toBe(alice.session.handle);
  });

  it("does not deliver a sender their own message back", async () => {
    const { alice, bob } = await pair();

    const sent = await alice.session.send("shipping it now");
    await until(() => bob.got.messages.length === 1);
    await settle();

    expect(alice.got.messages).toHaveLength(0);
    // send() hands the message back so the sender can display its own traffic.
    expect(sent.body).toBe("shipping it now");
  });

  it("keeps messages in the order they were sent", async () => {
    const { alice, bob } = await pair();

    for (const body of ["first", "second", "third"]) await alice.session.send(body);
    await until(() => bob.got.messages.length === 3);

    expect(bob.got.messages.map((message) => message.body)).toEqual([
      "first",
      "second",
      "third",
    ]);
  });

  it("delivers three sends that did not wait for each other", async () => {
    const { alice, bob } = await pair();

    // Three keypresses in a row, which is the path the interface actually
    // uses: `App.tsx` starts the next send without waiting for the last.
    //
    // This does *not* prove the send queue in `session.ts`. Counters are taken
    // before the first await, and Bun's WebCrypto resolves concurrent seals in
    // call order, so these three arrive in order with the queue deleted too.
    // What it does prove is that unawaited sends all arrive, none is lost, and
    // none reads as a gap.
    await Promise.all([
      alice.session.send("first"),
      alice.session.send("second"),
      alice.session.send("third"),
    ]);
    await until(() => bob.got.messages.length === 3);
    await settle();

    expect(bob.got.messages.map((message) => message.body)).toEqual([
      "first",
      "second",
      "third",
    ]);
    expect(bob.got.gaps).toEqual([]);
  });

  it("reports the connection lifecycle, and opens only once a peer has confirmed", async () => {
    const { alice } = await pair();
    expect(alice.got.connection).toEqual(["connecting", "open"]);
    expect(alice.got.joined).toEqual([alice.session.sasWords]);

    alice.session.close();
    await until(() => alice.got.connection.includes("closed"));
  });

  it("timestamps a message by when it arrived, not by anything the sender said", async () => {
    const { alice, bob } = await pair();
    const before = Date.now();

    await alice.session.send("shipping it now");
    await until(() => bob.got.messages.length === 1);

    const ts = bob.got.messages[0]?.ts ?? 0;
    expect(ts).toBeGreaterThanOrEqual(before);
    expect(ts).toBeLessThanOrEqual(Date.now());
  });
});

describe("somebody with a different invite", () => {
  it("is not even in the same channel", async () => {
    const { alice } = await pair();
    const stranger = deriveHandle(OTHER_PSK);

    expect(stranger).not.toBe(alice.session.handle);
  });
});

describe("a man in the middle", () => {
  it("cannot make either side accept a session", async () => {
    // It holds no secret. All it does is swap the ephemeral public key in
    // every hello for one of its own — which is the whole of the attack, and
    // is what an unauthenticated Diffie-Hellman exchange has no answer to.
    const theirs = startHandshake();

    const meddler = startMeddler(relay.port, {
      fromClient(raw, forward) {
        const frame = decodeFrame(raw);
        if (frame.t !== "hello") return forward(raw);

        forward(encodeFrame(helloFrame(frame.h, theirs.publicKey)));
      },
    });

    try {
      // Both are awaited together rather than one after the other: a rejection
      // nobody is waiting on yet is an unhandled one, which fails the run
      // somewhere other than here.
      const refusals = await Promise.all([
        rejection(startSession({ psk: PSK, nick: "alice", relayUrl: meddler.url, handshakeTimeoutMs: PATIENT })),
        rejection(startSession({ psk: PSK, nick: "bob", relayUrl: meddler.url, handshakeTimeoutMs: PATIENT })),
      ]);

      // Both confirms fail to open, so neither session is ever established and
      // the failure names what it might be rather than reading as a hiccup.
      for (const refusal of refusals) {
        expect(refusal.message).toMatch(/somebody is in the middle/);
      }
    } finally {
      meddler.stop();
    }
  });
});

describe("a hello that was not sent by the peer", () => {
  it("is refused when it is this client's own, reflected back", async () => {
    const meddler = startMeddler(relay.port, {
      fromClient(raw, forward) {
        const frame = decodeFrame(raw);
        forward(raw);

        // Straight back down the connection it came from, which an honest
        // relay never does.
        if (frame.t === "hello") meddler.inject(raw);
      },
    });

    try {
      const attempt = startSession({
        psk: PSK,
        nick: "alice",
        relayUrl: meddler.url,
        handshakeTimeoutMs: IMPATIENT,
      });

      await expect(attempt).rejects.toThrow(/reflected back/);
    } finally {
      meddler.stop();
    }
  });
});

describe("a third party", () => {
  it("is ignored and said out loud when it hellos into an established session", async () => {
    const meddler = startMeddler(relay.port);

    try {
      const { handlers, got } = recorder();

      // Started together: neither side's `startSession` resolves until the
      // other has answered, so waiting for the first one before opening the
      // second would wait for ever.
      const [alice, bob] = await Promise.all([
        startSession({ psk: PSK, nick: "alice", relayUrl: meddler.url, handlers }),
        joinAs("bob", meddler.url),
      ]);
      sessions.push(alice);

      const intruder = startHandshake();
      meddler.inject(encodeFrame(helloFrame(alice.handle, intruder.publicKey)));
      await until(() => got.thirdParties === 1);

      // Ignored, not acted on: the session alice already has still works.
      await bob.session.send("still here");
      await until(() => got.messages.length === 1);
      expect(got.messages[0]?.body).toBe("still here");
      expect(alice.sasWords).toBe(bob.session.sasWords);
    } finally {
      meddler.stop();
    }
  });

  it("says nothing when the peer merely repeats the hello it already sent", async () => {
    const { alice } = await pair();
    await settle();

    // Both sides answer a hello with one of their own, so a duplicate is the
    // ordinary case rather than an intrusion.
    expect(alice.got.thirdParties).toBe(0);
  });

  it("cannot get a third connection onto the handle at all", async () => {
    await pair();

    const attempt = startSession({
      psk: PSK,
      nick: "eve",
      relayUrl: relay.url,
      handshakeTimeoutMs: HANDSHAKE_TIMEOUT_MS,
    });

    await expect(attempt).rejects.toThrow(/two participants/);
  });
});

/**
 * Only alice sends text here, and a confirm is always counter 0, so a counter
 * above 0 belongs to alice alone. That makes "drop the message numbered 2" a
 * choice of one exact frame rather than of whichever frame happened to be
 * third through the pipe.
 */
function droppingMeddler(counter: number): Meddler {
  return startMeddler(relay.port, {
    toClient(raw, deliver) {
      const frame = decodeFrame(raw);
      if (frame.t === "msg" && frame.i === counter) return;

      deliver(raw);
    },
  });
}

describe("a gap in the numbering", () => {
  it("is reported once the message after it has arrived", async () => {
    const meddler = droppingMeddler(2);

    try {
      const { alice, bob } = await pair(meddler.url);

      await alice.session.send("one");
      await until(() => bob.got.messages.length === 1);
      await alice.session.send("two");
      await alice.session.send("three");
      await until(() => bob.got.messages.length === 2);
      await settle();

      // Nothing yet. The message numbered 2 is missing, but the one that
      // stepped over it is the only evidence so far, and a message that
      // overtakes another is not a message that was lost.
      expect(bob.got.gaps).toEqual([]);

      await alice.session.send("four");
      await until(() => bob.got.messages.length === 3);
      await until(() => bob.got.gaps.length === 1);

      expect(bob.got.gaps).toEqual([{ nick: "alice", count: 1 }]);
      expect(bob.got.messages.map((message) => message.body)).toEqual(["one", "three", "four"]);
    } finally {
      meddler.stop();
    }
  });

  it("is reported once and not again on every message that follows", async () => {
    const meddler = droppingMeddler(2);

    try {
      const { alice, bob } = await pair(meddler.url);

      for (const body of ["one", "two", "three", "four", "five"]) {
        await alice.session.send(body);
      }
      await until(() => bob.got.messages.length === 4);
      await settle();

      expect(bob.got.gaps).toEqual([{ nick: "alice", count: 1 }]);
    } finally {
      meddler.stop();
    }
  });

  it("says nothing when the missing message arrives out of order", async () => {
    // Holds message 2 back and lets 3 overtake it, which is reordering rather
    // than loss — and the cached key is what makes it openable when it lands.
    let held: string | null = null;

    const meddler = startMeddler(relay.port, {
      toClient(raw, deliver) {
        const frame = decodeFrame(raw);

        if (frame.t === "msg" && frame.i === 2) {
          held = raw;
          return;
        }

        deliver(raw);

        if (held !== null) {
          deliver(held);
          held = null;
        }
      },
    });

    try {
      const { alice, bob } = await pair(meddler.url);

      await alice.session.send("one");
      await until(() => bob.got.messages.length === 1);
      await alice.session.send("two");
      await alice.session.send("three");
      await until(() => bob.got.messages.length === 3);
      await settle();

      expect(bob.got.gaps).toEqual([]);
      expect(bob.got.messages.map((message) => message.body)).toEqual(["one", "three", "two"]);
    } finally {
      meddler.stop();
    }
  });
});

describe("a handshake timeout", () => {
  it("defaults to twenty seconds", () => {
    // Long enough for somebody to be slow opening a second terminal, and short
    // enough that a wrong invite does not read as a hang.
    expect(HANDSHAKE_TIMEOUT_MS).toBe(20_000);
  });

  it("says nobody is here when no hello ever arrives", async () => {
    const attempt = startSession({
      psk: PSK,
      nick: "alice",
      relayUrl: relay.url,
      handshakeTimeoutMs: IMPATIENT,
    });

    await expect(attempt).rejects.toThrow(/nobody else is here yet/);
  });

  it("says somebody may be in the middle when a hello arrives and nothing opens", async () => {
    await openSilentPeer(deriveHandle(PSK));

    const attempt = startSession({
      psk: PSK,
      nick: "alice",
      relayUrl: relay.url,
      handshakeTimeoutMs: PATIENT,
    });

    await expect(attempt).rejects.toThrow(/somebody is in the middle/);
  });

  it("tells the two failures apart", async () => {
    await openSilentPeer(deriveHandle(OTHER_PSK));

    const answered = await rejection(
      startSession({
        psk: OTHER_PSK,
        nick: "alice",
        relayUrl: relay.url,
        handshakeTimeoutMs: PATIENT,
      }),
    );

    const alone = await rejection(
      startSession({
        psk: PSK,
        nick: "alice",
        relayUrl: relay.url,
        handshakeTimeoutMs: IMPATIENT,
      }),
    );

    // Two different events, said two different ways: one is a conversation
    // nobody has joined yet, the other is an alarm.
    expect(answered.message).not.toBe(alone.message);
  });
});

/** The error a promise settled with, for a comparison that needs both. */
async function rejection(promise: Promise<unknown>): Promise<Error> {
  try {
    await promise;
  } catch (error) {
    return error as Error;
  }

  throw new Error("expected the session to be refused");
}

describe("a session being torn down", () => {
  it("wipes both chain keys and every cached message key before closing the socket", async () => {
    // A dropped frame leaves a key cached for a message that may still turn
    // up, which is the only way the skip cache has anything in it at all.
    const meddler = droppingMeddler(2);

    try {
      const { alice, bob } = await pair(meddler.url);

      await alice.session.send("one");
      await until(() => bob.got.messages.length === 1);
      await alice.session.send("two");
      await alice.session.send("three");
      await until(() => bob.got.messages.length === 2);

      const wiped = bob.session.close();

      // The sending chain, the receiving chain, and the key and nonce still
      // held for the message numbered 2. Nothing was handed in from out here:
      // these are the buffers the session was using a moment ago.
      expect(wiped).toHaveLength(4);
      for (const buffer of wiped) {
        expect(buffer.length).toBeGreaterThan(0);
        expect(Array.from(buffer).every((byte) => byte === 0)).toBe(true);
      }

      // The socket goes down after the wipe, not before: this is the far end
      // of the same close(), so it cannot report success for a teardown that
      // stopped half way.
      await until(() => bob.got.connection.includes("closed"));
    } finally {
      meddler.stop();
    }
  });

  it("has nothing left to send afterwards", async () => {
    const { alice } = await pair();
    alice.session.close();

    await expect(alice.session.send("hello?")).rejects.toBeInstanceOf(SessionClosedError);
  });

  it("refuses a message that was still being sealed when it closed", async () => {
    const { alice, bob } = await pair();

    // Somebody typing a line and quitting in the same breath. The interface
    // does not wait for a send before tearing the session down, so this
    // interleaving is a keystroke away rather than a curiosity.
    const pending = alice.session.send("did this leave the machine?");

    // One microtask, which is what puts the close *inside* the send: the queued
    // send has started and is suspended on sealing, and has not reached the
    // socket.
    await Promise.resolve();
    alice.session.close();

    // A closed socket neither delivers nor complains, so a send that resolved
    // here would put the line in the sender's own transcript as though it had
    // gone out. Nothing arrived at the other end, and the sender is told.
    await expect(pending).rejects.toBeInstanceOf(SessionClosedError);
    await settle();
    expect(bob.got.messages).toHaveLength(0);
  });
});
