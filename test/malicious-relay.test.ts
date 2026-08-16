import { afterEach, beforeEach, describe, expect, it } from "bun:test";
import { deriveHandle, generatePsk } from "../shared/crypto/psk.ts";
import { decodeFrame, encodeFrame, fromBase64, msgFrame } from "../shared/protocol/frame.ts";
import {
  startSession,
  type IncomingMessage,
  type Session,
  type SessionHandlers,
  type SessionOptions,
} from "../src/session.ts";
import { gapNotice } from "../src/tui/App.tsx";
import { wait } from "./support/harness.ts";
import { startMaliciousRelay, type MaliciousRelay } from "./support/malicious-relay.ts";

/**
 * The client against the party the protocol is designed to defend against.
 *
 * Everywhere else in this suite the relay behaves and the peer is the problem.
 * Here the relay is the problem: it drops a message, holds two back and lets
 * them out in the wrong order, invents a frame, delivers one twice, stops
 * carrying traffic, and cuts bytes out of what it forwards.
 *
 * Every assertion is about something the person at the terminal is told,
 * because a client that handles a dropped message perfectly and says nothing
 * has failed. The session's callbacks are that surface — `src/tui/App.tsx`
 * turns each into one line, and the line each test means is named in a comment
 * beside it:
 *
 *   onGap          → `⚠ 1 message from alice never arrived`
 *   onDecryptError → `could not open N messages — someone may be sending noise`,
 *                    one line rewritten in place rather than one per frame
 *   onPeerGone     → the status bar stops saying the peer is here
 */

const PSK = generatePsk();
const HANDLE = deriveHandle(PSK);

/** Counter 0 of a sending chain is the confirm, so the first line somebody
 * types is 1, the second is 2, and a test can name the frame it means. */
const FIRST_TEXT_COUNTER = 1;

/** Presence, driven fast enough to watch. Everything else in this file runs on
 * the real fifteen and forty-five seconds, which never tick inside a test. */
const QUICK_PING_MS = 20;
const QUICK_EXPIRY_MS = 60;
type Timings = Pick<SessionOptions, "pingIntervalMs" | "presenceExpiryMs">;
const QUICK_PRESENCE: Timings = {
  pingIntervalMs: QUICK_PING_MS,
  presenceExpiryMs: QUICK_EXPIRY_MS,
};

let relay: MaliciousRelay;
let sessions: Session[] = [];

interface Recorded {
  messages: IncomingMessage[];
  gaps: { nick: string; count: number }[];
  decryptErrors: Error[];
  gone: number;
}

interface Peer {
  session: Session;
  got: Recorded;
}

function recorder(): { handlers: SessionHandlers; got: Recorded } {
  const got: Recorded = { messages: [], gaps: [], decryptErrors: [], gone: 0 };

  return {
    got,
    handlers: {
      onMessage: (message) => got.messages.push(message),
      onGap: (nick, count) => got.gaps.push({ nick, count }),
      onDecryptError: (error) => got.decryptErrors.push(error),
      onPeerGone: () => (got.gone += 1),
    },
  };
}

async function until(condition: () => boolean, timeoutMs = 5000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (!condition()) {
    if (Date.now() > deadline) throw new Error("timed out waiting for the session");
    await wait(5);
  }
}

/** Long enough for anything in flight to land, before asserting absence. */
const settle = () => wait(150);

async function join(nick: string, timings: Timings): Promise<Peer> {
  const { handlers, got } = recorder();
  const session = await startSession({
    psk: PSK,
    nick,
    relayUrl: relay.url,
    handlers,
    ...timings,
  });

  sessions.push(session);
  return { session, got };
}

/**
 * Both ends of one conversation, established, with alice on side `a`.
 *
 * Which side is which matters here in a way it does not against an honest
 * relay: a policy that drops what alice sends has to know who alice is. Sides
 * are handed out in connection order, so bob is not started until the relay
 * has seen the first connection — and neither promise is awaited before both
 * exist, because each end blocks until the other answers.
 */
async function pair(timings: Timings = {}): Promise<{ alice: Peer; bob: Peer }> {
  const alice = join("alice", timings);
  await until(() => relay.connections() === 1);
  const bob = join("bob", timings);

  const [established, answered] = await Promise.all([alice, bob]);
  return { alice: established, bob: answered };
}

const bodiesSeenBy = (peer: Peer) => peer.got.messages.map((message) => message.body);

const noticesSeenBy = (peer: Peer) =>
  peer.got.gaps.map(({ nick, count }) => gapNotice(nick, count));

/** One bit of the ciphertext, turned over. The frame still decodes and the
 * base64 is still base64; it is the AEAD tag that no longer holds. */
function flipOneBit(bytes: Uint8Array): Uint8Array {
  const corrupted = new Uint8Array(bytes);
  corrupted[0] = (corrupted[0] ?? 0) ^ 0x01;
  return corrupted;
}

beforeEach(() => {
  sessions = [];
  relay = startMaliciousRelay();
});

afterEach(() => {
  for (const session of sessions) session.close();
  relay.close();
});

describe("a relay that misbehaves", () => {
  it("drops a message", async () => {
    // The second line alice types, and nothing else: a relay that swallowed
    // the handshake would be a relay nobody could talk through at all, which
    // is not an interesting attack.
    relay.policy.onFrame = (raw, from) => {
      const frame = decodeFrame(raw);
      const dropped = from === "a" && frame.t === "msg" && frame.i === FIRST_TEXT_COUNTER + 1;
      return dropped ? null : raw;
    };

    const { alice, bob } = await pair();

    await alice.session.send("one");
    await until(() => bob.got.messages.length === 1);
    await alice.session.send("two");
    await alice.session.send("three");
    await until(() => bob.got.messages.length === 2);

    // The message that stepped over the hole is not evidence of a loss on its
    // own — a message that overtakes another arrives late rather than never —
    // so the count is said once the one after it has come and gone.
    await alice.session.send("four");
    await until(() => bob.got.gaps.length === 1);
    await settle();

    expect(bodiesSeenBy(bob)).toEqual(["one", "three", "four"]);
    expect(noticesSeenBy(bob)).toEqual(["⚠ 1 message from alice never arrived"]);
  });

  it("reorders two messages", async () => {
    const { alice, bob } = await pair();

    relay.policy.hold = true;
    await alice.session.send("one");
    await alice.session.send("two");
    await until(() => relay.held().length === 2);

    // Delivered back to front. The key for the message that was stepped over
    // is kept rather than discarded, which is what makes this cost nothing.
    relay.policy.hold = false;
    relay.release([1, 0]);
    await until(() => bob.got.messages.length === 2);
    await settle();

    // In the order the relay delivered them, deliberately: a payload is shown
    // the moment it opens, and nothing in `IncomingMessage` carries a counter
    // for the screen to re-sort by. What is under test is that reordering
    // inside the skip window costs the user nothing and says nothing.
    expect(bodiesSeenBy(bob)).toEqual(["two", "one"]);
    expect(bob.got.gaps).toEqual([]);
    expect(bob.got.decryptErrors).toEqual([]);
  });

  it("injects a frame", async () => {
    const { alice, bob } = await pair();

    await alice.session.send("one");
    await until(() => bob.got.messages.length === 1);

    // A frame the relay wrote itself, at the counter alice's next line will
    // carry. It holds no key, so the ciphertext is noise.
    const forged = msgFrame(HANDLE, FIRST_TEXT_COUNTER + 1, crypto.getRandomValues(new Uint8Array(64)));
    relay.inject(encodeFrame(forged), "b");
    await until(() => bob.got.decryptErrors.length === 1);

    // And it costs alice the line that would have carried that counter: the
    // key was spent opening the forgery and there is not a second one. Both
    // refusals are announced — the screen reads "could not open 2 messages" —
    // because the second of them is a message the user will never get to read.
    await alice.session.send("two");
    await until(() => bob.got.decryptErrors.length === 2);

    await alice.session.send("three");
    await until(() => bob.got.messages.length === 2);
    await settle();

    expect(bodiesSeenBy(bob)).toEqual(["one", "three"]);
    expect(bob.got.decryptErrors).toHaveLength(2);
  });

  it("replays a captured frame", async () => {
    const captured: string[] = [];
    relay.policy.onFrame = (raw, from) => {
      const frame = decodeFrame(raw);
      if (from === "a" && frame.t === "msg" && frame.i === FIRST_TEXT_COUNTER) captured.push(raw);
      return raw;
    };

    const { alice, bob } = await pair();

    await alice.session.send("one");
    await until(() => bob.got.messages.length === 1);

    const replayed = captured[0];
    if (replayed === undefined) throw new Error("the relay captured nothing to replay");

    // The same bytes a second time. A counter is serviced exactly once, so
    // the key that opened it no longer exists — which is what replaces a
    // replay window, a set of delivered messages, and any dependence on
    // either machine's clock.
    relay.inject(replayed, "b");
    await until(() => bob.got.decryptErrors.length === 1);
    await settle();

    // Nothing appeared twice, and the conversation carries on.
    expect(bodiesSeenBy(bob)).toEqual(["one"]);
    await alice.session.send("two");
    await until(() => bob.got.messages.length === 2);
    expect(bodiesSeenBy(bob)).toEqual(["one", "two"]);
    expect(bob.got.gaps).toEqual([]);
  });

  it("partitions the two clients", async () => {
    const { alice, bob } = await pair(QUICK_PRESENCE);

    const cutAt = Date.now();
    relay.policy.partition = "both";

    // Not on the first ping that failed to arrive: presence is said from the
    // peer's own payloads, and a whole expiry of silence is what ends it.
    expect(alice.got.gone).toBe(0);
    await until(() => alice.got.gone === 1 && bob.got.gone === 1);

    expect(Date.now() - cutAt).toBeGreaterThanOrEqual(QUICK_EXPIRY_MS);
  });

  it("corrupts a frame's bytes", async () => {
    relay.policy.onFrame = (raw, from) => {
      const frame = decodeFrame(raw);
      if (from !== "a" || frame.t !== "msg") return raw;

      // One line has its ciphertext turned over, the next is cut short on the
      // wire. The first fails the AEAD tag, the second never decodes at all.
      if (frame.i === FIRST_TEXT_COUNTER) {
        return encodeFrame(msgFrame(frame.h, frame.i, flipOneBit(fromBase64(frame.c))));
      }
      if (frame.i === FIRST_TEXT_COUNTER + 1) return raw.slice(0, raw.length - 5);

      return raw;
    };

    const { alice, bob } = await pair();

    await alice.session.send("one");
    await until(() => bob.got.decryptErrors.length === 1);
    await alice.session.send("two");
    await until(() => bob.got.decryptErrors.length === 2);

    // Neither crashed the client: the next line opens as though nothing had
    // happened.
    await alice.session.send("three");
    await until(() => bob.got.messages.length === 1);

    // The truncated frame took its counter with it — the chain never reached
    // it — so it is also counted as a message that never arrived once a later
    // one has stepped over it. The corrupted one is not: its counter was
    // serviced, and it was announced when it failed to open.
    await alice.session.send("four");
    await until(() => bob.got.gaps.length === 1);
    await settle();

    expect(bodiesSeenBy(bob)).toEqual(["three", "four"]);
    expect(bob.got.decryptErrors).toHaveLength(2);
    expect(noticesSeenBy(bob)).toEqual(["⚠ 1 message from alice never arrived"]);
  });
});
