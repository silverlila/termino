import { afterEach, beforeEach, describe, expect, it } from "bun:test";
import { bytesToHex } from "@noble/hashes/utils.js";
import { deriveChannelKeys } from "../../src/crypto/derive.ts";
import { loadOrCreateIdentity, type Identity } from "../../src/crypto/identity.ts";
import { encodeFrame, subFrame } from "../../src/protocol/frame.ts";
import { sealMessage } from "../../src/protocol/message.ts";
import { removeTempDirs, startTestRelay, tempDir, wait, type TestRelay } from "../support/harness.ts";
import {
  startSession,
  type ConnectionState,
  type IncomingMessage,
  type Session,
  type SessionHandlers,
  type TrustEvent,
} from "../../src/client/session.ts";

const CHANNEL_NAME = "stage-five";
const PASSWORD = "correct horse battery staple";
const WRONG_PASSWORD = "incorrect horse battery staple";

// Derived once: argon2id is deliberately expensive, and these are the only two
// derivations the whole file needs.
const CHANNEL = deriveChannelKeys(CHANNEL_NAME, PASSWORD);
const WRONG_CHANNEL = deriveChannelKeys(CHANNEL_NAME, WRONG_PASSWORD);

let relay: TestRelay;
let sessions: Session[] = [];

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
  presence: number[];
  trust: TrustEvent[];
  decryptErrors: Error[];
  connection: ConnectionState[];
}

function recorder(): { handlers: SessionHandlers; got: Recorded } {
  const got: Recorded = {
    messages: [],
    presence: [],
    trust: [],
    decryptErrors: [],
    connection: [],
  };

  return {
    got,
    handlers: {
      onMessage: (message) => got.messages.push(message),
      onPresence: (count) => got.presence.push(count),
      onTrustEvent: (event) => got.trust.push(event),
      onDecryptError: (error) => got.decryptErrors.push(error),
      onConnectionChange: (state) => got.connection.push(state),
    },
  };
}

interface Peer {
  session: Session;
  identity: Identity;
  got: Recorded;
}

async function joinAs(
  nick: string,
  keys = CHANNEL,
  url = relay.url,
): Promise<Peer> {
  const identity = loadOrCreateIdentity(tempDir(`id-${nick}`));
  const { handlers, got } = recorder();

  const session = await startSession({
    keys,
    nick,
    identity,
    relayUrl: url,
    handlers,
    terminoDir: tempDir(`trust-${nick}`),
  });

  sessions.push(session);
  return { session, identity, got };
}

beforeEach(() => {
  sessions = [];
  relay = startTestRelay();
});

afterEach(() => {
  for (const session of sessions) session.close();
  relay.server.stop(true);
  removeTempDirs();
});

describe("two people in a channel", () => {
  it("delivers a message decrypted and signature-verified", async () => {
    const alice = await joinAs("alice");
    const bob = await joinAs("bob");
    await until(() => alice.got.presence.includes(2));

    await alice.session.send("shipping it now");
    await until(() => bob.got.messages.length === 1);

    const [received] = bob.got.messages;
    expect(received?.body).toBe("shipping it now");
    expect(received?.nick).toBe("alice");
    // openMessage throws unless the signature verifies, so arrival proves it;
    // this pins down *whose* key it verified against.
    expect(received?.from).toBe(alice.identity.publicKeyHex);
  });

  it("tells the first arrival that a second has joined", async () => {
    const alice = await joinAs("alice");
    const bob = await joinAs("bob");

    await until(() => bob.got.presence.length > 0);
    expect(bob.got.presence[0]).toBe(2);
    await until(() => alice.got.presence.includes(2));
  });

  it("does not deliver a sender their own message back", async () => {
    const alice = await joinAs("alice");
    const bob = await joinAs("bob");
    await until(() => alice.got.presence.includes(2));

    const sent = await alice.session.send("shipping it now");
    await until(() => bob.got.messages.length === 1);
    await settle();

    expect(alice.got.messages).toHaveLength(0);
    // send() hands the message back so the sender can display its own traffic.
    expect(sent.body).toBe("shipping it now");
    expect(sent.from).toBe(alice.identity.publicKeyHex);
  });

  it("keeps messages in the order they were sent", async () => {
    const alice = await joinAs("alice");
    const bob = await joinAs("bob");
    await until(() => alice.got.presence.includes(2));

    for (const body of ["first", "second", "third"]) await alice.session.send(body);
    await until(() => bob.got.messages.length === 3);

    expect(bob.got.messages.map((message) => message.body)).toEqual([
      "first",
      "second",
      "third",
    ]);
  });

  it("reports the connection lifecycle", async () => {
    const alice = await joinAs("alice");
    expect(alice.got.connection).toEqual(["connecting", "open"]);

    alice.session.close();
    await until(() => alice.got.connection.includes("closed"));
  });
});

describe("someone with the wrong password", () => {
  it("never sees a message, even after a confirmed exchange between the others", async () => {
    const alice = await joinAs("alice");
    const bob = await joinAs("bob");
    const eve = await joinAs("eve", WRONG_CHANNEL);
    await until(() => alice.got.presence.includes(2));

    await alice.session.send("shipping it now");
    // Assert absence only after the exchange is known to have completed.
    await until(() => bob.got.messages.length === 1);
    await settle();

    expect(eve.got.messages).toHaveLength(0);
    expect(eve.got.decryptErrors).toHaveLength(0);
    // The wrong password produces a different handle, so eve is not even in
    // the same channel — the relay never sends her anything to fail on.
    expect(eve.session.handle).not.toBe(alice.session.handle);
  });
});

describe("someone on the right handle with the wrong key", () => {
  it("receives the frame and fails to open it", async () => {
    const alice = await joinAs("alice");
    const bob = await joinAs("bob");
    // Unreachable through a password — handle and message key always derive
    // together — so it is constructed directly.
    const mallory = await joinAs("mallory", {
      handle: CHANNEL.handle,
      msgKey: new Uint8Array(32).fill(42),
    });
    await until(() => alice.got.presence.includes(3));

    await alice.session.send("shipping it now");
    await until(() => bob.got.messages.length === 1);
    await until(() => mallory.got.decryptErrors.length === 1);
    await settle();

    expect(mallory.got.messages).toHaveLength(0);
    expect(mallory.got.decryptErrors).toHaveLength(1);
  });
});

describe("impersonation inside a channel", () => {
  it("rejects a message whose signature does not match the key it claims", async () => {
    const alice = await joinAs("alice");
    const bob = await joinAs("bob");
    await until(() => alice.got.presence.includes(2));

    // Mallory holds the channel password, so she can encrypt. She cannot sign
    // as alice. This is the whole reason device keys exist.
    const mallory = loadOrCreateIdentity(tempDir("id-mallory"));
    const forged = await sealMessage({
      msgKey: CHANNEL.msgKey,
      handle: CHANNEL.handle,
      payload: {
        from: alice.identity.publicKeyHex,
        nick: "alice",
        body: "transfer the funds",
        ts: 1786531200000,
      },
      secretKey: mallory.secretKey,
    });

    const socket = new WebSocket(relay.url);
    await new Promise<void>((resolve) => socket.addEventListener("open", () => resolve()));
    socket.send(encodeFrame(subFrame(CHANNEL.handle)));
    socket.send(encodeFrame(forged));

    await until(() => bob.got.decryptErrors.length === 1);
    await settle();

    expect(bob.got.messages).toHaveLength(0);
    socket.close();
  });
});

describe("trust on first use across a live channel", () => {
  it("reports a first sighting as NEW and the next as KNOWN", async () => {
    const alice = await joinAs("alice");
    const bob = await joinAs("bob");
    await until(() => alice.got.presence.includes(2));

    await alice.session.send("first");
    await until(() => bob.got.messages.length === 1);
    await alice.session.send("second");
    await until(() => bob.got.messages.length === 2);

    expect(bob.got.messages.map((message) => message.trust)).toEqual(["NEW", "KNOWN"]);
    expect(bob.got.trust).toEqual([
      { nick: "alice", pubkey: alice.identity.publicKeyHex, state: "NEW" },
    ]);
  });

  it("persists what it saw, so the store outlives the session", async () => {
    const alice = await joinAs("alice");
    const bob = await joinAs("bob");
    await until(() => alice.got.presence.includes(2));

    await alice.session.send("shipping it now");
    await until(() => bob.got.messages.length === 1);

    expect(bob.session.trustRecords().alice?.pubkey).toBe(alice.identity.publicKeyHex);
    expect(bob.session.trustRecords().alice?.verified).toBe(false);
  });

  it("raises CHANGED when a nickname arrives with a second key", async () => {
    const alice = await joinAs("alice");
    const bob = await joinAs("bob");
    await until(() => alice.got.presence.includes(2));

    await alice.session.send("it is me");
    await until(() => bob.got.messages.length === 1);

    // A different device claiming the same nickname.
    const impostor = await joinAs("alice", CHANNEL);
    await impostor.session.send("no, it is me");
    await until(() => bob.got.messages.length === 2);

    expect(bob.got.messages[1]?.trust).toBe("CHANGED");
    expect(bob.got.trust.map((event) => event.state)).toEqual(["NEW", "CHANGED"]);
  });
});

describe("what the relay actually receives", () => {
  interface Wiretap {
    url: string;
    received: string[];
    stop(): void;
  }

  interface Pipe {
    upstream: WebSocket | null;
    pending: string[];
  }

  /** Sits between the client and the relay and records every byte travelling
   * towards the relay, so the assertions below are about what was really sent
   * rather than about what the client meant to send. */
  function startWiretap(targetPort: number): Wiretap {
    const received: string[] = [];

    const proxy = Bun.serve<Pipe, {}>({
      port: 0,
      fetch(request, server) {
        if (server.upgrade(request, { data: { upstream: null, pending: [] } })) return undefined;
        return new Response("websocket only", { status: 426 });
      },
      websocket: {
        open(ws) {
          const upstream = new WebSocket(`ws://localhost:${targetPort}/`);
          upstream.addEventListener("open", () => {
            for (const text of ws.data.pending) upstream.send(text);
            ws.data.pending = [];
          });
          upstream.addEventListener("message", (event) => ws.send(String(event.data)));
          ws.data.upstream = upstream;
        },
        message(ws, raw) {
          const text = String(raw);
          received.push(text);

          const upstream = ws.data.upstream;
          if (upstream !== null && upstream.readyState === WebSocket.OPEN) upstream.send(text);
          else ws.data.pending.push(text);
        },
        close(ws) {
          ws.data.upstream?.close();
        },
      },
    });

    return {
      url: `ws://localhost:${proxy.port}/`,
      received,
      stop: () => proxy.stop(true),
    };
  }

  it("sees only a handle and an opaque blob — never the password or a private key", async () => {
    const wiretap = startWiretap(relay.port);

    try {
      const alice = await joinAs("alice", CHANNEL, wiretap.url);
      const bob = await joinAs("bob", CHANNEL, wiretap.url);
      await until(() => alice.got.presence.includes(2));

      await alice.session.send("shipping it now");
      await until(() => bob.got.messages.length === 1);
      await settle();

      expect(wiretap.received.length).toBeGreaterThan(0);

      for (const raw of wiretap.received) {
        const frame = JSON.parse(raw);

        // The outer frame carries these keys and nothing else. In particular
        // there is no `sig`, no `nick`, and no public key.
        const expectedKeys = frame.t === "msg" ? ["c", "h", "n", "t", "v"] : ["h", "t", "v"];
        expect(Object.keys(frame).sort()).toEqual(expectedKeys);

        // Requirements 2 and 6: neither of these is ever transmitted.
        expect(raw).not.toContain(PASSWORD);
        expect(raw).not.toContain(bytesToHex(alice.identity.secretKey));
        expect(raw).not.toContain(bytesToHex(bob.identity.secretKey));
        expect(raw).not.toContain("shipping it now");
      }

      // And the message really did travel: a msg frame was among them.
      expect(wiretap.received.some((raw) => JSON.parse(raw).t === "msg")).toBe(true);
    } finally {
      wiretap.stop();
    }
  });
});
