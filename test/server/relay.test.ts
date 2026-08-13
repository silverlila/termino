import { afterEach, beforeEach, describe, expect, it } from "bun:test";
import {
  decodeFrame,
  encodeFrame,
  msgFrame,
  subFrame,
  toBase64,
  type Frame,
} from "../../shared/protocol/frame.ts";
import {
  fullBucket,
  IDLE_TIMEOUT_SECONDS,
  RATE_LIMIT_MESSAGES,
  RATE_LIMIT_WINDOW_MS,
  startRelay,
  takeToken,
  type RelayOptions,
} from "../../server/relay.ts";
import { portOf } from "../support/harness.ts";

const HANDLE = "63402012e8d78d978a4ab491cf2e5ae9";
const OTHER_HANDLE = "a1b2c3d4e5f60718293a4b5c6d7e8f90";
const NONCE = Uint8Array.from({ length: 12 }, (_, index) => index);
const CIPHERTEXT = new TextEncoder().encode("opaque to the relay");

/** The relay's clock, advanced by hand. Test *timing* still uses the real one. */
let clock = 0;
let relay: ReturnType<typeof startRelay>;
let clients: TestClient[] = [];
let cappedRelays: ReturnType<typeof startRelay>[] = [];
let rawSockets: WebSocket[] = [];

interface TestClient {
  received: Frame[];
  send(frame: Frame): void;
  sendRaw(raw: string): void;
  isOpen(): boolean;
  close(): void;
}

const wait = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

/** Waits for a condition, then settles briefly so that anything which should
 * NOT have arrived has had its chance to. */
async function until(condition: () => boolean, timeoutMs = 2000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (!condition()) {
    if (Date.now() > deadline) throw new Error("timed out waiting for the relay");
    await wait(5);
  }
}

/** Long enough for anything in flight to land. Used before asserting absence. */
const settle = () => wait(80);

async function connect(): Promise<TestClient> {
  const socket = new WebSocket(`ws://localhost:${relay.port}/`);
  const received: Frame[] = [];

  socket.addEventListener("message", (event) => received.push(decodeFrame(String(event.data))));
  await new Promise<void>((resolve) => socket.addEventListener("open", () => resolve()));

  const client: TestClient = {
    received,
    send: (frame) => socket.send(encodeFrame(frame)),
    sendRaw: (raw) => socket.send(raw),
    isOpen: () => socket.readyState === WebSocket.OPEN,
    close: () => socket.close(),
  };

  clients.push(client);
  return client;
}

/** A connected client that has completed its subscription. */
async function subscribed(handle = HANDLE): Promise<TestClient> {
  const client = await connect();
  client.send(subFrame(handle));
  await until(() => client.received.some((frame) => frame.t === "presence"));
  return client;
}

const framesOfType = (client: TestClient, type: Frame["t"]) =>
  client.received.filter((frame) => frame.t === type);

/**
 * A second relay with its caps turned down: proving a cap of 1000 holds by
 * opening 1001 sockets is not a test. Stopped in `afterEach` alongside the
 * shared one.
 */
function startCapped(caps: Pick<RelayOptions, "maxConnections" | "maxConnectionsPerIp">): number {
  const server = startRelay({ port: 0, now: () => clock, ...caps });
  cappedRelays.push(server);
  return portOf(server);
}

/**
 * Opens a socket and waits for it to be established, so it is counted by the
 * time the next assertion runs; rejects if the relay refuses the handshake.
 * Loopback is spelled `127.0.0.1` rather than `localhost` throughout the
 * connection-limit cases, because `localhost` may resolve to `::1` and the
 * per-source cap keys on the address the connection actually arrived from.
 */
async function openSocket(port: number, path = "/"): Promise<WebSocket> {
  const socket = new WebSocket(`ws://127.0.0.1:${port}${path}`);
  rawSockets.push(socket);

  await new Promise<void>((resolve, reject) => {
    socket.addEventListener("open", () => resolve());
    // A refused handshake surfaces as a close with 1002 ("Expected 101 status
    // code"), not as an error event — Bun only raises `error` for a socket
    // that was established and then broke.
    socket.addEventListener("close", () => reject(new Error("the relay refused the connection")));
  });
  return socket;
}

/** Polls until an ordinary HTTP request gets `status`, so a test can wait for
 * a slot to come back without guessing how long a close takes to land. */
async function untilStatus(port: number, status: number, timeoutMs = 2000): Promise<void> {
  const deadline = Date.now() + timeoutMs;

  for (;;) {
    const response = await fetch(`http://127.0.0.1:${port}/`);
    if (response.status === status) return;
    if (Date.now() > deadline) throw new Error(`the relay never answered ${status}`);
    await wait(5);
  }
}

beforeEach(() => {
  clock = 0;
  clients = [];
  cappedRelays = [];
  rawSockets = [];
  relay = startRelay({ port: 0, now: () => clock });
});

afterEach(() => {
  for (const client of clients) client.close();
  for (const socket of rawSockets) socket.close();
  for (const server of cappedRelays) server.stop(true);
  relay.stop(true);
});

describe("token bucket", () => {
  it("allows a full window's worth of messages", () => {
    let bucket = fullBucket(0);

    for (let sent = 0; sent < RATE_LIMIT_MESSAGES; sent++) {
      const result = takeToken(bucket, 0);
      expect(result.allowed).toBe(true);
      bucket = result.bucket;
    }

    expect(takeToken(bucket, 0).allowed).toBe(false);
  });

  it("refills over the window", () => {
    let bucket = fullBucket(0);
    for (let sent = 0; sent < RATE_LIMIT_MESSAGES; sent++) bucket = takeToken(bucket, 0).bucket;

    expect(takeToken(bucket, RATE_LIMIT_WINDOW_MS).allowed).toBe(true);
  });

  it("refills partially, part way through the window", () => {
    let bucket = fullBucket(0);
    for (let sent = 0; sent < RATE_LIMIT_MESSAGES; sent++) bucket = takeToken(bucket, 0).bucket;

    // One fifth of the window buys back exactly one message.
    expect(takeToken(bucket, RATE_LIMIT_WINDOW_MS / RATE_LIMIT_MESSAGES).allowed).toBe(true);
  });

  it("never accumulates more than a full bucket, however long the silence", () => {
    const rested = takeToken(fullBucket(0), RATE_LIMIT_WINDOW_MS * 1000).bucket;
    expect(rested.tokens).toBe(RATE_LIMIT_MESSAGES - 1);
  });

  it("does not refill if the clock goes backwards", () => {
    let bucket = fullBucket(1000);
    for (let sent = 0; sent < RATE_LIMIT_MESSAGES; sent++) bucket = takeToken(bucket, 1000).bucket;

    expect(takeToken(bucket, 0).allowed).toBe(false);
  });
});

describe("forwarding", () => {
  it("forwards the ciphertext byte for byte", async () => {
    const alice = await subscribed();
    const bob = await subscribed();
    const sent = msgFrame(HANDLE, NONCE, CIPHERTEXT);

    alice.send(sent);
    await until(() => framesOfType(bob, "msg").length === 1);

    const [forwarded] = framesOfType(bob, "msg");
    if (forwarded?.t !== "msg") throw new Error("expected a msg frame");

    expect(forwarded.c).toBe(sent.c);
    expect(forwarded.n).toBe(sent.n);
    expect(forwarded.h).toBe(sent.h);
  });

  it("does not echo a message back to its sender", async () => {
    const alice = await subscribed();
    await subscribed();

    alice.send(msgFrame(HANDLE, NONCE, CIPHERTEXT));
    await settle();

    expect(framesOfType(alice, "msg")).toHaveLength(0);
  });

  it("keeps channels separate", async () => {
    const alice = await subscribed(HANDLE);
    const stranger = await subscribed(OTHER_HANDLE);

    alice.send(msgFrame(HANDLE, NONCE, CIPHERTEXT));
    await settle();

    expect(framesOfType(stranger, "msg")).toHaveLength(0);
  });
});

describe("subscription", () => {
  it("drops a message sent before any subscribe, forwarding it to nobody", async () => {
    const listener = await subscribed();
    const unsubscribed = await connect();

    unsubscribed.send(msgFrame(HANDLE, NONCE, CIPHERTEXT));
    await until(() => unsubscribed.received.length > 0);
    await settle();

    expect(framesOfType(listener, "msg")).toHaveLength(0);
    expect(unsubscribed.received).toEqual([{ v: 1, t: "err", code: "not_subscribed" }]);
  });

  it("refuses to route a message into a channel the connection did not join", async () => {
    const alice = await subscribed(HANDLE);
    const stranger = await subscribed(OTHER_HANDLE);

    // A valid frame, but naming a handle this connection never subscribed to.
    stranger.send(msgFrame(HANDLE, NONCE, CIPHERTEXT));
    await until(() => framesOfType(stranger, "err").length === 1);
    await settle();

    expect(framesOfType(alice, "msg")).toHaveLength(0);
    expect(framesOfType(stranger, "err")).toEqual([{ v: 1, t: "err", code: "bad_frame" }]);
  });
});

describe("presence", () => {
  it("tells the first subscriber that a second has arrived", async () => {
    const alice = await subscribed();
    expect(framesOfType(alice, "presence")).toEqual([{ v: 1, t: "presence", n: 1 }]);

    await subscribed();
    await until(() => framesOfType(alice, "presence").length === 2);

    expect(framesOfType(alice, "presence")[1]).toEqual({ v: 1, t: "presence", n: 2 });
  });

  it("announces a departure to whoever is left", async () => {
    const alice = await subscribed();
    const bob = await subscribed();
    await until(() => framesOfType(alice, "presence").length === 2);

    bob.close();
    await until(() => framesOfType(alice, "presence").length === 3);

    expect(framesOfType(alice, "presence")[2]).toEqual({ v: 1, t: "presence", n: 1 });
  });

  it("counts subscribers per handle, not across the relay", async () => {
    const alice = await subscribed(HANDLE);
    await subscribed(OTHER_HANDLE);
    await settle();

    expect(framesOfType(alice, "presence")).toEqual([{ v: 1, t: "presence", n: 1 }]);
  });
});

describe("rate limiting", () => {
  /** The bucket covers every frame the relay acts on, and subscribing is one
   * of them — so a freshly subscribed connection has spent a token already. */
  const MESSAGES_AFTER_SUBSCRIBING = RATE_LIMIT_MESSAGES - 1;

  it("drops the message past the window's budget and tells only that sender", async () => {
    const alice = await subscribed();
    const bob = await subscribed();

    for (let sent = 0; sent < MESSAGES_AFTER_SUBSCRIBING + 1; sent++) {
      alice.send(msgFrame(HANDLE, NONCE, CIPHERTEXT));
    }
    await until(() => framesOfType(alice, "err").length === 1);
    await settle();

    expect(framesOfType(bob, "msg")).toHaveLength(MESSAGES_AFTER_SUBSCRIBING);
    expect(framesOfType(alice, "err")).toEqual([{ v: 1, t: "err", code: "rate_limited" }]);

    // The other connection has its own bucket and never hears about this.
    expect(framesOfType(bob, "err")).toHaveLength(0);

    bob.send(msgFrame(HANDLE, NONCE, CIPHERTEXT));
    await until(() => framesOfType(alice, "msg").length === 1);
    expect(framesOfType(bob, "err")).toHaveLength(0);
  });

  it("lets a limited sender speak again once the window has passed", async () => {
    const alice = await subscribed();
    const bob = await subscribed();

    for (let sent = 0; sent < MESSAGES_AFTER_SUBSCRIBING + 1; sent++) {
      alice.send(msgFrame(HANDLE, NONCE, CIPHERTEXT));
    }
    await until(() => framesOfType(alice, "err").length === 1);

    clock += RATE_LIMIT_WINDOW_MS;

    alice.send(msgFrame(HANDLE, NONCE, CIPHERTEXT));
    await until(() => framesOfType(bob, "msg").length === MESSAGES_AFTER_SUBSCRIBING + 1);

    expect(framesOfType(alice, "err")).toHaveLength(1);
  });

  it("charges subscriptions too, so handle churn cannot flood a channel", async () => {
    await subscribed(HANDLE);
    const mallory = await subscribed(HANDLE);

    // Alternating between two handles defeats the same-handle short circuit,
    // and every accepted subscribe announces presence to both the handle being
    // left and the one being joined. Uncharged, that turns a small frame into
    // a fan-out across every other member of the channel.
    for (let sent = 0; sent < MESSAGES_AFTER_SUBSCRIBING + 1; sent++) {
      mallory.send(subFrame(sent % 2 === 0 ? OTHER_HANDLE : HANDLE));
    }
    await until(() => framesOfType(mallory, "err").length === 1);
    await settle();

    expect(framesOfType(mallory, "err")).toEqual([{ v: 1, t: "err", code: "rate_limited" }]);
  });
});

describe("malformed input", () => {
  const rejected: Record<string, string> = {
    "text that is not JSON": "{not json",
    "an unsupported version": JSON.stringify({ v: 2, t: "sub", h: HANDLE }),
    "a handle that is not lowercase hex": JSON.stringify({ v: 1, t: "sub", h: "nope" }),
    "an unknown frame type": JSON.stringify({ v: 1, t: "shutdown" }),
    "a frame the relay itself originates": JSON.stringify({ v: 1, t: "presence", n: 99 }),
    "a JSON array": "[1,2,3]",
  };

  for (const [description, raw] of Object.entries(rejected)) {
    it(`answers bad_frame to ${description} without closing the connection`, async () => {
      const client = await subscribed();
      client.sendRaw(raw);
      await until(() => framesOfType(client, "err").length === 1);

      expect(framesOfType(client, "err")).toEqual([{ v: 1, t: "err", code: "bad_frame" }]);
      expect(client.isOpen()).toBe(true);
    });
  }

  it("rejects a frame over 64 KiB and keeps the connection usable", async () => {
    const alice = await subscribed();
    const bob = await subscribed();

    alice.sendRaw(encodeFrame(msgFrame(HANDLE, NONCE, new Uint8Array(70 * 1024))));
    await until(() => framesOfType(alice, "err").length === 1);

    expect(framesOfType(alice, "err")).toEqual([{ v: 1, t: "err", code: "bad_frame" }]);
    expect(framesOfType(bob, "msg")).toHaveLength(0);

    // Still a working connection afterwards.
    alice.send(msgFrame(HANDLE, NONCE, CIPHERTEXT));
    await until(() => framesOfType(bob, "msg").length === 1);
    expect(alice.isOpen()).toBe(true);
  });

  it("survives a burst of garbage and still delivers the message after it", async () => {
    const alice = await subscribed();
    const bob = await subscribed();

    for (const junk of ["", "null", "{}", '{"v":1}', " "]) alice.sendRaw(junk);
    alice.send(msgFrame(HANDLE, NONCE, CIPHERTEXT));

    await until(() => framesOfType(bob, "msg").length === 1);
    expect(alice.isOpen()).toBe(true);
  });
});

describe("http requests", () => {
  it("refuses a plain http request rather than serving anything", async () => {
    const response = await fetch(`http://localhost:${relay.port}/`);
    expect(response.status).toBe(426);
  });
});

describe("connection limits", () => {
  /** Every refusal answers 429, never merely "some 4xx": a request that is not
   * an upgrade already gets 426, so a `>= 400` assertion would pass against a
   * relay with no caps at all. */
  const REFUSED = 429;

  it("refuses a connection beyond the per-IP cap", async () => {
    const port = startCapped({ maxConnections: 100, maxConnectionsPerIp: 2 });
    await openSocket(port);
    await openSocket(port);

    // The global cap is fifty times higher, so only the per-IP one can refuse.
    expect((await fetch(`http://127.0.0.1:${port}/`)).status).toBe(REFUSED);
    await expect(openSocket(port)).rejects.toThrow("refused");
  });

  it("refuses a connection beyond the global cap", async () => {
    const port = startCapped({ maxConnections: 2, maxConnectionsPerIp: 10 });
    await openSocket(port);
    await openSocket(port);

    // Every test connection comes from one address, so the per-IP cap is set
    // above the global one: a refusal here can only be the global cap.
    expect((await fetch(`http://127.0.0.1:${port}/`)).status).toBe(REFUSED);
    await expect(openSocket(port)).rejects.toThrow("refused");
  });

  it("frees the slot when a connection closes", async () => {
    const port = startCapped({ maxConnections: 100, maxConnectionsPerIp: 1 });
    const first = await openSocket(port);
    expect((await fetch(`http://127.0.0.1:${port}/`)).status).toBe(REFUSED);

    first.close();
    await untilStatus(port, 426);

    // 426 means the cap let the request through and it was merely not an
    // upgrade — the slot came back rather than leaking.
    await openSocket(port);
  });

  it("refuses an upgrade on a path other than /", async () => {
    expect((await fetch(`http://127.0.0.1:${relay.port}/admin`)).status).toBe(REFUSED);
    await expect(openSocket(portOf(relay), "/admin")).rejects.toThrow("refused");
  });

  it("refuses an upgrade carrying an Origin header", async () => {
    const response = await fetch(`http://127.0.0.1:${relay.port}/`, {
      headers: { origin: "https://a-browser-page.example" },
    });

    expect(response.status).toBe(REFUSED);
  });

  it("configures a 120 second idle timeout", () => {
    // Bun's own default is 120 seconds, so an idle connection behaves the same
    // whether or not the relay sets it — there is nothing to observe, and the
    // constant is the assertion. It exists so the value stops moving with the
    // Bun version.
    expect(IDLE_TIMEOUT_SECONDS).toBe(120);
  });
});

describe("nonce and ciphertext validation", () => {
  it("rejects a message whose nonce is the wrong length", async () => {
    const alice = await subscribed();
    const bob = await subscribed();

    alice.sendRaw(
      JSON.stringify({ v: 1, t: "msg", h: HANDLE, n: toBase64(new Uint8Array(8)), c: "AAAA" }),
    );
    await until(() => framesOfType(alice, "err").length === 1);

    expect(framesOfType(bob, "msg")).toHaveLength(0);
  });
});
