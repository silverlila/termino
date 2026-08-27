/**
 * The relay's own tests: routing, the rate limiter, the connection caps, and
 * that it says nothing about anyone.
 *
 * A dependency that writes straight to fd 1 or 2 is invisible to a patched
 * `console`, so the silence cases assert against a spawned `src/main.ts serve`
 * rather than an in-process relay. Bun prints an exception that escapes a fetch
 * or socket handler with a stack trace, and answers 500 for a fetch handler that
 * threw — the frame, the handle and the sender's address are all in scope when
 * it does, which is what the `onError` and 429 cases exist to prevent.
 */
import { afterEach, beforeEach, describe, expect, it } from "bun:test";
import {
  decodeFrame,
  encodeFrame,
  helloFrame,
  msgFrame,
  subFrame,
  type Frame,
} from "../../shared/protocol/frame.ts";
import {
  fullBucket,
  IDLE_TIMEOUT_SECONDS,
  MAX_SUBSCRIBERS_PER_HANDLE,
  RATE_LIMIT_MESSAGES,
  RATE_LIMIT_WINDOW_MS,
  startRelay,
  takeToken,
  type RelayOptions,
} from "../../server/relay.ts";
import { portOf } from "../support/harness.ts";

const HANDLE = "63402012e8d78d978a4ab491cf2e5ae9";
const OTHER_HANDLE = "a1b2c3d4e5f60718293a4b5c6d7e8f90";
const PUBLIC_KEY = Uint8Array.from({ length: 32 }, (_, index) => index);
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

async function connect(port = portOf(relay)): Promise<TestClient> {
  const socket = new WebSocket(`ws://localhost:${port}/`);
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

/**
 * A connected client that has completed its subscription.
 *
 * A successful `sub` is answered with nothing at all — the relay says only what
 * it must — so this waits rather than watching for an acknowledgement. The wait
 * is what stops the *next* client's message racing ahead of this one's
 * subscription, which is a cross-socket ordering the relay does not promise.
 */
async function subscribed(handle = HANDLE, port = portOf(relay)): Promise<TestClient> {
  const client = await connect(port);
  client.send(subFrame(handle));
  await wait(25);
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
    const sent = msgFrame(HANDLE, 4, CIPHERTEXT);

    alice.send(sent);
    await until(() => framesOfType(bob, "msg").length === 1);

    const [forwarded] = framesOfType(bob, "msg");
    if (forwarded?.t !== "msg") throw new Error("expected a msg frame");

    expect(forwarded.c).toBe(sent.c);
    expect(forwarded.i).toBe(4);
    expect(forwarded.h).toBe(sent.h);
  });

  /**
   * A `hello` carries the key a session is built from, so where it goes is a
   * security property and not merely plumbing. The relay decides that from the
   * handle the *connection* subscribed to; the handle written inside the frame
   * buys the sender nothing at all. Both halves of that rule are here, because
   * the first alone cannot tell the two apart — a frame naming the handle it
   * was sent from routes identically under either.
   */
  describe("routes hello", () => {
    it("publishes it to the handle the connection joined, and never back to the sender", async () => {
      const alice = await subscribed(HANDLE);
      const bob = await subscribed(HANDLE);
      const stranger = await subscribed(OTHER_HANDLE);

      alice.send(helloFrame(HANDLE, PUBLIC_KEY));
      await until(() => framesOfType(bob, "hello").length === 1);
      await settle();

      const [forwarded] = framesOfType(bob, "hello");
      if (forwarded?.t !== "hello") throw new Error("expected a hello frame");
      expect(forwarded.k).toBe(helloFrame(HANDLE, PUBLIC_KEY).k);

      expect(framesOfType(stranger, "hello")).toHaveLength(0);
      // Never back to the sender: a client cannot be made to shake hands with
      // its own key by an honest relay.
      expect(framesOfType(alice, "hello")).toHaveLength(0);
    });

    it("refuses one naming another handle, so it reaches nobody on either", async () => {
      const sender = await subscribed(HANDLE);
      const roommate = await subscribed(HANDLE);
      const listener = await subscribed(OTHER_HANDLE);

      // Subscribed to one handle, naming the other. Refused rather than
      // rerouted: `hello` and `msg` get one rule, and a frame that says where
      // it would like to go is exactly the frame the routing rule exists to
      // ignore.
      sender.send(helloFrame(OTHER_HANDLE, PUBLIC_KEY));
      await until(() => framesOfType(sender, "err").length === 1);
      await settle();

      expect(framesOfType(sender, "err")).toEqual([{ v: 2, t: "err", code: "bad_frame" }]);
      // Nobody on the handle it was sent from, and nobody on the handle it
      // named.
      expect(framesOfType(roommate, "hello")).toHaveLength(0);
      expect(framesOfType(listener, "hello")).toHaveLength(0);
    });
  });

  it("does not echo a message back to its sender", async () => {
    const alice = await subscribed();
    await subscribed();

    alice.send(msgFrame(HANDLE, 0, CIPHERTEXT));
    await settle();

    expect(framesOfType(alice, "msg")).toHaveLength(0);
  });

  it("keeps channels separate", async () => {
    const alice = await subscribed(HANDLE);
    const stranger = await subscribed(OTHER_HANDLE);

    alice.send(msgFrame(HANDLE, 0, CIPHERTEXT));
    await settle();

    expect(framesOfType(stranger, "msg")).toHaveLength(0);
  });
});

describe("subscription", () => {
  it("drops a message sent before any subscribe, forwarding it to nobody", async () => {
    const listener = await subscribed();
    const unsubscribed = await connect();

    unsubscribed.send(msgFrame(HANDLE, 0, CIPHERTEXT));
    await until(() => unsubscribed.received.length > 0);
    await settle();

    expect(framesOfType(listener, "msg")).toHaveLength(0);
    expect(unsubscribed.received).toEqual([{ v: 2, t: "err", code: "not_subscribed" }]);
  });

  it("refuses to route a message into a channel the connection did not join", async () => {
    const alice = await subscribed(HANDLE);
    const stranger = await subscribed(OTHER_HANDLE);

    // A valid frame, but naming a handle this connection never subscribed to.
    stranger.send(msgFrame(HANDLE, 0, CIPHERTEXT));
    await until(() => framesOfType(stranger, "err").length === 1);
    await settle();

    expect(framesOfType(alice, "msg")).toHaveLength(0);
    expect(framesOfType(stranger, "err")).toEqual([{ v: 2, t: "err", code: "bad_frame" }]);
  });
});

describe("two participants and no more", () => {
  it("caps a handle at two connections", () => {
    // The number is the wire contract, not an implementation detail: a
    // conversation is between two people and the SAS compares one pair of keys.
    expect(MAX_SUBSCRIBERS_PER_HANDLE).toBe(2);
  });

  it("answers channel_full to a third subscriber and leaves the first two alone", async () => {
    const alice = await subscribed();
    const bob = await subscribed();
    const third = await subscribed();

    await until(() => framesOfType(third, "err").length === 1);
    await settle();

    expect(framesOfType(third, "err")).toEqual([{ v: 2, t: "err", code: "channel_full" }]);

    // Refused, not merely told: the third connection is in no channel, so a
    // message from it goes nowhere.
    third.send(msgFrame(HANDLE, 0, CIPHERTEXT));
    await settle();
    expect(framesOfType(alice, "msg")).toHaveLength(0);
    expect(framesOfType(bob, "msg")).toHaveLength(0);
  });

  it("frees the second place when somebody leaves", async () => {
    await subscribed();
    const bob = await subscribed();

    bob.close();
    await settle();

    const replacement = await subscribed();
    await settle();

    expect(framesOfType(replacement, "err")).toHaveLength(0);
  });

  it("lets a connection re-subscribe to the handle it is already on", async () => {
    const alice = await subscribed();
    await subscribed();

    alice.send(subFrame(HANDLE));
    await settle();

    // Counting the connection against its own place would refuse it, and a
    // client repeating its subscription is not a third party.
    expect(framesOfType(alice, "err")).toHaveLength(0);
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
      alice.send(msgFrame(HANDLE, sent, CIPHERTEXT));
    }
    await until(() => framesOfType(alice, "err").length === 1);
    await settle();

    expect(framesOfType(bob, "msg")).toHaveLength(MESSAGES_AFTER_SUBSCRIBING);
    expect(framesOfType(alice, "err")).toEqual([{ v: 2, t: "err", code: "rate_limited" }]);

    // The other connection has its own bucket and never hears about this.
    expect(framesOfType(bob, "err")).toHaveLength(0);

    bob.send(msgFrame(HANDLE, 0, CIPHERTEXT));
    await until(() => framesOfType(alice, "msg").length === 1);
    expect(framesOfType(bob, "err")).toHaveLength(0);
  });

  it("lets a limited sender speak again once the window has passed", async () => {
    const alice = await subscribed();
    const bob = await subscribed();

    for (let sent = 0; sent < MESSAGES_AFTER_SUBSCRIBING + 1; sent++) {
      alice.send(msgFrame(HANDLE, sent, CIPHERTEXT));
    }
    await until(() => framesOfType(alice, "err").length === 1);

    clock += RATE_LIMIT_WINDOW_MS;

    alice.send(msgFrame(HANDLE, 99, CIPHERTEXT));
    await until(() => framesOfType(bob, "msg").length === MESSAGES_AFTER_SUBSCRIBING + 1);

    expect(framesOfType(alice, "err")).toHaveLength(1);
  });

  it("charges subscriptions too, so handle churn cannot be made free", async () => {
    const mallory = await subscribed(HANDLE);

    // Alternating between two handles defeats the same-handle short circuit,
    // so every one of these is a subscription the relay has to service.
    for (let sent = 0; sent < MESSAGES_AFTER_SUBSCRIBING + 1; sent++) {
      mallory.send(subFrame(sent % 2 === 0 ? OTHER_HANDLE : HANDLE));
    }
    await until(() => framesOfType(mallory, "err").length === 1);
    await settle();

    expect(framesOfType(mallory, "err")).toEqual([{ v: 2, t: "err", code: "rate_limited" }]);
  });
});

describe("malformed input", () => {
  const rejected: Record<string, string> = {
    "text that is not JSON": "{not json",
    "an unsupported version": JSON.stringify({ v: 1, t: "sub", h: HANDLE }),
    "a handle that is not lowercase hex": JSON.stringify({ v: 2, t: "sub", h: "nope" }),
    "an unknown frame type": JSON.stringify({ v: 2, t: "shutdown" }),
    "a frame the relay itself originates": JSON.stringify({ v: 2, t: "err", code: "bad_frame" }),
    "the presence frame version 1 had": JSON.stringify({ v: 2, t: "presence", n: 2 }),
    "a JSON array": "[1,2,3]",
  };

  for (const [description, raw] of Object.entries(rejected)) {
    it(`answers bad_frame to ${description} without closing the connection`, async () => {
      const client = await subscribed();
      client.sendRaw(raw);
      await until(() => framesOfType(client, "err").length === 1);

      expect(framesOfType(client, "err")).toEqual([{ v: 2, t: "err", code: "bad_frame" }]);
      expect(client.isOpen()).toBe(true);
    });
  }

  it("rejects a frame over the size cap and keeps the connection usable", async () => {
    const alice = await subscribed();
    const bob = await subscribed();

    alice.sendRaw(encodeFrame(msgFrame(HANDLE, 0, new Uint8Array(70 * 1024))));
    await until(() => framesOfType(alice, "err").length === 1);

    expect(framesOfType(alice, "err")).toEqual([{ v: 2, t: "err", code: "bad_frame" }]);
    expect(framesOfType(bob, "msg")).toHaveLength(0);

    // Still a working connection afterwards.
    alice.send(msgFrame(HANDLE, 1, CIPHERTEXT));
    await until(() => framesOfType(bob, "msg").length === 1);
    expect(alice.isOpen()).toBe(true);
  });

  it("survives a burst of garbage and still delivers the message after it", async () => {
    const alice = await subscribed();
    const bob = await subscribed();

    for (const junk of ["", "null", "{}", '{"v":2}', " "]) alice.sendRaw(junk);
    alice.send(msgFrame(HANDLE, 0, CIPHERTEXT));

    await until(() => framesOfType(bob, "msg").length === 1);
    expect(alice.isOpen()).toBe(true);
  });

  it("rejects a message whose counter is not a whole number", async () => {
    const alice = await subscribed();
    const bob = await subscribed();

    alice.sendRaw(JSON.stringify({ v: 2, t: "msg", h: HANDLE, i: -1, c: "AAAA" }));
    await until(() => framesOfType(alice, "err").length === 1);

    expect(framesOfType(bob, "msg")).toHaveLength(0);
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

describe("writing nothing", () => {
  const MAIN = new URL("../../src/main.ts", import.meta.url).pathname;

  /** Accumulates a stream into a string as it arrives, so a test can wait for
   * the startup line and still see everything written after it. */
  async function drain(stream: ReadableStream<Uint8Array>, sink: { text: string }): Promise<void> {
    const decoder = new TextDecoder();
    for await (const chunk of stream) sink.text += decoder.decode(chunk, { stream: true });
  }

  it("writes nothing across a connection lifecycle", async () => {
    // Spawned rather than started in this process: a dependency writing
    // straight to the file descriptor bypasses any patched `console`, and what
    // an operator vouches for is the process, not a module.
    const child = Bun.spawn([process.execPath, "run", MAIN, "serve", "--port", "0"], {
      stdout: "pipe",
      stderr: "pipe",
      stdin: "ignore",
    });

    const out = { text: "" };
    const err = { text: "" };
    const drained = Promise.all([drain(child.stdout, out), drain(child.stderr, err)]);
    let port = 0;

    try {
      await until(() => out.text.includes("\n"), 10_000);
      port = Number(/ws:\/\/localhost:(\d+)/.exec(out.text)?.[1]);
      expect(port).toBeGreaterThan(0);

      const alice = await subscribed(HANDLE, port);
      const bob = await subscribed(HANDLE, port);

      alice.send(msgFrame(HANDLE, 0, CIPHERTEXT));
      await until(() => framesOfType(bob, "msg").length === 1);

      alice.sendRaw("{not json");
      await until(() => framesOfType(alice, "err").length === 1);

      // This relay runs on the real clock, so the window cannot be skipped
      // past: a malformed frame is refused before it is charged, leaving
      // alice three tokens of five, and these five exhaust them.
      for (let sent = 1; sent <= RATE_LIMIT_MESSAGES; sent++) {
        alice.send(msgFrame(HANDLE, sent, CIPHERTEXT));
      }
      await until(() =>
        alice.received.some((frame) => frame.t === "err" && frame.code === "rate_limited"),
      );

      alice.close();
      bob.close();
      await settle();
    } finally {
      child.kill();
      await child.exited;
      await drained;
    }

    expect(out.text).toBe(`termino relay listening on ws://localhost:${port}\n`);
    expect(err.text).toBe("");
  }, 20_000);

  it("hands an unexpected failure to onError rather than throwing it at Bun", async () => {
    // An exception escaping the message handler is printed by Bun with a stack
    // trace, and the frame and the sender are in scope when it is. There is no
    // way to make the relay fail from the wire — that is the point of the
    // parser — so the injected clock stands in for whatever unanticipated
    // failure a future change brings.
    let failures = 0;
    let clockBroken = false;
    const server = startRelay({
      port: 0,
      now: () => {
        if (clockBroken) throw new Error("the clock is unavailable");
        return clock;
      },
      onError: () => {
        failures += 1;
      },
    });

    try {
      const client = await subscribed(HANDLE, portOf(server));
      clockBroken = true;

      client.send(msgFrame(HANDLE, 0, CIPHERTEXT));
      await until(() => framesOfType(client, "err").length === 1);
      clockBroken = false;

      expect(failures).toBe(1);
      expect(framesOfType(client, "err")).toEqual([{ v: 2, t: "err", code: "bad_frame" }]);
      expect(client.isOpen()).toBe(true);
    } finally {
      server.stop(true);
    }
  });

  it("refuses a connection it cannot serve rather than throwing at Bun", async () => {
    let failures = 0;
    const server = startRelay({
      port: 0,
      now: () => {
        throw new Error("the clock is unavailable");
      },
      onError: () => {
        failures += 1;
      },
    });

    try {
      const port = portOf(server);

      expect((await fetch(`http://127.0.0.1:${port}/`)).status).toBe(429);
      await expect(openSocket(port)).rejects.toThrow("refused");

      expect(failures).toBe(2);
    } finally {
      server.stop(true);
    }
  });

  it("keeps answering the sender when the caller's onError throws", async () => {
    let clockBroken = false;
    const server = startRelay({
      port: 0,
      now: () => {
        if (clockBroken) throw new Error("the clock is unavailable");
        return clock;
      },
      onError: () => {
        throw new Error("the reporter is broken too");
      },
    });

    try {
      const client = await subscribed(HANDLE, portOf(server));
      clockBroken = true;

      client.send(msgFrame(HANDLE, 0, CIPHERTEXT));
      await until(() => framesOfType(client, "err").length === 1);
      clockBroken = false;

      expect(framesOfType(client, "err")).toEqual([{ v: 2, t: "err", code: "bad_frame" }]);
      expect(client.isOpen()).toBe(true);

      const listener = await subscribed(HANDLE, portOf(server));
      client.send(msgFrame(HANDLE, 1, CIPHERTEXT));
      await until(() => framesOfType(listener, "msg").length === 1);
    } finally {
      server.stop(true);
    }
  });
});
