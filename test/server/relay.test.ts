/**
 * The Bun relay's own tests: what only it has — the per-address and global connection
 * caps, the injectable clock, the idle timeout — and that it says nothing about anyone.
 * Everything a relay must do whoever runs it is in test/support/relay-contract.ts, run
 * here against this relay and in cloudflare/worker.test.ts against the other.
 *
 * A dependency that writes straight to fd 1 or 2 is invisible to a patched `console`,
 * so the silence cases assert against a spawned `src/main.ts serve` rather than an
 * in-process relay. Bun prints an exception that escapes a fetch or socket handler with
 * a stack trace, and answers 500 for a fetch handler that threw — the frame, the handle
 * and the sender's address are all in scope when it does, which is what the `onError`
 * and 429 cases exist to prevent.
 */
import { afterEach, beforeEach, describe, expect, it } from "bun:test";
import {
  decodeFrame,
  encodeFrame,
  msgFrame,
  subFrame,
  type Frame,
} from "../../shared/protocol/frame.ts";
import {
  IDLE_TIMEOUT_SECONDS,
  RATE_LIMIT_MESSAGES,
  RATE_LIMIT_WINDOW_MS,
} from "../../server/channel.ts";
import { startRelay, type RelayOptions } from "../../server/relay.ts";
import { portOf } from "../support/harness.ts";
import {
  framesOfType,
  openSocket as openUrl,
  REFUSED,
  relayContract,
  settle,
  until,
  wait,
  type TestClient,
} from "../support/relay-contract.ts";

const HANDLE = "63402012e8d78d978a4ab491cf2e5ae9";
const CIPHERTEXT = new TextEncoder().encode("opaque to the relay");

/** The relay's clock, advanced by hand. Test *timing* still uses the real one. */
let clock = 0;
let relay: ReturnType<typeof startRelay>;
let clients: TestClient[] = [];
let cappedRelays: ReturnType<typeof startRelay>[] = [];
let rawSockets: WebSocket[] = [];

async function connect(port = portOf(relay)): Promise<TestClient> {
  const socket = new WebSocket(`ws://localhost:${port}/${HANDLE}`);
  const received: Frame[] = [];

  socket.addEventListener("message", (event) => received.push(decodeFrame(String(event.data))));
  await new Promise<void>((resolve) => socket.addEventListener("open", () => resolve()));

  const client: TestClient = {
    received,
    send: (frame) => socket.send(encodeFrame(frame)),
    sendRaw: (raw) => socket.send(raw),
    sendBinary: (raw) => socket.send(raw),
    isOpen: () => socket.readyState === WebSocket.OPEN,
    close: () => socket.close(),
  };

  clients.push(client);
  return client;
}

async function subscribed(handle = HANDLE, port = portOf(relay)): Promise<TestClient> {
  const client = await connect(port);
  client.send(subFrame(handle));
  await wait(25);
  return client;
}

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
 * Loopback is spelled `127.0.0.1` rather than `localhost` throughout the
 * connection-limit cases, because `localhost` may resolve to `::1` and the
 * per-source cap keys on the address the connection actually arrived from.
 */
async function openSocket(port: number): Promise<WebSocket> {
  const socket = await openUrl(`ws://127.0.0.1:${port}/${HANDLE}`);
  rawSockets.push(socket);
  return socket;
}

/** Polls until an ordinary HTTP request gets `status`, so a test can wait for
 * a slot to come back without guessing how long a close takes to land. */
async function untilStatus(port: number, status: number, timeoutMs = 2000): Promise<void> {
  const deadline = Date.now() + timeoutMs;

  for (;;) {
    const response = await fetch(`http://127.0.0.1:${port}/${HANDLE}`);
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

describe("the contract every relay keeps", () => {
  // Its own relay on the real clock: the contract cannot advance an injected one.
  let contracted: ReturnType<typeof startRelay>;

  beforeEach(() => {
    contracted = startRelay({ port: 0 });
  });

  afterEach(() => {
    contracted.stop(true);
  });

  relayContract("bun relay", () => ({
    ws: (path) => `ws://localhost:${portOf(contracted)}${path}`,
    http: (path) => `http://localhost:${portOf(contracted)}${path}`,
  }));
});

describe("rate limiting on an injected clock", () => {
  const MESSAGES_AFTER_SUBSCRIBING = RATE_LIMIT_MESSAGES - 1;

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

});

describe("connection limits", () => {
  it("refuses a connection beyond the per-IP cap", async () => {
    const port = startCapped({ maxConnections: 100, maxConnectionsPerIp: 2 });
    await openSocket(port);
    await openSocket(port);

    // The global cap is fifty times higher, so only the per-IP one can refuse.
    expect((await fetch(`http://127.0.0.1:${port}/${HANDLE}`)).status).toBe(REFUSED);
    await expect(openSocket(port)).rejects.toThrow("refused");
  });

  it("refuses a connection beyond the global cap", async () => {
    const port = startCapped({ maxConnections: 2, maxConnectionsPerIp: 10 });
    await openSocket(port);
    await openSocket(port);

    // Every test connection comes from one address, so the per-IP cap is set
    // above the global one: a refusal here can only be the global cap.
    expect((await fetch(`http://127.0.0.1:${port}/${HANDLE}`)).status).toBe(REFUSED);
    await expect(openSocket(port)).rejects.toThrow("refused");
  });

  it("frees the slot when a connection closes", async () => {
    const port = startCapped({ maxConnections: 100, maxConnectionsPerIp: 1 });
    const first = await openSocket(port);
    expect((await fetch(`http://127.0.0.1:${port}/${HANDLE}`)).status).toBe(REFUSED);

    first.close();
    await untilStatus(port, 426);

    // 426 means the cap let the request through and it was merely not an
    // upgrade — the slot came back rather than leaking.
    await openSocket(port);
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
      // past: subscribing, one message and one malformed frame leave alice two
      // tokens of five, and these five exhaust them.
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

      expect((await fetch(`http://127.0.0.1:${port}/${HANDLE}`)).status).toBe(REFUSED);
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
