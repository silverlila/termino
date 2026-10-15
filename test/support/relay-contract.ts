/**
 * What every relay must do, whoever runs it: the Bun server a person self-hosts and the
 * Cloudflare Durable Object are held to the same suite. Behaviour that
 * only one of them has — Bun's per-address caps, its injectable clock — is tested
 * beside that relay instead.
 *
 * Every test takes fresh handles, so a channel left over from an earlier test (a
 * Durable Object outlives its sockets) can never be the one under test.
 *
 * Runs on the real clock: a fresh connection holds a full bucket, so a test that sends
 * fewer frames than the bucket holds is never limited, and the one that is about the
 * limiter sends faster than it refills.
 *
 * Refusals must answer 429, not merely some 4xx: a request that is not an upgrade already
 * gets 426, so a `>= 400` assertion would pass against a relay that refused nothing. A
 * refused WebSocket handshake surfaces in Bun as a close with code 1002, never as an
 * error event.
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
  RATE_LIMIT_MESSAGES,
  RATE_LIMIT_WINDOW_MS,
} from "../../server/channel.ts";

export interface RelayTarget {
  ws(path: string): string;
  http(path: string): string;
}

export interface TestClient {
  received: Frame[];
  send(frame: Frame): void;
  sendRaw(raw: string): void;
  sendBinary(raw: Uint8Array): void;
  isOpen(): boolean;
  close(): void;
}

export const REFUSED = 429;

const PUBLIC_KEY = Uint8Array.from({ length: 32 }, (_, index) => index);
const CIPHERTEXT = new TextEncoder().encode("opaque to the relay");

export const wait = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

export function freshHandle(): string {
  return Buffer.from(crypto.getRandomValues(new Uint8Array(16))).toString("hex");
}

export async function until(condition: () => boolean, timeoutMs = 3000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (!condition()) {
    if (Date.now() > deadline) throw new Error("timed out waiting for the relay");
    await wait(5);
  }
}

export const settle = () => wait(120);

export const framesOfType = (client: TestClient, type: Frame["t"]) =>
  client.received.filter((frame) => frame.t === type);

export async function openSocket(url: string): Promise<WebSocket> {
  const socket = new WebSocket(url);

  await new Promise<void>((resolve, reject) => {
    socket.addEventListener("open", () => resolve(), { once: true });
    socket.addEventListener("close", () => reject(new Error("the relay refused the connection")), {
      once: true,
    });
  });
  return socket;
}

export function relayContract(name: string, target: () => RelayTarget): void {
  let clients: TestClient[] = [];
  let HANDLE = "";
  let OTHER_HANDLE = "";

  beforeEach(() => {
    clients = [];
    HANDLE = freshHandle();
    OTHER_HANDLE = freshHandle();
  });

  afterEach(() => {
    for (const client of clients) client.close();
  });

  async function connect(handle = HANDLE): Promise<TestClient> {
    const socket = await openSocket(target().ws(`/${handle}`));
    const received: Frame[] = [];

    socket.addEventListener("message", (event) => received.push(decodeFrame(String(event.data))));

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

  async function subscribed(handle = HANDLE): Promise<TestClient> {
    const client = await connect(handle);
    client.send(subFrame(handle));
    await wait(40);
    return client;
  }

  describe(`${name}: forwarding`, () => {
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

    it("forwards hello to the other end of the channel, never back to the sender", async () => {
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
      expect(framesOfType(alice, "hello")).toHaveLength(0);
    });

    it("forwards a passphrase room's hello with its associated data intact", async () => {
      const alice = await subscribed();
      const bob = await subscribed();
      const associatedData = Uint8Array.from({ length: 16 }, (_, index) => 100 + index);
      const sent = helloFrame(HANDLE, PUBLIC_KEY, associatedData);

      alice.send(sent);
      await until(() => framesOfType(bob, "hello").length === 1);

      expect(framesOfType(bob, "hello")[0]).toEqual(sent);
    });

    it("refuses a hello naming another handle, so it reaches nobody on either", async () => {
      const sender = await subscribed(HANDLE);
      const roommate = await subscribed(HANDLE);
      const listener = await subscribed(OTHER_HANDLE);

      sender.send(helloFrame(OTHER_HANDLE, PUBLIC_KEY));
      await until(() => framesOfType(sender, "err").length === 1);
      await settle();

      expect(framesOfType(sender, "err")).toEqual([{ v: 2, t: "err", code: "bad_frame" }]);
      expect(framesOfType(roommate, "hello")).toHaveLength(0);
      expect(framesOfType(listener, "hello")).toHaveLength(0);
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

  describe(`${name}: subscription`, () => {
    it("drops a message sent before any subscribe, forwarding it to nobody", async () => {
      const listener = await subscribed();
      const unsubscribed = await connect();

      unsubscribed.send(msgFrame(HANDLE, 0, CIPHERTEXT));
      await until(() => unsubscribed.received.length > 0);
      await settle();

      expect(framesOfType(listener, "msg")).toHaveLength(0);
      expect(unsubscribed.received).toEqual([{ v: 2, t: "err", code: "not_subscribed" }]);
    });

    it("refuses to route a message into a channel the connection is not on", async () => {
      const alice = await subscribed(HANDLE);
      const stranger = await subscribed(OTHER_HANDLE);

      stranger.send(msgFrame(HANDLE, 0, CIPHERTEXT));
      await until(() => framesOfType(stranger, "err").length === 1);
      await settle();

      expect(framesOfType(alice, "msg")).toHaveLength(0);
      expect(framesOfType(stranger, "err")).toEqual([{ v: 2, t: "err", code: "bad_frame" }]);
    });

    it("refuses a subscription to a handle other than the one the connection dialled", async () => {
      const alice = await subscribed(OTHER_HANDLE);
      const mallory = await connect(HANDLE);

      mallory.send(subFrame(OTHER_HANDLE));
      await until(() => framesOfType(mallory, "err").length === 1);
      mallory.send(msgFrame(OTHER_HANDLE, 0, CIPHERTEXT));
      await settle();

      expect(framesOfType(mallory, "err")[0]).toEqual({ v: 2, t: "err", code: "bad_frame" });
      expect(framesOfType(alice, "msg")).toHaveLength(0);
    });
  });

  describe(`${name}: two participants and no more`, () => {
    it("answers channel_full to a third subscriber and leaves the first two alone", async () => {
      const alice = await subscribed();
      const bob = await subscribed();
      const third = await subscribed();

      await until(() => framesOfType(third, "err").length === 1);
      await settle();

      expect(framesOfType(third, "err")).toEqual([{ v: 2, t: "err", code: "channel_full" }]);

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

      expect(framesOfType(alice, "err")).toHaveLength(0);
    });
  });

  describe(`${name}: rate limiting`, () => {
    const MESSAGES_AFTER_SUBSCRIBING = RATE_LIMIT_MESSAGES - 1;

    it("drops the message past the budget and tells only that sender", async () => {
      const alice = await subscribed();
      const bob = await subscribed();

      for (let sent = 0; sent < MESSAGES_AFTER_SUBSCRIBING + 1; sent++) {
        alice.send(msgFrame(HANDLE, sent, CIPHERTEXT));
      }
      await until(() => framesOfType(alice, "err").length === 1);
      await settle();

      expect(framesOfType(bob, "msg")).toHaveLength(MESSAGES_AFTER_SUBSCRIBING);
      expect(framesOfType(alice, "err")).toEqual([{ v: 2, t: "err", code: "rate_limited" }]);
      expect(framesOfType(bob, "err")).toHaveLength(0);

      bob.send(msgFrame(HANDLE, 0, CIPHERTEXT));
      await until(() => framesOfType(alice, "msg").length === 1);
      expect(framesOfType(bob, "err")).toHaveLength(0);
    });

    it("answers once while a sender stays over budget, not once per frame", async () => {
      const mallory = await subscribed();

      for (let sent = 0; sent < MESSAGES_AFTER_SUBSCRIBING + 20; sent++) {
        mallory.send(msgFrame(HANDLE, sent, CIPHERTEXT));
      }
      await until(() => framesOfType(mallory, "err").length === 1);
      await settle();

      expect(framesOfType(mallory, "err")).toEqual([{ v: 2, t: "err", code: "rate_limited" }]);
    });

    it("lets a limited sender speak again once a token has come back", async () => {
      const alice = await subscribed();
      const bob = await subscribed();

      for (let sent = 0; sent < MESSAGES_AFTER_SUBSCRIBING + 1; sent++) {
        alice.send(msgFrame(HANDLE, sent, CIPHERTEXT));
      }
      await until(() => framesOfType(alice, "err").length === 1);

      await wait(RATE_LIMIT_WINDOW_MS / RATE_LIMIT_MESSAGES + 100);
      alice.send(msgFrame(HANDLE, 99, CIPHERTEXT));

      await until(() => framesOfType(bob, "msg").length === MESSAGES_AFTER_SUBSCRIBING + 1);
      expect(framesOfType(alice, "err")).toHaveLength(1);
    });

    it("charges repeated subscriptions too, so they cannot be made free", async () => {
      const mallory = await subscribed(HANDLE);

      for (let sent = 0; sent < MESSAGES_AFTER_SUBSCRIBING + 1; sent++) {
        mallory.send(subFrame(HANDLE));
      }
      await until(() => framesOfType(mallory, "err").length === 1);
      await settle();

      expect(framesOfType(mallory, "err")).toEqual([{ v: 2, t: "err", code: "rate_limited" }]);
    });
  });

  describe(`${name}: malformed input`, () => {
    const rejected: Record<string, () => string> = {
      "text that is not JSON": () => "{not json",
      "an unsupported version": () => JSON.stringify({ v: 1, t: "sub", h: HANDLE }),
      "a handle that is not lowercase hex": () => JSON.stringify({ v: 2, t: "sub", h: "nope" }),
      "an unknown frame type": () => JSON.stringify({ v: 2, t: "shutdown" }),
      "a frame the relay itself originates": () => JSON.stringify({ v: 2, t: "err", code: "bad_frame" }),
      "the presence frame version 1 had": () => JSON.stringify({ v: 2, t: "presence", n: 2 }),
      "a JSON array": () => "[1,2,3]",
    };

    for (const [description, raw] of Object.entries(rejected)) {
      it(`answers bad_frame to ${description} without closing the connection`, async () => {
        const client = await subscribed();
        client.sendRaw(raw());
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

      alice.send(msgFrame(HANDLE, 1, CIPHERTEXT));
      await until(() => framesOfType(bob, "msg").length === 1);
      expect(alice.isOpen()).toBe(true);
    });

    it("survives garbage and still delivers the message after it", async () => {
      const alice = await subscribed();
      const bob = await subscribed();

      for (const junk of ["", "null", "{}"]) alice.sendRaw(junk);
      alice.send(msgFrame(HANDLE, 0, CIPHERTEXT));

      await until(() => framesOfType(bob, "msg").length === 1);
      expect(alice.isOpen()).toBe(true);
    });

    it("charges garbage like any other frame, so it cannot be sent for free", async () => {
      const mallory = await subscribed();

      for (let sent = 0; sent < RATE_LIMIT_MESSAGES; sent++) mallory.sendRaw("{not json");
      await until(() => framesOfType(mallory, "err").length === RATE_LIMIT_MESSAGES);

      expect(framesOfType(mallory, "err").at(-1)).toEqual({ v: 2, t: "err", code: "rate_limited" });
    });

    it("reads a frame sent as binary the same as one sent as text", async () => {
      const alice = await subscribed();
      const bob = await subscribed();

      alice.sendBinary(new TextEncoder().encode(encodeFrame(msgFrame(HANDLE, 7, CIPHERTEXT))));

      await until(() => framesOfType(bob, "msg").length === 1);
      expect(framesOfType(alice, "err")).toHaveLength(0);
    });

    it("rejects a message whose counter is not a whole number", async () => {
      const alice = await subscribed();
      const bob = await subscribed();

      alice.sendRaw(JSON.stringify({ v: 2, t: "msg", h: HANDLE, i: -1, c: "AAAA" }));
      await until(() => framesOfType(alice, "err").length === 1);

      expect(framesOfType(bob, "msg")).toHaveLength(0);
    });
  });

  describe(`${name}: what it serves`, () => {
    it("refuses a plain http request to a channel rather than serving anything", async () => {
      const response = await fetch(target().http(`/${HANDLE}`));
      expect(response.status).toBe(426);
    });

    it("refuses an upgrade whose path is not a handle", async () => {
      for (const path of ["/", "/admin", `/${HANDLE}/extra`, `/${HANDLE.toUpperCase()}`, `/${HANDLE}?x=1`]) {
        expect((await fetch(target().http(path))).status).toBe(REFUSED);
        await expect(openSocket(target().ws(path))).rejects.toThrow("refused");
      }
    });

    it("refuses an upgrade carrying an Origin header", async () => {
      const response = await fetch(target().http(`/${HANDLE}`), {
        headers: { origin: "https://a-browser-page.example" },
      });

      expect(response.status).toBe(REFUSED);
    });
  });
}
