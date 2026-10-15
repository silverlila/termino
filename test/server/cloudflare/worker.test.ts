import { afterAll, describe, expect, it } from "bun:test";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { encodeFrame, subFrame } from "../../../shared/protocol/frame.ts";
import { joinChat, newChat, passphraseChat } from "../../../src/launch.ts";
import type { IncomingMessage, Session } from "../../../src/session.ts";
import {
  freshHandle,
  openSocket,
  REFUSED,
  relayContract,
  until,
  wait,
} from "../../support/relay-contract.ts";

/**
 * The Cloudflare relay, run in workerd through `wrangler dev` on a loopback port: the
 * shared relay contract, what only this relay has, and a real client session across it.
 *
 * It runs wrangler.jsonc's `test` environment, which raises the per-address connection
 * limit (every connection here comes from one address) and cuts idle reaping to three
 * seconds. Wrangler environments do not inherit bindings, so that environment repeats them.
 *
 * Wrangler logs every request, so its stdout and stderr are read to the end: a pipe nobody
 * drains fills and blocks it mid-suite. It runs with WRANGLER_SEND_METRICS=false, since
 * otherwise it prompts for telemetry consent and then reports usage to Cloudflare.
 */

const IDLE_TIMEOUT_MS = 3000;

const CONFIG = new URL("../../../server/cloudflare/wrangler.jsonc", import.meta.url).pathname;

const STARTUP_DEADLINE_MS = 60_000;

let port = 0;

function freePort(): number {
  const probe = Bun.serve({ port: 0, fetch: () => new Response() });
  const found = probe.port;
  probe.stop(true);
  if (found === undefined) throw new Error("no free port");
  return found;
}

async function drain(stream: ReadableStream<Uint8Array>, sink: { text: string }): Promise<void> {
  const decoder = new TextDecoder();
  for await (const chunk of stream) sink.text += decoder.decode(chunk, { stream: true });
}

async function ready(output: { text: string }, exited: Promise<number>): Promise<void> {
  let gone = false;
  void exited.then(() => (gone = true));
  const deadline = Date.now() + STARTUP_DEADLINE_MS;

  while (!output.text.includes("Ready on")) {
    if (gone) throw new Error(`wrangler exited before it was ready:\n${output.text}`);
    if (Date.now() > deadline) throw new Error(`wrangler was not ready in time:\n${output.text}`);
    await Bun.sleep(50);
  }
}

port = freePort();
const state = mkdtempSync(join(tmpdir(), "termino-wrangler-"));
const wrangler = Bun.spawn(
  [
    "bunx",
    "wrangler",
    "dev",
    "--config",
    CONFIG,
    "--ip",
    "127.0.0.1",
    "--port",
    String(port),
    "--show-interactive-dev-session=false",
    "--env",
    "test",
    "--persist-to",
    state,
  ],
  {
    stdout: "pipe",
    stderr: "pipe",
    stdin: "ignore",
    env: { ...process.env, WRANGLER_SEND_METRICS: "false" },
  },
);
const output = { text: "" };
void drain(wrangler.stdout, output);
void drain(wrangler.stderr, output);
await ready(output, wrangler.exited);

afterAll(async () => {
  wrangler.kill();
  await wrangler.exited;
  rmSync(state, { recursive: true, force: true });
});

relayContract("cloudflare relay", () => ({
  ws: (path) => `ws://127.0.0.1:${port}${path}`,
  http: (path) => `http://127.0.0.1:${port}${path}`,
}));

describe("a real session across the cloudflare relay", () => {
  it("establishes, agrees its session words, and delivers a message", async () => {
    const started = newChat(`ws://127.0.0.1:${port}`);
    const joined = joinChat(started.invite ?? "");
    if (!joined.ok) throw new Error(joined.reason);

    const received: IncomingMessage[] = [];
    const sessions: Session[] = await Promise.all([
      started.connect("alice", {}),
      joined.chat.connect("bob", { onMessage: (message) => received.push(message) }),
    ]);
    const [alice, bob] = sessions;
    if (alice === undefined || bob === undefined) throw new Error("unreachable");

    try {
      expect(alice.sasWords).toBe(bob.sasWords);

      await alice.send("hello through cloudflare");
      await until(() => received.length === 1);
      expect(received[0]).toMatchObject({ nick: "alice", body: "hello through cloudflare" });
    } finally {
      for (const session of sessions) session.close();
    }
  });
});

describe("a passphrase room across the cloudflare relay", () => {
  it("establishes for two people with the same room and phrase", async () => {
    const relayUrl = `ws://127.0.0.1:${port}`;
    const one = passphraseChat(relayUrl, `room ${freshHandle()}`, "the blue house on the corner");
    if (!one.ok) throw new Error(one.reason);

    const sessions = await Promise.all([one.chat.connect("alice", {}), one.chat.connect("bob", {})]);
    try {
      expect(sessions[0]?.sasWords).toBe(sessions[1]?.sasWords);
    } finally {
      for (const session of sessions) session.close();
    }
  });
});

describe("what only the cloudflare relay has", () => {
  const ws = (handle: string) => `ws://127.0.0.1:${port}/${handle}`;

  it("holds at most four sockets on one channel, subscribed or not", async () => {
    const handle = freshHandle();
    const held = [];
    for (let opened = 0; opened < 4; opened++) held.push(await openSocket(ws(handle)));

    try {
      await expect(openSocket(ws(handle))).rejects.toThrow("refused");
      held.push(await openSocket(ws(freshHandle())));
    } finally {
      for (const socket of held) socket.close();
    }
  });

  it("gives a silent subscriber's place to somebody new once it has been idle too long", async () => {
    const handle = freshHandle();
    const dead = [await openSocket(ws(handle)), await openSocket(ws(handle))];
    for (const socket of dead) socket.send(encodeFrame(subFrame(handle)));
    await wait(IDLE_TIMEOUT_MS + 500);

    const newcomer = await openSocket(ws(handle));
    const received: string[] = [];
    newcomer.addEventListener("message", (event) => received.push(String(event.data)));
    newcomer.send(encodeFrame(subFrame(handle)));

    try {
      await until(() => dead.every((socket) => socket.readyState === WebSocket.CLOSED));
      expect(received).toEqual([]);
    } finally {
      newcomer.close();
    }
  });

  it("refuses an address that opens connections faster than a person does", async () => {
    let refusal = "";
    for (let sent = 0; sent < 1000 && refusal === ""; sent++) {
      const response = await fetch(`http://127.0.0.1:${port}/${freshHandle()}`);
      const text = await response.text();
      if (response.status === REFUSED) refusal = text;
      else expect(response.status).toBe(426);
    }

    expect(refusal).toBe("termino relay: too many connections from this address\n");
  });
});
