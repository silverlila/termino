import { afterEach, beforeEach, describe, expect, it } from "bun:test";
import { joinChat, newChat, passphraseChat } from "../src/launch.ts";
import type { IncomingMessage, Session } from "../src/session.ts";
import { startTestRelay, unlimitedClock, wait, type TestRelay } from "./support/harness.ts";

/**
 * The two ways into a chat, without a screen: what `newChat` hands the person who
 * starts one has to be exactly what `joinChat` needs to reach them.
 */

let relay: TestRelay;
const sessions: Session[] = [];

beforeEach(() => {
  relay = startTestRelay({ now: unlimitedClock() });
});

afterEach(() => {
  for (const session of sessions) session.close();
  sessions.length = 0;
  relay.server.stop(true);
});

async function until(check: () => boolean, timeoutMs = 3000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (!check()) {
    if (Date.now() > deadline) throw new Error("timed out");
    await wait(10);
  }
}

describe("starting a chat", () => {
  it("hands back an invite naming the relay it was started on", () => {
    const { invite } = newChat("wss://relay.example:8787");

    expect(invite).toMatch(/^([a-z]+-){15}[a-z]+@relay\.example:8787$/);
  });

  it("mints a different secret every time", () => {
    expect(newChat("wss://relay.example").invite).not.toBe(newChat("wss://relay.example").invite);
  });
});

describe("joining a chat", () => {
  it("connects to whoever started it, with both sides seeing the same session words", async () => {
    const started = newChat(relay.url);
    const joined = joinChat(started.invite ?? "");
    if (!joined.ok) throw new Error(joined.reason);

    const received: IncomingMessage[] = [];
    const [alice, bob] = await Promise.all([
      started.connect("alice", {}),
      joined.chat.connect("bob", { onMessage: (message) => received.push(message) }),
    ]);
    sessions.push(alice, bob);

    expect(alice.sasWords).toBe(bob.sasWords);

    await alice.send("hello bob");
    await until(() => received.length > 0);
    expect(received[0]).toMatchObject({ nick: "alice", body: "hello bob" });
  });

  it("has no invite of its own to show", () => {
    const joined = joinChat(newChat("wss://relay.example").invite ?? "");
    if (!joined.ok) throw new Error(joined.reason);

    expect(joined.chat.invite).toBeNull();
  });

  it("refuses a malformed invite with a reason rather than throwing", () => {
    expect(joinChat("not-an-invite")).toEqual({
      ok: false,
      reason: "invalid invite: the host is missing — an invite is <words>@<host>",
    });
  });

  it("names control characters in a reason instead of passing them to the screen", () => {
    // A hostile 'invite' is a way to put bytes on somebody's terminal: the
    // reason quotes the word it could not read.
    expect(joinChat("a\u001B]52;c;ZXZpbA==\u0007b@relay.example")).toEqual({
      ok: false,
      reason: "not a word from the list: a<U+001B>]52;c;ZXZpbA==<U+0007>b",
    });
  });

  it("refuses a mistyped word, a short invite and a spaced one with a reason", () => {
    // `join` used to let all three escape as a stack trace: only the host
    // errors were turned into a usage message.
    expect(joinChat("acorn-zzzz@relay.example")).toEqual({
      ok: false,
      reason: "not a word from the list: zzzz",
    });
    expect(joinChat("acorn-acorn@relay.example")).toMatchObject({
      ok: false,
      reason: expect.stringContaining("found 2"),
    });
    expect(joinChat("acorn acorn@relay.example")).toMatchObject({
      ok: false,
      reason: expect.stringContaining("hyphens"),
    });
  });
});

describe("meeting with a passphrase", () => {
  it("connects two people who typed the same room and phrase", async () => {
    const one = passphraseChat(relay.url, "Silver and Ana", "the blue house on the corner");
    const other = passphraseChat(relay.url, "silver and ana ", "the blue house on the corner");
    if (!one.ok || !other.ok) throw new Error("refused a usable room and phrase");

    const [alice, bob] = await Promise.all([
      one.chat.connect("alice", {}),
      other.chat.connect("bob", {}),
    ]);
    sessions.push(alice, bob);

    expect(alice.sasWords).toBe(bob.sasWords);
    expect(one.chat.invite).toBeNull();
  });

  it("refuses an empty room or a short phrase before dialling anything", () => {
    expect(passphraseChat(relay.url, " ", "the blue house")).toEqual({
      ok: false,
      reason: "a room name is required",
    });
    expect(passphraseChat(relay.url, "room", "hunter2")).toMatchObject({
      ok: false,
      reason: expect.stringContaining("at least 10 characters"),
    });
  });
});

