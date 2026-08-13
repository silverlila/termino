import { afterEach, beforeEach, describe, expect, it } from "bun:test";
import { appendCapped, type TranscriptLine } from "../../src/tui/App.tsx";
import { COMMANDS } from "../../src/tui/commands.ts";
import { removeTempDirs, startTestRelay, wait, type TestRelay } from "../support/harness.ts";
import {
  closeChats,
  joinAs,
  joinWithWrongKey,
  mountChat,
  pressEnter,
  seeOnScreen,
  submit,
  typeText,
} from "../support/tui.tsx";

/**
 * The chat screen itself: what it shows, and — the reason this rewrite
 * happened at all — what it does not destroy while showing it.
 */

let relay: TestRelay;

beforeEach(() => {
  relay = startTestRelay();
});

afterEach(() => {
  closeChats();
  relay.server.stop(true);
  removeTempDirs();
});

describe("the chat screen", () => {
  it("shows the channel, the nickname and this device's own fingerprint", async () => {
    const { screen, fingerprint } = await mountChat("alice", relay.url);
    const frame = screen.captureCharFrame();

    expect(frame).toContain("#demo");
    expect(frame).toContain("alice");
    // The first two words are enough: eight of them wrap past 80 columns, and
    // this is asserting that the real fingerprint is on screen, not a stub.
    expect(frame).toContain(fingerprint.split(" ").slice(0, 2).join(" "));
  });

  it("shows a message from a peer, marked unverified", async () => {
    const { screen } = await mountChat("alice", relay.url);
    const bob = await joinAs("bob", relay.url);

    await bob.session.send("shipping it now");
    const frame = await seeOnScreen(screen, "shipping it now");

    expect(frame).toContain("?bob");
  });

  it("shows what this user sends, marked with their own verified key", async () => {
    const { screen } = await mountChat("alice", relay.url);
    await joinAs("bob", relay.url);

    await typeText(screen, "ready when you are");
    await pressEnter(screen);

    const frame = await seeOnScreen(screen, "ready when you are");
    expect(frame).toContain("✓alice");
  });

  it("clears the composer once a line has been sent", async () => {
    const { screen } = await mountChat("alice", relay.url);
    await joinAs("bob", relay.url);

    await typeText(screen, "ready when you are");
    await pressEnter(screen);
    await seeOnScreen(screen, "✓alice");

    // The sent line is in the transcript, so it is still on screen once — the
    // composer having kept a copy would make it twice.
    const frame = screen.captureCharFrame();
    expect(frame.split("ready when you are")).toHaveLength(2);
  });

  it("keeps half-typed input intact when a message arrives", async () => {
    const { screen } = await mountChat("alice", relay.url);
    const bob = await joinAs("bob", relay.url);

    await typeText(screen, "half a thought");
    expect(screen.captureCharFrame()).toContain("half a thought");

    await bob.session.send("shipping it now");
    const frame = await seeOnScreen(screen, "shipping it now");

    // The regression this whole rewrite exists for: the old client called
    // console.clear() and reprinted the transcript, erasing the draft.
    expect(frame).toContain("half a thought");
  });

  it("tells the user when the relay drops a message rather than failing silently", async () => {
    const { screen } = await mountChat("alice", relay.url);
    await joinAs("bob", relay.url);

    // The relay's bucket is five per ten seconds; the sixth comes back as an
    // error frame addressed to this connection alone.
    for (let sent = 0; sent < 6; sent++) {
      await typeText(screen, `line ${sent}`);
      await pressEnter(screen);
      await wait(10);
    }

    const frame = await seeOnScreen(screen, "rate_limited");
    expect(frame).toContain("the relay rejected a message");
  });

  it("coalesces undecryptable frames into one notice carrying a count", async () => {
    const { screen } = await mountChat("alice", relay.url);
    const mallory = await joinWithWrongKey("mallory", relay.url);

    // Four, not more: the relay spends a token on `sub` as well as on each
    // `msg`, and a fifth would trip the bucket and add notices of its own.
    for (let sent = 0; sent < 4; sent++) await mallory.session.send(`noise ${sent}`);

    const frame = await seeOnScreen(screen, "could not open 4 messages");

    // Once on screen, not four times: the flood is what the count is for.
    expect(frame.split("could not open")).toHaveLength(2);
  });

  it("starts a fresh count once a message opens again", async () => {
    const { screen } = await mountChat("alice", relay.url);
    const bob = await joinAs("bob", relay.url);
    const mallory = await joinWithWrongKey("mallory", relay.url);

    for (let sent = 0; sent < 3; sent++) await mallory.session.send(`noise ${sent}`);
    await seeOnScreen(screen, "could not open 3 messages");

    await bob.session.send("still here");
    await seeOnScreen(screen, "still here");

    await mallory.session.send("noise again");
    const frame = await seeOnScreen(screen, "could not open 1 message ");

    // The earlier run stays where it was: the count belongs to the burst, not
    // to the session.
    expect(frame).toContain("could not open 3 messages");
  });

  it("reports that nobody else is here until somebody is", async () => {
    const { screen } = await mountChat("alice", relay.url);
    expect(screen.captureCharFrame()).toContain("just you");

    await joinAs("bob", relay.url);
    const frame = await seeOnScreen(screen, "2 here");
    expect(frame).not.toContain("just you");
  });
});

/**
 * The cap is tested against the pure function rather than through the screen:
 * every inbound line has to cross the relay's five-frames-per-ten-seconds
 * bucket, so two thousand of them is over an hour of wall clock.
 */
describe("a long session", () => {
  const noticeLine = (id: string): TranscriptLine => ({
    kind: "notice",
    id,
    text: `line ${id}`,
    ts: 0,
    tone: "info",
  });

  it("caps the transcript at 2000 lines and drops the oldest first", () => {
    let lines: TranscriptLine[] = [];
    for (let index = 0; index < 2001; index++) lines = appendCapped(lines, noticeLine(String(index)));

    expect(lines).toHaveLength(2000);
    expect(lines[0]!.id).toBe("1");
    expect(lines.at(-1)!.id).toBe("2000");
  });
});

describe("/help", () => {
  it("lists every command, so the set is discoverable without guessing", async () => {
    const { screen } = await mountChat("alice", relay.url);

    await submit(screen, "/help");
    const frame = await seeOnScreen(screen, "/exit");

    for (const command of COMMANDS) expect(frame).toContain(command.usage.split(" ")[0]!);
  });

  it("is not sent to anybody", async () => {
    const { screen } = await mountChat("alice", relay.url);
    const bob = await joinAs("bob", relay.url);

    await submit(screen, "/help");
    await seeOnScreen(screen, "list these commands");

    await wait(100);
    expect(bob.received).toEqual([]);
  });
});

describe("/exit", () => {
  it("asks to be closed", async () => {
    const { screen, exits } = await mountChat("alice", relay.url);
    expect(exits).toHaveLength(0);

    await submit(screen, "/exit");

    expect(exits).toHaveLength(1);
  });

  it("leaves the channel, so the others stop counting this client", async () => {
    const alice = await mountChat("alice", relay.url);
    const bob = await mountChat("bob", relay.url);
    await seeOnScreen(bob.screen, "2 here");

    await submit(alice.screen, "/exit");

    // The relay publishes presence on every disconnect: bob learning he is
    // alone again is the proof the socket actually closed, rather than the
    // screen merely being asked to go away.
    await seeOnScreen(bob.screen, "just you");
  });
});
