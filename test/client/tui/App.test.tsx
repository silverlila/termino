import { afterEach, beforeEach, describe, expect, it } from "bun:test";
import { removeTempDirs, startTestRelay, wait, type TestRelay } from "../../support/harness.ts";
import {
  closeChats,
  joinAs,
  mountChat,
  pressEnter,
  seeOnScreen,
  typeText,
} from "../../support/tui.tsx";

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

  it("reports that nobody else is here until somebody is", async () => {
    const { screen } = await mountChat("alice", relay.url);
    expect(screen.captureCharFrame()).toContain("just you");

    await joinAs("bob", relay.url);
    const frame = await seeOnScreen(screen, "2 here");
    expect(frame).not.toContain("just you");
  });
});
