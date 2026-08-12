import { afterEach, beforeEach, describe, expect, it } from "bun:test";
import { loadTrustRecords } from "../../../src/client/trust.ts";
import { removeTempDirs, startTestRelay, wait, type TestRelay } from "../../support/harness.ts";
import { closeChats, joinAs, mountChat, seeOnScreen, submit } from "../../support/tui.tsx";

/**
 * Verification as a user meets it: the marker beside a nickname, what
 * `/verify` does to it, whether it is still there tomorrow, and what the
 * screen says when a nickname that was one key yesterday is another today.
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

describe("an unverified peer", () => {
  it("renders their nickname prefixed with ?", async () => {
    const { screen } = await mountChat("alice", relay.url);
    const bob = await joinAs("bob", relay.url);

    await bob.session.send("shipping it now");
    const frame = await seeOnScreen(screen, "shipping it now");

    expect(frame).toContain("?bob");
    expect(frame).not.toContain("✓bob");
  });
});

describe("/verify", () => {
  it("marks the peer verified when the fingerprint matches, and remembers it", async () => {
    const { screen, trustDir } = await mountChat("alice", relay.url);
    const bob = await joinAs("bob", relay.url);

    await bob.session.send("shipping it now");
    await seeOnScreen(screen, "?bob");

    await submit(screen, `/verify bob ${bob.fingerprint}`);

    const frame = await seeOnScreen(screen, "✓bob");
    expect(frame).not.toContain("?bob");
    expect(loadTrustRecords(trustDir).bob?.verified).toBe(true);
  });

  it("keeps the verification when another nickname turns up afterwards", async () => {
    const { screen, trustDir } = await mountChat("alice", relay.url);
    const bob = await joinAs("bob", relay.url);

    await bob.session.send("shipping it now");
    await seeOnScreen(screen, "?bob");
    await submit(screen, `/verify bob ${bob.fingerprint}`);
    await seeOnScreen(screen, "✓bob");

    // A first sighting of anybody rewrites the store. If the writer holds a
    // copy from before `/verify`, bob quietly reverts to unverified on disk —
    // and nothing says so until the next launch, because his key never
    // changed and so nothing raises an alarm.
    const carol = await joinAs("carol", relay.url);
    await carol.session.send("morning");
    await seeOnScreen(screen, "?carol");

    expect(loadTrustRecords(trustDir).bob?.verified).toBe(true);
    expect(screen.captureCharFrame()).toContain("✓bob");
  });

  it("accepts a fingerprint typed back in the wrong case and spacing", async () => {
    const { screen } = await mountChat("alice", relay.url);
    const bob = await joinAs("bob", relay.url);

    await bob.session.send("shipping it now");
    await seeOnScreen(screen, "?bob");

    await submit(screen, `/verify bob  ${bob.fingerprint.toUpperCase()}`);

    await seeOnScreen(screen, "✓bob");
  });

  it("leaves the marker alone when the fingerprint does not match", async () => {
    const { screen, trustDir } = await mountChat("alice", relay.url);
    const bob = await joinAs("bob", relay.url);
    const mallory = await joinAs("mallory", relay.url);

    await bob.session.send("shipping it now");
    await seeOnScreen(screen, "?bob");

    // Somebody else's real fingerprint: the near miss this check exists for.
    await submit(screen, `/verify bob ${mallory.fingerprint}`);

    const frame = await seeOnScreen(screen, "does not match");
    expect(frame).toContain("?bob");
    expect(frame).not.toContain("✓bob");
    expect(loadTrustRecords(trustDir).bob?.verified).toBe(false);
  });

  it("says so when nothing has arrived from that nickname yet", async () => {
    const { screen } = await mountChat("alice", relay.url);
    const bob = await joinAs("bob", relay.url);

    await submit(screen, `/verify bob ${bob.fingerprint}`);

    await seeOnScreen(screen, "nothing has arrived from bob yet");
  });
});

describe("a nickname whose key has changed", () => {
  it("renders the alarm line", async () => {
    const { screen } = await mountChat("alice", relay.url);

    const bob = await joinAs("bob", relay.url);
    await bob.session.send("shipping it now");
    await seeOnScreen(screen, "shipping it now");

    // Same nickname, a key this client has never seen — a reinstall, or
    // somebody else answering to the name.
    const impostor = await joinAs("bob", relay.url);
    await impostor.session.send("actually, hold off");

    await seeOnScreen(screen, "!! KEY CHANGED for bob — verify out of band");
  });

  it("drops the verified marker it used to have", async () => {
    const { screen, trustDir } = await mountChat("alice", relay.url);

    const bob = await joinAs("bob", relay.url);
    await bob.session.send("shipping it now");
    await seeOnScreen(screen, "?bob");
    await submit(screen, `/verify bob ${bob.fingerprint}`);
    await seeOnScreen(screen, "✓bob");

    const impostor = await joinAs("bob", relay.url);
    await impostor.session.send("actually, hold off");

    const frame = await seeOnScreen(screen, "!! KEY CHANGED");
    expect(frame).not.toContain("✓bob");
    expect(frame).toContain("?bob");
    expect(loadTrustRecords(trustDir).bob?.verified).toBe(false);
  });
});

describe("an unrecognised command", () => {
  it("is reported to the user and sent to nobody", async () => {
    const { screen } = await mountChat("alice", relay.url);
    const bob = await joinAs("bob", relay.url);

    await submit(screen, "/frobnicate the widget");
    await seeOnScreen(screen, "unknown command /frobnicate");

    // A mistyped command going out as chat is how people say in public what
    // they meant to type privately.
    await wait(100);
    expect(bob.received).toEqual([]);
  });
});
