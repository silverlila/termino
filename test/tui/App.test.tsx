import { afterEach, beforeEach, describe, expect, it } from "bun:test";
import { deriveHandle } from "../../shared/crypto/psk.ts";
import { encodeFrame, subFrame } from "../../shared/protocol/frame.ts";
import { appendCapped, type TranscriptLine } from "../../src/tui/App.tsx";
import { COMMANDS } from "../../src/tui/commands.ts";
import {
  openHostilePeer,
  startTestRelay,
  unlimitedClock,
  wait,
  type HostilePeer,
  type TestRelay,
} from "../support/harness.ts";
import {
  closeChats,
  joinAs,
  mountChat,
  pressEnter,
  PSK,
  seeOnScreen,
  submit,
  typeText,
} from "../support/tui.tsx";

/**
 * The chat screen itself: what it shows, and — the reason this rewrite
 * happened at all — what it does not destroy while showing it.
 *
 * The relay these tests mount against runs on a clock that jumps a rate-limit
 * window per frame, so the limiter never refuses one. A session spends three
 * frames on its handshake and the bucket holds five, which would otherwise
 * make every test here a frame-counting exercise. The one case that is *about*
 * the limiter starts a relay of its own.
 */

let relay: TestRelay;
const hostiles: HostilePeer[] = [];

/** A peer that holds the secret, establishes a session honestly, and then
 * sends what an honest client will not. */
async function hostilePeer(): Promise<HostilePeer> {
  const peer = await openHostilePeer(relay.url, PSK);
  hostiles.push(peer);
  await peer.confirm();

  return peer;
}

/** The eight words as they are on screen: everything between the label and the
 * line saying what to do with them, with whatever wrapping the status bar did
 * squeezed back out. Read the way a person reads them, rather than from the
 * session object, so a regression that stops drawing them fails here. */
function sessionWordsOn(frame: string): string {
  const afterLabel = frame.split("session words:")[1] ?? "";
  const beforeInstruction = afterLabel.split("read them aloud")[0] ?? "";

  return beforeInstruction.trim().split(/\s+/).join(" ");
}

beforeEach(() => {
  relay = startTestRelay({ now: unlimitedClock() });
});

afterEach(() => {
  for (const peer of hostiles) peer.close();
  hostiles.length = 0;
  closeChats();
  relay.server.stop(true);
});

describe("the chat screen", () => {
  it("shows the unaudited banner on the first frame", async () => {
    // Before a peer, before a key exchange, before anything is typed: whoever
    // is about to decide what to say here is told first that nobody outside
    // this project has reviewed how it is built, and where to read what that
    // means.
    const { screen } = await mountChat("alice", relay.url);

    const frame = screen.captureCharFrame();
    expect(frame).toContain("unaudited");
    expect(frame).toContain("no external security review");
    expect(frame).toContain("THREAT-MODEL.md");
  });

  it("keeps the unaudited banner up once a session is established", async () => {
    // It is a standing fact about the software, not a splash screen: an
    // audit is what removes it, not a peer arriving.
    const { screen } = await mountChat("alice", relay.url);
    await joinAs("bob", relay.url);

    const frame = await seeOnScreen(screen, "both here");
    expect(frame).toContain("unaudited");
  });

  it("shows the nickname, and says nobody is here until somebody is", async () => {
    const { screen } = await mountChat("alice", relay.url);
    const waiting = await seeOnScreen(screen, "alice");

    // Nobody has answered yet, and a session that nobody has answered is not
    // one: it is not established until a peer's confirm has opened. Said as
    // what the client is doing rather than as a count of the room, because
    // there is exactly one other seat in it.
    expect(waiting).toContain("waiting for the other side");

    await joinAs("bob", relay.url);
    const frame = await seeOnScreen(screen, "both here");

    expect(frame).not.toContain("waiting for the other side");
  });

  it("says the other side has gone quiet when their pings stop", async () => {
    // Timings the test can outlive: a peer is gone once an expiry has passed
    // with nothing of theirs opening, and the check runs on the ping beat.
    const { screen } = await mountChat("alice", relay.url, {
      pingIntervalMs: 20,
      presenceExpiryMs: 60,
    });
    const bob = await joinAs("bob", relay.url);
    await seeOnScreen(screen, "both here");

    bob.session.close();

    // The socket to the relay is still open — this is the other person having
    // stopped answering, which is a different fact and now says so.
    const frame = await seeOnScreen(screen, "gone quiet");
    expect(frame).toContain("connected");
  });

  it("shows the session words, the same eight on both screens", async () => {
    const alice = await mountChat("alice", relay.url);
    const bob = await mountChat("bob", relay.url);

    await seeOnScreen(alice.screen, "session words:");
    const frame = await seeOnScreen(bob.screen, "session words:");

    // Read off bob's screen and looked for on alice's: this is exactly what
    // the two people do to each other out loud. Three words is enough to be
    // this session's rather than any session's, and short enough to sit on one
    // row at any width the test uses.
    const spoken = frame.split("session words:")[1]?.trim().split(/\s+/).slice(0, 3) ?? [];
    expect(spoken).toHaveLength(3);

    await seeOnScreen(alice.screen, spoken.join(" "));
  });

  it("shows different session words in a second session on the same secret", async () => {
    // The property the whole comparison rests on. Words that came from the
    // secret alone would be identical in every session it ever ran, and two
    // people who compared them last week would go on nodding at the same eight
    // words while somebody sat in the middle of today's conversation.
    const first = await mountChat("alice", relay.url);
    const bob = await joinAs("bob", relay.url);
    const firstWords = sessionWordsOn(await seeOnScreen(first.screen, "session words:"));

    // The channel holds two, so the first pair leaves before the second
    // arrives — and leaving is the thing `/exit` does.
    await submit(first.screen, "/exit");
    bob.session.close();
    await wait(100);

    const second = await mountChat("carol", relay.url);
    await joinAs("dave", relay.url);
    const secondWords = sessionWordsOn(await seeOnScreen(second.screen, "session words:"));

    expect(firstWords.split(" ")).toHaveLength(8);
    expect(secondWords).not.toBe(firstWords);
  });

  it("says what the session words are for, next to them", async () => {
    // The words are the whole defence against a relay running its own exchange
    // with each side, and they defend nothing unless both people actually say
    // them out loud. Eight unexplained words on a status bar do not ask anyone
    // to do that.
    const { screen } = await mountChat("alice", relay.url);
    await joinAs("bob", relay.url);

    const frame = await seeOnScreen(screen, "session words:");
    expect(frame).toContain("read them aloud to each other");
    expect(frame).toContain("somebody is in the middle");
  });

  it("shows no session words before there is anybody to compare them with", async () => {
    const { screen } = await mountChat("alice", relay.url);

    const frame = await seeOnScreen(screen, "waiting for the other side");
    expect(frame).not.toContain("session words:");
  });

  it("shows a message from a peer", async () => {
    const { screen } = await mountChat("alice", relay.url);
    const bob = await joinAs("bob", relay.url);

    await bob.session.send("shipping it now");
    const frame = await seeOnScreen(screen, "shipping it now");

    expect(frame).toContain("bob");
  });

  it("shows what this user sends", async () => {
    const { screen } = await mountChat("alice", relay.url);
    await joinAs("bob", relay.url);
    await seeOnScreen(screen, "connected");

    await typeText(screen, "ready when you are");
    await pressEnter(screen);

    await seeOnScreen(screen, "ready when you are");
  });

  it("clears the composer once a line has been sent", async () => {
    const { screen } = await mountChat("alice", relay.url);
    await joinAs("bob", relay.url);
    await seeOnScreen(screen, "connected");

    await typeText(screen, "ready when you are");
    await pressEnter(screen);
    await seeOnScreen(screen, "ready when you are");

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
    // Its own relay, with the limiter running on a real clock: this is the one
    // case here that is about being refused.
    const limited = startTestRelay();

    try {
      const { screen } = await mountChat("alice", limited.url);
      await joinAs("bob", limited.url);
      await seeOnScreen(screen, "connected");

      // The bucket is five frames per ten seconds and the handshake has spent
      // three of them, so the third line typed is over the budget.
      for (let sent = 0; sent < 4; sent++) {
        await typeText(screen, `line ${sent}`);
        await pressEnter(screen);
        await wait(10);
      }

      const frame = await seeOnScreen(screen, "rate_limited");
      expect(frame).toContain("the relay rejected a message");
    } finally {
      limited.server.stop(true);
    }
  });

  it("coalesces undecryptable frames into one notice carrying a count", async () => {
    const { screen } = await mountChat("alice", relay.url);
    const mallory = await hostilePeer();

    mallory.sendNoise();
    mallory.sendNoise();

    const frame = await seeOnScreen(screen, "could not open 2 messages");

    // Once on screen, not twice: the flood is what the count is for.
    expect(frame.split("could not open")).toHaveLength(2);
  });

  it("starts a fresh count once a message opens again", async () => {
    const { screen } = await mountChat("alice", relay.url);
    const mallory = await hostilePeer();

    mallory.sendNoise();
    mallory.sendNoise();
    await seeOnScreen(screen, "could not open 2 messages");

    await mallory.send({ t: "text", nick: "mallory", body: "still here" });
    await seeOnScreen(screen, "still here");

    mallory.sendNoise();
    const frame = await seeOnScreen(screen, "could not open 1 message ");

    // The earlier run stays where it was: the count belongs to the burst, not
    // to the session.
    expect(frame).toContain("could not open 2 messages");
  });

  it("writes a notice when a message never arrives", async () => {
    const { screen } = await mountChat("alice", relay.url);
    const mallory = await hostilePeer();

    // A counter skipped on purpose, which is what a lost frame looks like from
    // the receiving end.
    await mallory.send({ t: "text", nick: "mallory", body: "one" });
    mallory.skipCounter();
    await mallory.send({ t: "text", nick: "mallory", body: "three" });
    await seeOnScreen(screen, "three");

    await mallory.send({ t: "text", nick: "mallory", body: "four" });
    const frame = await seeOnScreen(screen, "never arrived");

    expect(frame).toContain("⚠ 1 message from mallory never arrived");
  });

  it("writes a notice counting several messages that never arrived", async () => {
    const { screen } = await mountChat("alice", relay.url);
    const mallory = await hostilePeer();

    await mallory.send({ t: "text", nick: "mallory", body: "one" });
    mallory.skipCounter();
    mallory.skipCounter();
    await mallory.send({ t: "text", nick: "mallory", body: "four" });
    await seeOnScreen(screen, "four");

    await mallory.send({ t: "text", nick: "mallory", body: "five" });
    const frame = await seeOnScreen(screen, "never arrived");

    // Plural, and counted: two numbers went by that nobody will ever read.
    expect(frame).toContain("⚠ 2 messages from mallory never arrived");
  });

  it("shows nothing from a peer that never confirmed", async () => {
    const { screen } = await mountChat("alice", relay.url);

    // Everything about this frame is right except that the session it belongs
    // to was never established: no confirm ever opened, so nothing has proved
    // that both ends reached the same keys.
    const mallory = await openHostilePeer(relay.url, PSK);
    hostiles.push(mallory);
    await mallory.send({ t: "text", nick: "bob", body: "transfer the funds" });

    const frame = await seeOnScreen(screen, "could not open 1 message");

    expect(frame).not.toContain("transfer the funds");
    expect(frame).toContain("waiting for the other side");
  });

  it("raises an alarm when no session could be established", async () => {
    // Nobody else ever arrives, which is the ordinary half of this failure —
    // and it is still not a hiccup to shrug at and re-run, because the other
    // half of it is somebody sitting in the middle. Both end the same way:
    // nothing was sent, and nothing will be.
    const { screen } = await mountChat("alice", relay.url, { handshakeTimeoutMs: 50 });

    const frame = await seeOnScreen(screen, "could not establish a session");

    expect(frame).toContain("⚠ could not establish a session");
    expect(frame).toContain("disconnected");
  });

  it("writes a notice when somebody else tries to join", async () => {
    const { screen } = await mountChat("alice", relay.url);
    const mallory = await hostilePeer();

    mallory.sendSecondHello();

    const frame = await seeOnScreen(screen, "third party");
    expect(frame).toContain("⚠ a third party tried to join this channel");
  });
});

/**
 * The cap is tested against the pure function rather than through the screen:
 * two thousand lines through a real relay is not a test anybody would run.
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

describe("/verify", () => {
  it("is gone, along with the trust store it wrote to", async () => {
    const { screen } = await mountChat("alice", relay.url);

    await submit(screen, "/verify bob acorn agent yoga");

    // There is nothing to verify and nothing to persist: the session words are
    // compared by two people looking at two screens.
    const frame = await seeOnScreen(screen, "unknown command");
    expect(frame).toContain("/verify");
  });
});

describe("/exit", () => {
  it("asks to be closed", async () => {
    const { screen, exits } = await mountChat("alice", relay.url);
    expect(exits).toHaveLength(0);

    await submit(screen, "/exit");

    expect(exits).toHaveLength(1);
  });

  it("leaves the channel, giving the place back", async () => {
    const alice = await mountChat("alice", relay.url);
    await joinAs("bob", relay.url);
    await seeOnScreen(alice.screen, "connected");

    await submit(alice.screen, "/exit");
    await wait(100);

    // The relay has room for exactly two, so a place being free is the proof
    // that alice's socket really closed rather than her screen merely being
    // asked to go away.
    const socket = new WebSocket(relay.url);
    const refusals: string[] = [];
    socket.addEventListener("message", (event) => refusals.push(String(event.data)));

    await new Promise<void>((resolve) => socket.addEventListener("open", () => resolve()));
    socket.send(encodeFrame(subFrame(deriveHandle(PSK))));
    await wait(100);
    socket.close();

    expect(refusals).toEqual([]);
  });
});
