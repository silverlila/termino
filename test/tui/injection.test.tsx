import { afterEach, beforeEach, describe, expect, it } from "bun:test";
import {
  openHostilePeer,
  startTestRelay,
  unlimitedClock,
  type HostilePeer,
  type TestRelay,
} from "../support/harness.ts";
import { closeChats, mountChat, PSK, seeOnScreen } from "../support/tui.tsx";

/**
 * What the other participant can do to this one's terminal.
 *
 * The attacker here holds the secret and completes a real handshake, so
 * everything they send opens under the receiving chain — the cryptography is
 * working exactly as intended. What is under test is whether the bytes they
 * chose reach the screen.
 *
 * Their frames are built without going through `sealMessage`, which refuses
 * these bodies itself: going through it would leave the probe passing because
 * nothing was ever sent.
 */

const ESC = "\u001B";
const BEL = "\u0007";

let relay: TestRelay;
let mallory: HostilePeer;

beforeEach(() => {
  relay = startTestRelay({ now: unlimitedClock() });
});

afterEach(() => {
  mallory.close();
  closeChats();
  relay.server.stop(true);
});

describe("a hostile message body", () => {
  it("cannot reach the frame", async () => {
    const { screen } = await mountChat("alice", relay.url);
    mallory = await openHostilePeer(relay.url, PSK);
    await mallory.confirm();

    // OSC 52 writes the attacker's text into the reader's system clipboard;
    // the rest clears the screen and repaints it in their colours.
    await mallory.send({
      t: "text",
      nick: "bob",
      body: `hi${ESC}]52;c;cGF3bmVk${BEL}${ESC}[2J${ESC}[31m`,
    });

    // The positive control: these assertions are all absences, and an absence
    // passes against a blank frame. The rejection notice proves the frame
    // arrived, was refused, and was said out loud.
    const frame = await seeOnScreen(screen, "could not open 1 message");

    expect(frame).not.toContain(ESC);
    expect(frame).not.toContain(BEL);
  });

  it("cannot forge a transcript line with a newline", async () => {
    const { screen } = await mountChat("alice", relay.url);
    mallory = await openHostilePeer(relay.url, PSK);
    await mallory.confirm();

    await mallory.send({ t: "text", nick: "bob", body: "ok\n00:00 alice  forged line" });

    const frame = await seeOnScreen(screen, "could not open 1 message");

    // A single newline would otherwise put words on screen under somebody
    // else's name. The whole screen comes back with its rows joined by "\n",
    // so what is asserted is the absence of the forged row rather than of the
    // character.
    expect(frame).not.toContain("forged line");
    expect(frame).not.toMatch(/\d\d:\d\d\s+alice\s+forged/);
  });

  it("cannot spell a nickname with a zero-width character", async () => {
    const { screen } = await mountChat("alice", relay.url);
    mallory = await openHostilePeer(relay.url, PSK);
    await mallory.confirm();

    // Two nicknames that render identically are the same impersonation an
    // escape sequence buys, spelt in characters that draw as nothing.
    await mallory.send({ t: "text", nick: "al\u200Bice", body: "transfer the funds" });

    const frame = await seeOnScreen(screen, "could not open 1 message");

    expect(frame).not.toContain("transfer the funds");
  });
});
