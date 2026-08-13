import { afterEach, beforeEach, describe, expect, it } from "bun:test";
import { ed25519 } from "@noble/curves/ed25519.js";
import { bytesToHex } from "@noble/hashes/utils.js";
import { seal } from "../../shared/crypto/seal.ts";
import { encodeFrame, msgFrame, subFrame } from "../../shared/protocol/frame.ts";
import { sign } from "../../shared/protocol/message.ts";
import { removeTempDirs, startTestRelay, type TestRelay } from "../support/harness.ts";
import { CHANNEL_KEYS, closeChats, mountChat, seeOnScreen } from "../support/tui.tsx";

/**
 * What a channel member can do to the other members' terminals.
 *
 * The attacker here holds the channel key and a device key of their own, so
 * everything they send decrypts and verifies — the cryptography is working.
 * What is under test is whether the bytes they chose reach the screen.
 */

const ESC = "\u001B";
const BEL = "\u0007";

/** A device key of the attacker's own: they sign honestly, and the signature
 * verifies. Nothing about this attack is a broken signature. */
const HOSTILE_SECRET_KEY = Uint8Array.from({ length: 32 }, (_, index) => index + 7);
const HOSTILE_PUBLIC_KEY_HEX = bytesToHex(ed25519.getPublicKey(HOSTILE_SECRET_KEY));

let relay: TestRelay;
const hostileSockets: WebSocket[] = [];

beforeEach(() => {
  relay = startTestRelay();
});

afterEach(() => {
  for (const socket of hostileSockets) socket.close();
  hostileSockets.length = 0;
  closeChats();
  relay.server.stop(true);
  removeTempDirs();
});

/**
 * Seals and sends a body no honest client would produce, over a socket of its
 * own — the relay forwards whatever it is handed.
 *
 * Built from `sign`, `seal` and `msgFrame` rather than from `sealMessage`,
 * which now refuses these bodies itself: going through it would leave the
 * probe passing because nothing was ever sent.
 */
async function sendHostileBody(nick: string, body: string): Promise<void> {
  const signed = sign(
    { from: HOSTILE_PUBLIC_KEY_HEX, nick, body, ts: Date.now() },
    CHANNEL_KEYS.handle,
    HOSTILE_SECRET_KEY,
  );
  const { nonce, ciphertext } = await seal(
    CHANNEL_KEYS.msgKey,
    new TextEncoder().encode(JSON.stringify(signed)),
  );

  const socket = new WebSocket(relay.url);
  hostileSockets.push(socket);
  await new Promise<void>((resolve) => socket.addEventListener("open", () => resolve()));

  socket.send(encodeFrame(subFrame(CHANNEL_KEYS.handle)));
  socket.send(encodeFrame(msgFrame(CHANNEL_KEYS.handle, nonce, ciphertext)));
}

describe("a hostile message body", () => {
  it("a hostile body cannot reach the frame", async () => {
    const { screen } = await mountChat("alice", relay.url);

    // OSC 52 writes the attacker's text into the reader's system clipboard;
    // the rest clears the screen and repaints it in their colours.
    await sendHostileBody("bob", `hi${ESC}]52;c;cGF3bmVk${BEL}${ESC}[2J${ESC}[31m`);

    // The positive control: these assertions are all absences, and an absence
    // passes against a blank frame. The rejection notice proves the frame
    // arrived, was refused, and was said out loud.
    const frame = await seeOnScreen(screen, "could not open 1 message");

    expect(frame).not.toContain(ESC);
    expect(frame).not.toContain(BEL);
  });

  it("a newline cannot forge a transcript line", async () => {
    const { screen } = await mountChat("alice", relay.url);

    await sendHostileBody("bob", "ok\n00:00 ?alice  forged line");

    const frame = await seeOnScreen(screen, "could not open 1 message");

    // Every line carries an Ed25519 signature, and a single newline would
    // otherwise put words on screen under somebody else's name.
    expect(frame).not.toContain("forged line");
    expect(frame).not.toMatch(/\d\d:\d\d\s+\?alice/);
  });
});
