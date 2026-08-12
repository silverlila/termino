import { afterEach, beforeEach, describe, expect, it } from "bun:test";
import { testRender } from "@opentui/react/test-utils";
import { bytesToHex } from "@noble/hashes/utils.js";
import type { ChannelKeys } from "../../../src/crypto/derive.ts";
import { fingerprint } from "../../../src/crypto/fingerprint.ts";
import { loadOrCreateIdentity } from "../../../src/crypto/identity.ts";
import { startSession, type Session } from "../../../src/client/session.ts";
import { App } from "../../../src/client/tui/App.tsx";
import { removeTempDirs, startTestRelay, tempDir, wait, type TestRelay } from "../../support/harness.ts";

/**
 * The TUI is rendered headlessly: `testRender` drives a renderer over test
 * streams at an explicit `width`/`height`, so nothing here needs a TTY and the
 * suite passes with stdout redirected to a file.
 *
 * Keys are constructed rather than derived. Derivation is argon2id and costs
 * ~850 ms; what these cases are about is the screen, and `derive.test.ts`
 * already proves the derivation.
 */

const WIDTH = 80;
const HEIGHT = 20;

const CHANNEL: ChannelKeys = {
  handle: bytesToHex(crypto.getRandomValues(new Uint8Array(16))),
  msgKey: crypto.getRandomValues(new Uint8Array(32)),
};

type Screen = Awaited<ReturnType<typeof testRender>>;

let relay: TestRelay;
let sessions: Session[] = [];
let screens: Screen[] = [];

/**
 * Mounts the App against the live relay and waits until it is connected.
 *
 * `testRender` switches React into its act environment, and it is switched
 * straight back off: what these cases wait on arrives from a WebSocket, so
 * every update is by definition outside an `act` call, and leaving it on
 * yields a warning per message and nothing else.
 */
async function mountApp(nick: string): Promise<{ screen: Screen; ownFingerprint: string }> {
  const identity = loadOrCreateIdentity(tempDir(`id-${nick}`));

  const screen = await testRender(
    <App
      channel="demo"
      nick={nick}
      identity={identity}
      keys={CHANNEL}
      relayUrl={relay.url}
      terminoDir={tempDir(`trust-${nick}`)}
    />,
    { width: WIDTH, height: HEIGHT },
  );

  (globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = false;
  screens.push(screen);
  await seeOnScreen(screen, "connected");

  return { screen, ownFingerprint: fingerprint(identity.publicKey) };
}

/** A peer with no terminal at all, so the App is the only thing under test. */
async function joinAs(nick: string): Promise<Session> {
  const session = await startSession({
    keys: CHANNEL,
    nick,
    identity: loadOrCreateIdentity(tempDir(`id-${nick}`)),
    relayUrl: relay.url,
    terminoDir: tempDir(`trust-${nick}`),
  });

  sessions.push(session);
  return session;
}

async function type(screen: Screen, text: string): Promise<void> {
  await screen.mockInput.typeText(text);
  await screen.renderOnce();
}

async function pressEnter(screen: Screen): Promise<void> {
  screen.mockInput.pressEnter();
  await screen.renderOnce();
}

/**
 * Renders until `text` is on screen, and returns that frame.
 *
 * Time-based rather than `waitForFrame`, whose budget is a number of render
 * passes: what these cases wait on is a WebSocket round trip through a real
 * relay, and twenty passes of an idle tree go by in well under a millisecond.
 */
async function seeOnScreen(screen: Screen, text: string, timeoutMs = 3000): Promise<string> {
  const deadline = Date.now() + timeoutMs;

  while (true) {
    await screen.renderOnce();

    const frame = screen.captureCharFrame();
    if (frame.includes(text)) return frame;

    if (Date.now() > deadline) throw new Error(`never saw "${text}" on screen:\n${frame}`);
    await wait(10);
  }
}

beforeEach(() => {
  sessions = [];
  screens = [];
  relay = startTestRelay();
});

afterEach(() => {
  for (const screen of screens) screen.renderer.destroy();
  for (const session of sessions) session.close();
  relay.server.stop(true);
  removeTempDirs();
});

describe("the chat screen", () => {
  it("shows the channel, the nickname and this device's own fingerprint", async () => {
    const { screen, ownFingerprint } = await mountApp("alice");
    const frame = screen.captureCharFrame();

    expect(frame).toContain("#demo");
    expect(frame).toContain("alice");
    // The first two words are enough: eight of them wrap past 80 columns, and
    // this is asserting that the real fingerprint is on screen, not a stub.
    expect(frame).toContain(ownFingerprint.split(" ").slice(0, 2).join(" "));
  });

  it("shows a message from a peer, marked unverified", async () => {
    const { screen } = await mountApp("alice");
    const bob = await joinAs("bob");

    await bob.send("shipping it now");
    const frame = await seeOnScreen(screen, "shipping it now");

    expect(frame).toContain("?bob");
  });

  it("shows what this user sends, marked with their own verified key", async () => {
    const { screen } = await mountApp("alice");
    await joinAs("bob");

    await type(screen, "ready when you are");
    await pressEnter(screen);

    const frame = await seeOnScreen(screen, "ready when you are");
    expect(frame).toContain("✓alice");
  });

  it("clears the composer once a line has been sent", async () => {
    const { screen } = await mountApp("alice");
    await joinAs("bob");

    await type(screen, "ready when you are");
    await pressEnter(screen);
    await seeOnScreen(screen, "✓alice");

    // The sent line is in the transcript, so it is still on screen once — the
    // composer having kept a copy would make it twice.
    const frame = screen.captureCharFrame();
    expect(frame.split("ready when you are")).toHaveLength(2);
  });

  it("keeps half-typed input intact when a message arrives", async () => {
    const { screen } = await mountApp("alice");
    const bob = await joinAs("bob");

    await type(screen, "half a thought");
    expect(screen.captureCharFrame()).toContain("half a thought");

    await bob.send("shipping it now");
    const frame = await seeOnScreen(screen, "shipping it now");

    // The regression this whole rewrite exists for: the old client called
    // console.clear() and reprinted the transcript, erasing the draft.
    expect(frame).toContain("half a thought");
  });

  it("tells the user when the relay drops a message rather than failing silently", async () => {
    const { screen } = await mountApp("alice");
    await joinAs("bob");

    // The relay's bucket is five per ten seconds; the sixth comes back as an
    // error frame addressed to this connection alone.
    for (let sent = 0; sent < 6; sent++) {
      await type(screen, `line ${sent}`);
      await pressEnter(screen);
      await wait(10);
    }

    const frame = await seeOnScreen(screen, "rate_limited");
    expect(frame).toContain("the relay rejected a message");
  });

  it("reports that nobody else is here until somebody is", async () => {
    const { screen } = await mountApp("alice");
    expect(screen.captureCharFrame()).toContain("just you");

    await joinAs("bob");
    const frame = await seeOnScreen(screen, "2 here");
    expect(frame).not.toContain("just you");
  });
});
