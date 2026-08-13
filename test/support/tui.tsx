import { testRender } from "@opentui/react/test-utils";
import { bytesToHex } from "@noble/hashes/utils.js";
import type { ChannelKeys } from "../../shared/crypto/derive.ts";
import { fingerprint } from "../../shared/crypto/fingerprint.ts";
import { loadOrCreateIdentity } from "../../shared/crypto/identity.ts";
import { startSession, type Session, type SessionHandlers } from "../../src/session.ts";
import { App } from "../../src/tui/App.tsx";
import { tempDir, wait } from "./harness.ts";

/**
 * Scaffolding for the tests that put the App on a screen: mounting it against
 * a live relay, giving it somebody to talk to, typing at it, and waiting for
 * something to appear.
 *
 * The TUI is rendered headlessly — `testRender` drives a renderer over test
 * streams at an explicit width and height, so nothing here needs a TTY and the
 * suite passes with stdout redirected to a file.
 */

export const WIDTH = 80;
export const HEIGHT = 20;

/**
 * One channel for every test in the suite. Constructed rather than derived:
 * derivation is argon2id and costs ~850 ms per call, and what these tests are
 * about is the screen — `derive.test.ts` proves the derivation.
 */
export const CHANNEL_KEYS: ChannelKeys = {
  handle: bytesToHex(crypto.getRandomValues(new Uint8Array(16))),
  msgKey: crypto.getRandomValues(new Uint8Array(32)),
};

export type Screen = Awaited<ReturnType<typeof testRender>>;

export interface Chat {
  screen: Screen;
  /** This client's own fingerprint, as its status bar shows it. */
  fingerprint: string;
  /** Where this client's trust store lives, so a test can read what it wrote
   * through the store's own loader rather than parsing the file. */
  trustDir: string;
  /** One entry per time the screen asked to be closed. */
  exits: number[];
}

export interface Peer {
  session: Session;
  /** What this peer would read aloud over the phone. */
  fingerprint: string;
  /** Bodies this peer received, for proving something was or was not sent. */
  received: string[];
}

const screens: Screen[] = [];
const peers: Peer[] = [];

/**
 * Mounts the App against a relay and waits until it is connected.
 *
 * `testRender` switches React into its act environment, and it is switched
 * straight back off: what these tests wait on arrives over a WebSocket, so
 * every update is by definition outside an `act` call, and leaving it on
 * yields a warning per message and nothing else.
 */
export async function mountChat(nick: string, relayUrl: string): Promise<Chat> {
  const identity = loadOrCreateIdentity(tempDir(`id-${nick}`));
  const trustDir = tempDir(`trust-${nick}`);
  const ownFingerprint = fingerprint(identity.publicKey);
  // The real one tears down the renderer and ends the process; a test records
  // that it was asked to instead, and keeps its screen.
  const exits: number[] = [];

  // The same closure the CLI builds: the keys and the trust directory are
  // captured here rather than handed to the component, so nothing secret is a
  // prop in a test either.
  const connect = (handlers: SessionHandlers) =>
    startSession({ keys: CHANNEL_KEYS, nick, identity, relayUrl, terminoDir: trustDir, handlers });

  const screen = await testRender(
    <App
      channel="demo"
      nick={nick}
      fingerprint={ownFingerprint}
      connect={connect}
      onExit={() => exits.push(Date.now())}
    />,
    { width: WIDTH, height: HEIGHT },
  );

  (globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = false;
  screens.push(screen);
  await seeOnScreen(screen, "connected");

  return { screen, fingerprint: ownFingerprint, trustDir, exits };
}

/**
 * A peer with no terminal at all, so the App stays the only thing under test.
 * Each call generates a fresh identity, so calling it twice under one nickname
 * is a device that reinstalled — or somebody else claiming the name.
 */
export function joinAs(nick: string, relayUrl: string): Promise<Peer> {
  return join(nick, relayUrl, CHANNEL_KEYS);
}

/**
 * A peer whose frames route to this channel and cannot be opened in it: the
 * handle matches, the message key does not. A handle travels in the clear, so
 * this is what anybody who learns one can do without knowing the password.
 */
export function joinWithWrongKey(nick: string, relayUrl: string): Promise<Peer> {
  const wrongKeys: ChannelKeys = {
    handle: CHANNEL_KEYS.handle,
    msgKey: crypto.getRandomValues(new Uint8Array(32)),
  };

  return join(nick, relayUrl, wrongKeys);
}

async function join(nick: string, relayUrl: string, keys: ChannelKeys): Promise<Peer> {
  const identity = loadOrCreateIdentity(tempDir(`id-${nick}`));
  const received: string[] = [];

  const session = await startSession({
    keys,
    nick,
    identity,
    relayUrl,
    terminoDir: tempDir(`trust-${nick}`),
    handlers: { onMessage: (message) => received.push(message.body) },
  });

  const peer = { session, fingerprint: fingerprint(identity.publicKey), received };
  peers.push(peer);
  return peer;
}

export async function typeText(screen: Screen, text: string): Promise<void> {
  await screen.mockInput.typeText(text);
  await screen.renderOnce();
}

export async function pressEnter(screen: Screen): Promise<void> {
  screen.mockInput.pressEnter();
  await screen.renderOnce();
}

/** Types a whole line and sends it. */
export async function submit(screen: Screen, line: string): Promise<void> {
  await typeText(screen, line);
  await pressEnter(screen);
}

/**
 * Renders until `text` is on screen, and returns that frame.
 *
 * Time-based rather than `waitForFrame`, whose budget is a number of render
 * passes: what these tests wait on is a WebSocket round trip through a real
 * relay, and twenty passes of an idle tree go by in well under a millisecond.
 */
export async function seeOnScreen(screen: Screen, text: string, timeoutMs = 3000): Promise<string> {
  const deadline = Date.now() + timeoutMs;

  while (true) {
    await screen.renderOnce();

    const frame = screen.captureCharFrame();
    if (frame.includes(text)) return frame;

    if (Date.now() > deadline) throw new Error(`never saw "${text}" on screen:\n${frame}`);
    await wait(10);
  }
}

/** Tears down every screen and peer this module has handed out. Call from
 * `afterEach`, alongside `removeTempDirs()`. */
export function closeChats(): void {
  for (const screen of screens) screen.renderer.destroy();
  for (const peer of peers) peer.session.close();

  screens.length = 0;
  peers.length = 0;
}
