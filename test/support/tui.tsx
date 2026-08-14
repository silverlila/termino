import { testRender } from "@opentui/react/test-utils";
import { generatePsk } from "../../shared/crypto/psk.ts";
import {
  startSession,
  type Session,
  type SessionHandlers,
  type SessionOptions,
} from "../../src/session.ts";
import { App } from "../../src/tui/App.tsx";
import { wait } from "./harness.ts";

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
 * One secret for every test in the suite, and both ends of every conversation
 * share it: a session key comes from the exchange rather than from the secret,
 * so two clients on one secret still land in a different session every time.
 */
export const PSK = generatePsk();

export type Screen = Awaited<ReturnType<typeof testRender>>;

export interface Chat {
  screen: Screen;
  /** One entry per time the screen asked to be closed. */
  exits: number[];
}

export interface Peer {
  session: Session;
  /** Bodies this peer received, for proving something was or was not sent. */
  received: string[];
}

const screens: Screen[] = [];
const peers: Peer[] = [];

/**
 * Mounts the App against a relay.
 *
 * It does not wait for a connection, because there is nothing to connect to
 * yet: a v2 session is not established until a peer has answered and its
 * confirm has opened. Call `joinAs` and then wait for "connected".
 *
 * `testRender` switches React into its act environment, and it is switched
 * straight back off: what these tests wait on arrives over a WebSocket, so
 * every update is by definition outside an `act` call, and leaving it on
 * yields a warning per message and nothing else.
 */
export async function mountChat(
  nick: string,
  relayUrl: string,
  // Presence and the handshake are both measured in tens of seconds. A test
  // that watches somebody go quiet, or watches nobody arrive at all, hands in
  // its own timings or spends the difference asleep.
  timings: Pick<
    SessionOptions,
    "pingIntervalMs" | "presenceExpiryMs" | "handshakeTimeoutMs"
  > = {},
): Promise<Chat> {
  // The real one tears down the renderer and ends the process; a test records
  // that it was asked to instead, and keeps its screen.
  const exits: number[] = [];

  // The same closure the CLI builds: the secret is captured here rather than
  // handed to the component, so nothing secret is a prop in a test either.
  const connect = (handlers: SessionHandlers) =>
    startSession({ psk: PSK, nick, relayUrl, handlers, ...timings });

  const screen = await testRender(
    <App nick={nick} connect={connect} onExit={() => exits.push(Date.now())} />,
    { width: WIDTH, height: HEIGHT },
  );

  (globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = false;
  screens.push(screen);

  // One pass, so the caller is handed a screen with something drawn on it
  // rather than the empty buffer a renderer starts with.
  await screen.renderOnce();

  return { screen, exits };
}

/** A peer with no terminal at all, so the App stays the only thing under test.
 * It holds the same secret, so it completes the handshake and the screen goes
 * to "connected". */
export async function joinAs(nick: string, relayUrl: string): Promise<Peer> {
  const received: string[] = [];

  const session = await startSession({
    psk: PSK,
    nick,
    relayUrl,
    handlers: { onMessage: (message) => received.push(message.body) },
  });

  const peer = { session, received };
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
 * `afterEach`. */
export function closeChats(): void {
  for (const screen of screens) screen.renderer.destroy();
  for (const peer of peers) peer.session.close();

  screens.length = 0;
  peers.length = 0;
}
