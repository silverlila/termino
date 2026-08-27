/**
 * Scaffolding for tests that put the App on a screen.
 *
 * `testRender` takes width and height explicitly and needs no TTY, so these tests pass
 * with stdout redirected to a file. It sets IS_REACT_ACT_ENVIRONMENT and leaves it set
 * until `renderer.destroy()`; these tests are driven by real sockets, so it is switched
 * back off — polling inside act() deadlocks, and every socket update would otherwise log
 * a warning. It also returns before anything is drawn: `captureCharFrame()` is empty
 * until the first `renderOnce()`.
 *
 * `waitFor`/`waitForFrame` budget in render passes, not milliseconds — ~20 passes of an
 * idle tree elapse in under a millisecond — so anything awaiting a WebSocket round trip
 * polls `renderOnce()` against a wall-clock deadline.
 */

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

export const WIDTH = 80;
export const HEIGHT = 20;

export const PSK = generatePsk();

export type Screen = Awaited<ReturnType<typeof testRender>>;

export interface Chat {
  screen: Screen;
  exits: number[];
}

export interface Peer {
  session: Session;
  received: string[];
}

const screens: Screen[] = [];
const peers: Peer[] = [];

export async function mountChat(
  nick: string,
  relayUrl: string,
  timings: Pick<
    SessionOptions,
    "pingIntervalMs" | "presenceExpiryMs" | "handshakeTimeoutMs"
  > = {},
): Promise<Chat> {
  const exits: number[] = [];

  const connect = (handlers: SessionHandlers) =>
    startSession({ psk: PSK, nick, relayUrl, handlers, ...timings });

  const screen = await testRender(
    <App nick={nick} connect={connect} onExit={() => exits.push(Date.now())} />,
    { width: WIDTH, height: HEIGHT },
  );

  (globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = false;
  screens.push(screen);

  await screen.renderOnce();

  return { screen, exits };
}

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

export async function submit(screen: Screen, line: string): Promise<void> {
  await typeText(screen, line);
  await pressEnter(screen);
}

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

export function closeChats(): void {
  for (const screen of screens) screen.renderer.destroy();
  for (const peer of peers) peer.session.close();

  screens.length = 0;
  peers.length = 0;
}
