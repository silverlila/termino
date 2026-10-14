import { afterEach, beforeEach, describe, expect, it } from "bun:test";
import { joinChat, newChat, passphraseChat } from "../../src/launch.ts";
import type { Session } from "../../src/session.ts";
import { Termino } from "../../src/tui/Termino.tsx";
import { startTestRelay, unlimitedClock, wait, type TestRelay } from "../support/harness.ts";
import {
  closeChats,
  mount,
  pressEnter,
  seeOnScreen,
  submit,
  type Screen,
} from "../support/tui.tsx";

/**
 * From the start screen into a live chat, against a real relay: the invite the
 * starter is shown has to be the one that brings the other person in.
 */

let relay: TestRelay;
const sessions: Session[] = [];

beforeEach(() => {
  relay = startTestRelay({ now: unlimitedClock() });
  exits = 0;
});

afterEach(() => {
  for (const session of sessions) session.close();
  sessions.length = 0;
  closeChats();
  relay.server.stop(true);
});

let exits = 0;

async function mountTermino(nick: string): Promise<Screen> {
  return await mount(
    <Termino
      relay={relay.url}
      nick={nick}
      start={() => newChat(relay.url)}
      join={joinChat}
      meet={(room, phrase) => passphraseChat(relay.url, room, phrase)}
      onExit={() => (exits += 1)}
    />,
  );
}

/** Stands in for the terminal at the one place the screen touches it: the clipboard. */
function clipboardOf(screen: Screen, accepts: boolean): string[] {
  const copied: string[] = [];
  screen.renderer.copyToClipboardOSC52 = (text: string) => {
    copied.push(text);
    return accepts;
  };
  return copied;
}

async function joinThroughScreen(nick: string, invite: string): Promise<Screen> {
  const screen = await mountTermino(nick);
  await seeOnScreen(screen, "What do you want to do?");
  screen.mockInput.pressArrow("down");
  await pressEnter(screen);
  await seeOnScreen(screen, "Paste the invite");
  await submit(screen, invite);
  await seeOnScreen(screen, "write a message");
  return screen;
}

/** The invite as drawn in its panel, with the panel's wrapping squeezed out. */
function inviteOn(frame: string): string {
  const match = /([a-z]+(?:-[a-z│\s]+)+@[\w.:[\]]+)/.exec(frame.replace(/│/g, ""));
  return (match?.[1] ?? "").replace(/\s+/g, "");
}

async function startChat(nick: string): Promise<{ screen: Screen; invite: string }> {
  const screen = await mountTermino(nick);
  await pressEnter(screen);

  const frame = await seeOnScreen(screen, "your invite");
  return { screen, invite: inviteOn(frame) };
}

describe("starting a chat from the start screen", () => {
  it("shows the invite, which brings the other person in under the name given", async () => {
    const { screen, invite } = await startChat("alice");

    const joined = joinChat(invite);
    if (!joined.ok) throw new Error(`the invite on screen did not read: ${joined.reason} (${invite})`);
    const heard: string[] = [];
    sessions.push(
      await joined.chat.connect("bob", {
        onMessage: (message) => heard.push(`${message.nick}: ${message.body}`),
      }),
    );
    await seeOnScreen(screen, "session words:");

    await submit(screen, "hi bob");

    const deadline = Date.now() + 3000;
    while (heard.length === 0 && Date.now() < deadline) await wait(10);
    expect(heard).toEqual(["alice: hi bob"]);
  });

  it("stops showing the invite once the other person is in", async () => {
    // Nobody needs it after that, and it is the whole secret: it should not
    // stay on a screen somebody might glance at for the rest of the chat.
    const { screen, invite } = await startChat("alice");
    const joined = joinChat(invite);
    if (!joined.ok) throw new Error(joined.reason);
    sessions.push(await joined.chat.connect("bob", {}));

    const frame = await seeOnScreen(screen, "session words:");
    expect(frame).not.toContain("your invite");
  });

  it("copies exactly the invite on /copy, and says so", async () => {
    const { screen, invite } = await startChat("alice");
    const copied = clipboardOf(screen, true);

    await submit(screen, "/copy");

    await seeOnScreen(screen, "invite sent to the clipboard");
    expect(copied).toEqual([invite]);
  });

  it("says so when the terminal refuses the copy, rather than claiming it worked", async () => {
    const { screen } = await startChat("alice");
    clipboardOf(screen, false);

    await submit(screen, "/copy");

    const frame = await seeOnScreen(screen, "does not allow copying");
    expect(frame).not.toContain("invite sent to the clipboard");
  });

  it("leaves through onExit on /exit", async () => {
    const { screen } = await startChat("alice");

    await submit(screen, "/exit");

    expect(exits).toBe(1);
  });
});

describe("joining a chat from the start screen", () => {
  it("shows no invite panel while waiting, having none to show", async () => {
    // Nobody has started this chat, so the handshake never completes and the
    // screen stays in the state the panel would appear in.
    const screen = await joinThroughScreen("bob", newChat(relay.url).invite ?? "");

    const frame = await seeOnScreen(screen, "waiting for the other side");
    expect(frame).not.toContain("your invite");
  });

  it("connects with an invite pasted in", async () => {
    const started = newChat(relay.url);
    const pending = started.connect("alice", {});

    const screen = await joinThroughScreen("bob", started.invite ?? "");

    sessions.push(await pending);
    const frame = await seeOnScreen(screen, "session words:");
    expect(frame).not.toContain("your invite");
  });

  it("has no invite to /copy", async () => {
    const screen = await joinThroughScreen("bob", newChat(relay.url).invite ?? "");
    const copied = clipboardOf(screen, true);

    await submit(screen, "/copy");

    await seeOnScreen(screen, "there is no invite to copy");
    expect(copied).toEqual([]);
  });
});

async function meetThroughScreen(nick: string, room: string, phrase: string): Promise<Screen> {
  const screen = await mountTermino(nick);
  await seeOnScreen(screen, "What do you want to do?");
  screen.mockInput.pressArrow("down");
  screen.mockInput.pressArrow("down");
  await pressEnter(screen);
  await seeOnScreen(screen, "Room name");
  await submit(screen, room);
  await seeOnScreen(screen, "Passphrase for room");
  await submit(screen, phrase);
  return screen;
}

describe("meeting with a passphrase from the start screen", () => {
  it("shows a mismatched phrase as a failure, never as a session", async () => {
    // The peer's confirm cannot be opened, which the screen says at once; the alarm
    // naming a possible man in the middle follows at the handshake timeout, which the
    // session tests cover rather than this one waiting twenty seconds.
    const other = passphraseChat(relay.url, "silver-and-ana", "the blue house on the corner");
    if (!other.ok) throw new Error(other.reason);
    // It waits out its own handshake timeout and fails when the relay stops; caught here
    // so that failure is not an unhandled rejection.
    void other.chat.connect("mallory", {}).catch(() => undefined);

    const screen = await meetThroughScreen("alice", "silver-and-ana", "a different phrase entirely");

    const frame = await seeOnScreen(screen, "could not open");
    expect(frame).not.toContain("session words:");
    await submit(screen, "/exit");
  });

  it("connects to somebody in the same room with the same phrase", async () => {
    const other = passphraseChat(relay.url, "silver-and-ana", "the blue house on the corner");
    if (!other.ok) throw new Error(other.reason);
    const pending = other.chat.connect("bob", {});

    const screen = await mountTermino("alice");
    await seeOnScreen(screen, "What do you want to do?");
    screen.mockInput.pressArrow("down");
    screen.mockInput.pressArrow("down");
    await pressEnter(screen);
    await seeOnScreen(screen, "Room name");
    await submit(screen, "silver-and-ana");
    await seeOnScreen(screen, "Passphrase for room");
    await submit(screen, "the blue house on the corner");

    sessions.push(await pending);
    const frame = await seeOnScreen(screen, "session words:");
    expect(frame).not.toContain("your invite");
  });
});

