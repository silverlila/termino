import { afterEach, describe, expect, it } from "bun:test";
import { joinChat, newChat, passphraseChat, type Chat } from "../../src/launch.ts";
import { Start } from "../../src/tui/Start.tsx";
import { wait } from "../support/harness.ts";
import { closeChats, mount, pressEnter, seeOnScreen, submit, type Screen } from "../support/tui.tsx";

/**
 * The start screen on its own: what it asks, what it refuses, and where Esc takes you.
 * Nothing here connects — choosing hands a chat to `onChosen`, and what happens next is
 * Termino.test.tsx's business.
 */

const RELAY = "wss://relay.example:8787";

interface Started {
  screen: Screen;
  chosen: { nick: string; chat: Chat }[];
}

async function mountStart(nick?: string, meetings: string[] = []): Promise<Started> {
  const chosen: Started["chosen"] = [];

  const screen = await mount(
    <Start
      relay={RELAY}
      nick={nick}
      start={() => newChat(RELAY)}
      join={joinChat}
      meet={(room, phrase) => {
        meetings.push(phrase);
        return passphraseChat(RELAY, room, phrase);
      }}
      onChosen={(chosenNick, chat) => chosen.push({ nick: chosenNick, chat })}
    />,
  );

  return { screen, chosen };
}

// React commits a step change on its own schedule, after the key that caused it,
// and keys sent before the new step's widget mounts land on nothing — so each
// step change waits to see the step's own words before typing into it.
async function chooseJoin(screen: Screen): Promise<void> {
  await seeOnScreen(screen, "What do you want to do?");
  await pressDown(screen);
  await pressEnter(screen);
  await seeOnScreen(screen, "Paste the invite");
}

async function chooseMeet(screen: Screen): Promise<void> {
  await seeOnScreen(screen, "What do you want to do?");
  await pressDown(screen);
  await pressDown(screen);
  await pressEnter(screen);
  await seeOnScreen(screen, "Room name");
}

async function reachPhrase(screen: Screen, room: string): Promise<void> {
  await chooseMeet(screen);
  await submit(screen, room);
  await seeOnScreen(screen, `Passphrase for room ${room}`);
}

async function pressEscape(screen: Screen): Promise<void> {
  screen.mockInput.pressEscape();
  await screen.renderOnce();
}

async function pressDown(screen: Screen): Promise<void> {
  screen.mockInput.pressArrow("down");
  await screen.renderOnce();
}

afterEach(() => {
  closeChats();
});

describe("the first frame", () => {
  it("shows the unaudited banner and the relay a new chat would meet on", async () => {
    const { screen } = await mountStart();

    const frame = screen.captureCharFrame();
    expect(frame).toContain("unaudited");
    expect(frame).toContain(`new chats and passphrase rooms meet on ${RELAY}`);
    expect(frame).toContain("Your name");
  });
});

describe("the name", () => {
  it("is required", async () => {
    const { screen } = await mountStart();

    await pressEnter(screen);

    await seeOnScreen(screen, "a nickname is required");
  });

  it("is held to the same rule as --nick", async () => {
    // The status bar draws the name unescaped, so the screen that asks for it
    // cannot be a way around the check the flag goes through.
    const { screen } = await mountStart();

    await submit(screen, "a".repeat(33));

    await seeOnScreen(screen, "over the limit of 32");
    expect(screen.captureCharFrame()).toContain("Your name");
  });

  it("leads to the choice, greeting you by it", async () => {
    const { screen } = await mountStart();

    await submit(screen, "alice");

    const frame = await seeOnScreen(screen, "Hi alice. What do you want to do?");
    expect(frame).toContain("Start a new chat");
    expect(frame).toContain("Join a chat");
  });

  it("is taken without the spaces around it", async () => {
    const { screen, chosen } = await mountStart();

    await submit(screen, "  alice  ");
    await seeOnScreen(screen, "Hi alice. What do you want to do?");
    await pressEnter(screen);

    expect(chosen[0]?.nick).toBe("alice");
  });

  it("is skipped when --nick already gave one", async () => {
    const { screen } = await mountStart("alice");

    const frame = screen.captureCharFrame();
    expect(frame).toContain("Hi alice.");
    expect(frame).not.toContain("Your name");
  });
});

describe("starting a chat", () => {
  it("hands over a chat that carries an invite to show", async () => {
    const { screen, chosen } = await mountStart("alice");

    await pressEnter(screen);

    expect(chosen).toHaveLength(1);
    expect(chosen[0]?.nick).toBe("alice");
    expect(chosen[0]?.chat.invite).toMatch(/@relay\.example:8787$/);
  });
});

describe("joining a chat", () => {
  it("asks for the invite", async () => {
    const { screen } = await mountStart("alice");

    await chooseJoin(screen);
  });

  it("says what is wrong with a bad invite and lets you try again", async () => {
    const { screen, chosen } = await mountStart("alice");
    await chooseJoin(screen);

    await submit(screen, "acorn-zzzz@relay.example");

    const frame = await seeOnScreen(screen, "not a word from the list: zzzz");
    expect(frame).toContain("Paste the invite");
    expect(chosen).toHaveLength(0);
  });

  it("hands over a chat with no invite of its own once the invite reads", async () => {
    const invite = newChat(RELAY).invite ?? "";
    const { screen, chosen } = await mountStart("bob");
    await chooseJoin(screen);

    await submit(screen, `  ${invite}  `);

    // Pasted with the spaces a terminal selection tends to carry.
    expect(chosen).toHaveLength(1);
    expect(chosen[0]?.nick).toBe("bob");
    expect(chosen[0]?.chat.invite).toBeNull();
  });
});

describe("meeting with a passphrase", () => {
  const PHRASE = "the blue house on the corner";

  it("asks for a room, refusing an empty one", async () => {
    const { screen } = await mountStart("alice");
    await chooseMeet(screen);

    await pressEnter(screen);

    await seeOnScreen(screen, "a room name is required");
  });

  it("asks for the phrase without ever drawing it", async () => {
    const { screen } = await mountStart("alice");
    await reachPhrase(screen, "silver-and-ana");

    await screen.mockInput.typeText(PHRASE);
    await screen.renderOnce();

    const frame = await seeOnScreen(screen, "•".repeat(PHRASE.length));
    expect(frame).not.toContain("blue");
    expect(frame).not.toContain("corner");
  });

  it("masks a pasted phrase too", async () => {
    const { screen } = await mountStart("alice");
    await reachPhrase(screen, "silver-and-ana");

    await screen.mockInput.pasteBracketedText(PHRASE);

    const frame = await seeOnScreen(screen, "•".repeat(PHRASE.length));
    expect(frame).not.toContain("blue");
  });

  it("takes back a character on backspace", async () => {
    const { screen } = await mountStart("alice");
    await reachPhrase(screen, "silver-and-ana");

    await screen.mockInput.typeText("abc");
    screen.mockInput.pressBackspace();

    await seeOnScreen(screen, "••");
    // The field is padded to its border, so two dots then spaces: never a third dot.
    expect(screen.captureCharFrame()).toMatch(/│ •• +│/);
  });

  /** What the field hands over on Enter, read through the seam it hands it to. */
  async function submitted(screen: Screen, chosen: Started["chosen"], meetings: string[]): Promise<string> {
    await pressEnter(screen);
    expect(chosen).toHaveLength(1);
    return meetings.at(-1) ?? "";
  }

  it("drops a pasted trailing newline and turns inner ones into spaces", async () => {
    const meetings: string[] = [];
    const { screen, chosen } = await mountStart("alice", meetings);
    await reachPhrase(screen, "silver-and-ana");

    await screen.mockInput.pasteBracketedText("the blue\r\nhouse on the corner\n");

    expect(await submitted(screen, chosen, meetings)).toBe("the blue house on the corner");
  });

  it("drops control and direction-override characters from a paste, where nobody could see them", async () => {
    const meetings: string[] = [];
    const { screen, chosen } = await mountStart("alice", meetings);
    await reachPhrase(screen, "silver-and-ana");

    await screen.mockInput.pasteBracketedText("the blue\u001B[2J house\u202E on\u0000 the corner");

    expect(await submitted(screen, chosen, meetings)).toBe("the blue[2J house on the corner");
  });

  it("types nothing for an arrow key or Tab", async () => {
    const meetings: string[] = [];
    const { screen, chosen } = await mountStart("alice", meetings);
    await reachPhrase(screen, "silver-and-ana");

    await screen.mockInput.typeText("the blue house");
    screen.mockInput.pressArrow("left");
    screen.mockInput.pressTab();
    await screen.mockInput.typeText(" on the corner");

    expect(await submitted(screen, chosen, meetings)).toBe("the blue house on the corner");
  });

  it("takes back a whole emoji, never half of one", async () => {
    const meetings: string[] = [];
    const { screen, chosen } = await mountStart("alice", meetings);
    await reachPhrase(screen, "silver-and-ana");

    await screen.mockInput.pasteBracketedText("the blue house 👍🏽x");
    screen.mockInput.pressBackspace();
    screen.mockInput.pressBackspace();
    await screen.mockInput.typeText("ok");

    expect(await submitted(screen, chosen, meetings)).toBe("the blue house ok");
  });

  it("refuses a phrase too short to hold off somebody guessing", async () => {
    const { screen, chosen } = await mountStart("alice");
    await reachPhrase(screen, "silver-and-ana");

    await submit(screen, "hunter2");

    await seeOnScreen(screen, "at least 10 characters");
    expect(chosen).toHaveLength(0);
  });

  it("hands over a chat with no invite once the room and phrase are usable", async () => {
    const { screen, chosen } = await mountStart("alice");
    await reachPhrase(screen, "silver-and-ana");

    await submit(screen, PHRASE);

    expect(chosen).toHaveLength(1);
    expect(chosen[0]?.nick).toBe("alice");
    expect(chosen[0]?.chat.invite).toBeNull();
  });

  it("goes back from the phrase to the room, and from the room to the choice", async () => {
    const { screen } = await mountStart("alice");
    await reachPhrase(screen, "silver-and-ana");

    await pressEscape(screen);
    await seeOnScreen(screen, "Room name");

    await pressEscape(screen);
    await seeOnScreen(screen, "What do you want to do?");
  });
});

describe("Esc", () => {
  it("goes back from the invite to the choice, and from the choice to the name", async () => {
    const { screen } = await mountStart();
    await submit(screen, "alice");
    await chooseJoin(screen);

    await pressEscape(screen);
    await seeOnScreen(screen, "Hi alice.");

    await pressEscape(screen);
    await seeOnScreen(screen, "Your name");
  });

  it("clears a complaint along with the step it was about", async () => {
    const { screen } = await mountStart("alice");
    await chooseJoin(screen);
    await submit(screen, "acorn-zzzz@relay.example");
    await seeOnScreen(screen, "not a word from the list");

    await pressEscape(screen);

    const frame = await seeOnScreen(screen, "Hi alice.");
    expect(frame).not.toContain("not a word from the list");
  });

  it("does not go back to a name that --nick already gave", async () => {
    const { screen, chosen } = await mountStart("alice");

    await pressEscape(screen);
    // Absence needs time to have been possible: React commits a step change
    // after the key that caused it.
    await wait(80);
    await screen.renderOnce();
    expect(screen.captureCharFrame()).not.toContain("Your name");

    // And the list is still the thing taking keys.
    await pressEnter(screen);
    expect(chosen[0]?.nick).toBe("alice");
  });
});
