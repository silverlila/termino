/**
 * The start screen: a name, then a choice between starting a chat, joining one with an
 * invite, and meeting in a room on a passphrase both people already know.
 *
 * One input or list is on screen at a time, and each step remounts its input by key, so
 * focus never has to be handed between widgets and a draft never leaks into the next
 * step. The inputs are uncontrolled for the same reason as the composer's.
 */

import type { InputRenderable } from "@opentui/core";
import { useKeyboard } from "@opentui/react";
import { useRef, useState } from "react";
import { nickProblem, roomProblem } from "../../shared/protocol/text.ts";
import type { Chat, Joined } from "../launch.ts";
import { SecretField } from "./SecretField.tsx";
import { UNAUDITED_BANNER } from "./StatusBar.tsx";

export interface StartProps {
  relay: string;
  nick?: string;
  start: () => Chat;
  join: (invite: string) => Joined;
  meet: (room: string, phrase: string) => Joined;
  onChosen: (nick: string, chat: Chat) => void;
}

type Step =
  | { name: "nick" }
  | { name: "choose"; nick: string }
  | { name: "invite"; nick: string }
  | { name: "room"; nick: string }
  | { name: "phrase"; nick: string; room: string };

type Choice = "new" | "join" | "meet";

const CHOICES: { name: string; description: string; value: Choice }[] = [
  { name: "Start a new chat", description: "the strongest: an invite to send to the other person", value: "new" },
  { name: "Join a chat", description: "paste the invite somebody sent you", value: "join" },
  { name: "Meet with a passphrase", description: "a room and a phrase you both already know", value: "meet" },
];

function previous(step: Step, nickGiven: boolean): Step | null {
  switch (step.name) {
    case "nick":
      return null;
    case "choose":
      return nickGiven ? null : { name: "nick" };
    case "invite":
    case "room":
      return { name: "choose", nick: step.nick };
    case "phrase":
      return { name: "room", nick: step.nick };
  }
}

export function Start({ relay, nick, start, join, meet, onChosen }: StartProps) {
  const [step, setStep] = useState<Step>(
    nick === undefined ? { name: "nick" } : { name: "choose", nick },
  );
  const [problem, setProblem] = useState<string | null>(null);

  function go(next: Step): void {
    setProblem(null);
    setStep(next);
  }

  useKeyboard((key) => {
    if (key.name !== "escape") return;

    const back = previous(step, nick !== undefined);
    if (back !== null) go(back);
  });

  function chooseNick(typed: string): void {
    const found = typed === "" ? "a nickname is required" : nickProblem(typed);
    if (found !== null) return setProblem(`that name is not usable: ${found}`);

    go({ name: "choose", nick: typed });
  }

  function choose(choice: Choice, chosenNick: string): void {
    if (choice === "new") return onChosen(chosenNick, start());

    go({ name: choice === "join" ? "invite" : "room", nick: chosenNick });
  }

  function chooseRoom(typed: string, chosenNick: string): void {
    const found = roomProblem(typed);
    if (found !== null) return setProblem(`that room name is not usable: ${found}`);

    go({ name: "phrase", nick: chosenNick, room: typed });
  }

  function meetWith(phrase: string, chosenNick: string, room: string): void {
    const met = meet(room, phrase);
    if (!met.ok) return setProblem(met.reason);

    onChosen(chosenNick, met.chat);
  }

  function joinWith(typed: string, chosenNick: string): void {
    const joined = join(typed);
    if (!joined.ok) return setProblem(joined.reason);

    onChosen(chosenNick, joined.chat);
  }

  return (
    <box style={{ width: "100%", height: "100%", flexDirection: "column", backgroundColor: "#11141c" }}>
      <box style={{ flexShrink: 0, paddingLeft: 1, paddingRight: 1, backgroundColor: "#1f2430" }}>
        <text style={{ fg: "#e0a35c" }}>{UNAUDITED_BANNER}</text>
      </box>
      <box style={{ flexDirection: "column", paddingLeft: 2, paddingRight: 2, paddingTop: 1 }}>
        <text style={{ fg: "#c8d3f5" }}>termino — end-to-end encrypted chat</text>
        <text style={{ fg: "#8b93a8" }}>{`new chats and passphrase rooms meet on ${relay}`}</text>
        <box style={{ height: 1 }} />
        {step.name === "nick" ? (
          <Field
            key="nick"
            label="Your name"
            placeholder="what the other person sees you as"
            hint="Enter to continue · Ctrl+C quits"
            onSubmit={chooseNick}
          />
        ) : null}
        {step.name === "choose" ? (
          <ChoiceList
            nick={step.nick}
            onChoose={(choice) => choose(choice, step.nick)}
            canGoBack={nick === undefined}
          />
        ) : null}
        {step.name === "invite" ? (
          <Field
            key="invite"
            label="Paste the invite"
            placeholder="sixteen-words-joined-by-hyphens@relay.host"
            hint="Enter to join · Esc goes back"
            onSubmit={(typed) => joinWith(typed, step.nick)}
          />
        ) : null}
        {step.name === "room" ? (
          <Field
            key="room"
            label="Room name"
            placeholder="a name you both agreed — it is not secret"
            hint="Enter to continue · Esc goes back"
            onSubmit={(typed) => chooseRoom(typed, step.nick)}
          />
        ) : null}
        {step.name === "phrase" ? (
          <SecretField
            label={`Passphrase for room ${step.room}`}
            hint="Enter to meet · Esc goes back · a wrong phrase fails the session, out loud"
            onSubmit={(typed) => meetWith(typed, step.nick, step.room)}
          />
        ) : null}
        {problem === null ? null : (
          <text style={{ fg: "#ff5f5f" }} wrapMode="word">
            {problem}
          </text>
        )}
      </box>
    </box>
  );
}

interface FieldProps {
  label: string;
  placeholder: string;
  hint: string;
  onSubmit: (typed: string) => void;
}

function Field({ label, placeholder, hint, onSubmit }: FieldProps) {
  const input = useRef<InputRenderable>(null);

  function submit(): void {
    const field = input.current;
    if (field === null) return;

    onSubmit(field.value.trim());
  }

  return (
    <box style={{ flexDirection: "column" }}>
      <text style={{ fg: "#c8d3f5" }}>{label}</text>
      <box style={{ border: true, borderColor: "#3a4055", paddingLeft: 1, paddingRight: 1 }}>
        <input ref={input} focused placeholder={placeholder} onSubmit={submit} />
      </box>
      <text style={{ fg: "#8b93a8" }}>{hint}</text>
    </box>
  );
}

interface ChoiceListProps {
  nick: string;
  canGoBack: boolean;
  onChoose: (choice: Choice) => void;
}

function ChoiceList({ nick, canGoBack, onChoose }: ChoiceListProps) {
  const hint = canGoBack ? "↑↓ to move · Enter to choose · Esc goes back" : "↑↓ to move · Enter to choose";

  return (
    <box style={{ flexDirection: "column" }}>
      <text style={{ fg: "#c8d3f5" }}>{`Hi ${nick}. What do you want to do?`}</text>
      <select
        focused
        options={CHOICES}
        style={{ height: 6, backgroundColor: "#11141c", focusedBackgroundColor: "#11141c" }}
        onSelect={(index) => {
          const chosen = CHOICES[index];
          if (chosen !== undefined) onChoose(chosen.value);
        }}
      />
      <text style={{ fg: "#8b93a8" }}>{hint}</text>
    </box>
  );
}
