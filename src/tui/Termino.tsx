import { useState } from "react";
import type { Chat } from "../launch.ts";
import { App } from "./App.tsx";
import { Start, type StartProps } from "./Start.tsx";

export interface TerminoProps extends Omit<StartProps, "onChosen"> {
  onExit: () => void;
}

interface Chosen {
  nick: string;
  chat: Chat;
}

export function Termino({ onExit, ...startProps }: TerminoProps) {
  const [chosen, setChosen] = useState<Chosen | null>(null);

  if (chosen === null) {
    return <Start {...startProps} onChosen={(nick, chat) => setChosen({ nick, chat })} />;
  }

  const { nick, chat } = chosen;

  return (
    <App
      nick={nick}
      invite={chat.invite}
      connect={(handlers) => chat.connect(nick, handlers)}
      onExit={onExit}
    />
  );
}
