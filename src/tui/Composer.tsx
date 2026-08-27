/**
 * The composer. It is uncontrolled — it never receives a value prop — so no re-render
 * caused by an incoming message can destroy half-typed input.
 *
 * @opentui/react 0.5.1's onSubmit types are unsatisfiable: InputProps declares
 * (value: string) => void, TextareaOptions declares (event: SubmitEvent) => void. The
 * handler takes no arguments and reads the draft off the InputRenderable ref.
 */

import { useRef } from "react";
import type { InputRenderable } from "@opentui/core";

export interface ComposerProps {
  onSubmit: (line: string) => void;
}

export function Composer({ onSubmit }: ComposerProps) {
  const input = useRef<InputRenderable>(null);

  function submit(): void {
    const composing = input.current;
    if (composing === null) return;

    const line = composing.value.trim();
    composing.value = "";
    if (line === "") return;

    onSubmit(line);
  }

  return (
    <box
      style={{
        flexShrink: 0,
        border: true,
        borderColor: "#3a4055",
        paddingLeft: 1,
        paddingRight: 1,
      }}
    >
      <input
        ref={input}
        focused
        placeholder="write a message · Enter sends · /help lists commands"
        onSubmit={submit}
      />
    </box>
  );
}
