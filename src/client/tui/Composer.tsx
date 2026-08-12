import { useRef } from "react";
import type { InputRenderable } from "@opentui/core";

/**
 * The single line the user types into.
 *
 * The input is deliberately **uncontrolled**: nothing above it ever passes a
 * `value` prop, so no re-render — including the one an incoming message
 * causes — can write over what is being typed. The draft lives in the input
 * itself until Enter, and the only thing that ever clears it is Enter.
 */

export interface ComposerProps {
  /** Called with the trimmed line. A blank line is swallowed here rather than
   * sent as an empty message. */
  onSend: (line: string) => void;
}

export function Composer({ onSend }: ComposerProps) {
  const input = useRef<InputRenderable>(null);

  // Reads the draft off the input rather than out of the event: OpenTUI's own
  // types disagree about what `onSubmit` is handed — `TextareaOptions` says a
  // `SubmitEvent`, `InputProps` says the string — and the input is the thing
  // actually holding the draft either way.
  function submit(): void {
    const composing = input.current;
    if (composing === null) return;

    const line = composing.value.trim();
    composing.value = "";
    if (line === "") return;

    onSend(line);
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
      <input ref={input} focused placeholder="write a message · Enter sends" onSubmit={submit} />
    </box>
  );
}
