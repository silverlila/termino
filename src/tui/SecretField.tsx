/**
 * A one-line field that shows a dot per character instead of the character.
 *
 * OpenTUI's input has no masked mode, and colouring the text to match the background
 * would leave the phrase in the screen buffer for any mouse selection to copy. The phrase
 * lives only in a ref, emptied on unmount; that bounds this copy only — the phrase handed
 * on lives in the session's closure for as long as the session does.
 *
 * Arrow keys and Tab arrive as control sequences starting with ESC, so a key whose
 * sequence carries a control character is ignored whole rather than stripped.
 */

import { useKeyboard, usePaste } from "@opentui/react";
import { useEffect, useRef, useState } from "react";
import { graphemes, MAX_PASSPHRASE_BYTES, withoutControls } from "../../shared/protocol/text.ts";

export interface SecretFieldProps {
  label: string;
  hint: string;
  onSubmit: (typed: string) => void;
}

export function SecretField({ label, hint, onSubmit }: SecretFieldProps) {
  const typed = useRef("");
  const [length, setLength] = useState(0);

  function replace(next: string): void {
    typed.current = next;
    setLength(graphemes(next).length);
  }

  function append(text: string): void {
    const next = typed.current + withoutControls(text);
    if (Buffer.byteLength(next, "utf8") > MAX_PASSPHRASE_BYTES) return;
    replace(next);
  }

  useEffect(
    () => () => {
      typed.current = "";
    },
    [],
  );

  useKeyboard((key) => {
    if (key.name === "return" || key.name === "linefeed") return onSubmit(typed.current);
    if (key.name === "backspace") return replace(graphemes(typed.current).slice(0, -1).join(""));
    if (key.ctrl || key.meta || withoutControls(key.sequence) !== key.sequence) return;

    append(key.sequence);
  });

  usePaste((event) => {
    append(new TextDecoder().decode(event.bytes).replace(/[\r\n]+/g, " ").trimEnd());
  });

  return (
    <box style={{ flexDirection: "column" }}>
      <text style={{ fg: "#c8d3f5" }}>{label}</text>
      <box style={{ border: true, borderColor: "#3a4055", paddingLeft: 1, paddingRight: 1, height: 3 }}>
        <text style={{ fg: length === 0 ? "#5a6075" : "#c8d3f5" }}>
          {length === 0 ? "hidden as you type" : "•".repeat(length)}
        </text>
      </box>
      <text style={{ fg: "#8b93a8" }}>{hint}</text>
    </box>
  );
}
