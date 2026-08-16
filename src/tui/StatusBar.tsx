import type { ConnectionState } from "../session.ts";

/**
 * The lines that are always on screen. Everything here is context the user
 * needs while typing and would otherwise have to remember: who they are,
 * whether the other person is really there, and — the one nobody can look up
 * elsewhere — the session words.
 *
 * The words are the only defence against a relay that runs its own exchange
 * with each side, and they defend nothing until two people have said them to
 * each other. So they are not left to speak for themselves: the line under them
 * says what to do with them and what a mismatch means.
 */

export interface StatusBarProps {
  nick: string;
  /** The eight words for this session, empty until a peer has answered.
   * Different every session, so there is nothing to remember and nothing to
   * store. */
  sasWords: string;
  connection: ConnectionState;
  /** Whether the other person has been heard from inside the presence expiry.
   * Not a count: a channel holds exactly two, so "how many" is a question with
   * only one interesting answer. */
  peerPresent: boolean;
}

/** Two facts on one line, because they are two facts: the socket can be up
 * while the person on the other end of it has stopped answering, and that is
 * exactly the case a relay withholding traffic produces. */
export function stateLabel(connection: ConnectionState, peerPresent: boolean): string {
  if (connection === "closed") return "disconnected";

  // A session does not exist until a peer's confirm has opened, so there is
  // nobody to be connected to yet.
  if (connection === "connecting") return "waiting for the other side…";

  return peerPresent ? "connected · both here" : "connected · the other side has gone quiet";
}

/**
 * The first thing on the first screen, and it stays there for the whole
 * session.
 *
 * Nobody outside this project has reviewed the way these primitives were
 * assembled into a protocol, and assembly is where the mistakes live. A note in
 * a README is read once by the person who installed it, which is not the same
 * person as the one deciding what to type — so the claim is repeated where the
 * typing happens, and it names the document that says what is and is not
 * defended.
 */
export const UNAUDITED_BANNER = "⚠ unaudited — no external security review; see THREAT-MODEL.md";

export const SAS_LABEL = "session words:";

/** Under the words rather than over them: it is read after the eye has already
 * landed on the thing it is about. */
export const SAS_INSTRUCTION =
  "read them aloud to each other — if they differ, somebody is in the middle";

export function StatusBar({ nick, sasWords, connection, peerPresent }: StatusBarProps) {
  return (
    <box style={{ flexDirection: "column", flexShrink: 0, backgroundColor: "#1f2430" }}>
      <box style={{ flexDirection: "row", paddingLeft: 1, paddingRight: 1 }}>
        <text style={{ fg: "#e0a35c" }}>{UNAUDITED_BANNER}</text>
      </box>
      <box style={{ flexDirection: "row", justifyContent: "space-between", paddingLeft: 1, paddingRight: 1 }}>
        <text style={{ fg: "#c8d3f5" }}>{nick}</text>
        <text style={{ fg: "#8b93a8" }}>{stateLabel(connection, peerPresent)}</text>
      </box>
      {sasWords === "" ? null : (
        <box style={{ flexDirection: "column", paddingLeft: 1, paddingRight: 1 }}>
          <text style={{ fg: "#c8d3f5" }} wrapMode="word">{`${SAS_LABEL} ${sasWords}`}</text>
          <text style={{ fg: "#e0a35c" }} wrapMode="word">
            {SAS_INSTRUCTION}
          </text>
        </box>
      )}
    </box>
  );
}
