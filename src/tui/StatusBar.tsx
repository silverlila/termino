import type { ConnectionState } from "../session.ts";

/**
 * The two lines that are always on screen. Everything here is context the
 * user needs while typing and would otherwise have to remember: who they are,
 * whether anything is getting through, and — the one nobody can look up
 * elsewhere — the session words, which mean nothing until both people have read
 * them to each other and found they match.
 */

export interface StatusBarProps {
  nick: string;
  /** The eight words for this session. Different every session, so there is
   * nothing to remember and nothing to store. */
  sasWords: string;
  connection: ConnectionState;
  /** People on this handle, including this one. */
  presence: number;
}

const CONNECTION_LABEL: Record<ConnectionState, string> = {
  connecting: "connecting",
  open: "connected",
  closed: "disconnected",
};

export function StatusBar({ nick, sasWords, connection, presence }: StatusBarProps) {
  const here = presence === 1 ? "just you" : `${presence} here`;

  return (
    <box style={{ flexDirection: "column", flexShrink: 0, backgroundColor: "#1f2430" }}>
      <box style={{ flexDirection: "row", justifyContent: "space-between", paddingLeft: 1, paddingRight: 1 }}>
        <text style={{ fg: "#c8d3f5" }}>{nick}</text>
        <text style={{ fg: "#8b93a8" }}>{`${CONNECTION_LABEL[connection]} · ${here}`}</text>
      </box>
      <box style={{ paddingLeft: 1, paddingRight: 1 }}>
        <text style={{ fg: "#8b93a8" }} wrapMode="word">{`session words: ${sasWords}`}</text>
      </box>
    </box>
  );
}
