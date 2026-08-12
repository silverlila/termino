import type { ConnectionState } from "../session.ts";

/**
 * The two lines that are always on screen. Everything here is context the
 * user needs while typing and would otherwise have to remember: which channel
 * this is, who the relay thinks they are, whether anything is getting through,
 * and — the one nobody can look up elsewhere — their own fingerprint, so they
 * can read it aloud when somebody else runs `/verify`.
 */

export interface StatusBarProps {
  channel: string;
  nick: string;
  /** Own fingerprint, eight words. */
  fingerprint: string;
  connection: ConnectionState;
  /** Connections subscribed to this handle, including this one. */
  presence: number;
}

const CONNECTION_LABEL: Record<ConnectionState, string> = {
  connecting: "connecting",
  open: "connected",
  closed: "disconnected",
};

export function StatusBar({ channel, nick, fingerprint, connection, presence }: StatusBarProps) {
  const here = presence === 1 ? "just you" : `${presence} here`;

  return (
    <box style={{ flexDirection: "column", flexShrink: 0, backgroundColor: "#1f2430" }}>
      <box style={{ flexDirection: "row", justifyContent: "space-between", paddingLeft: 1, paddingRight: 1 }}>
        <text style={{ fg: "#c8d3f5" }}>{`#${channel} · ${nick}`}</text>
        <text style={{ fg: "#8b93a8" }}>{`${CONNECTION_LABEL[connection]} · ${here}`}</text>
      </box>
      <box style={{ paddingLeft: 1, paddingRight: 1 }}>
        <text style={{ fg: "#8b93a8" }} wrapMode="word">{`your fingerprint: ${fingerprint}`}</text>
      </box>
    </box>
  );
}
