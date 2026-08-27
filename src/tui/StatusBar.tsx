import type { ConnectionState } from "../session.ts";

export interface StatusBarProps {
  nick: string;
  sasWords: string;
  connection: ConnectionState;
  peerPresent: boolean;
}

function stateLabel(connection: ConnectionState, peerPresent: boolean): string {
  if (connection === "closed") return "disconnected";

  if (connection === "connecting") return "waiting for the other side…";

  return peerPresent ? "connected · both here" : "connected · the other side has gone quiet";
}

const UNAUDITED_BANNER = "⚠ unaudited — no external security review; see THREAT-MODEL.md";

const SAS_LABEL = "session words:";

const SAS_INSTRUCTION =
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
