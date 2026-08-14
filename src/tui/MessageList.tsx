/**
 * The scrollable transcript. It is handed a finished list and renders it —
 * no protocol, no clock of its own, no knowledge of where an entry came from.
 *
 * The old client called `console.clear()` and reprinted everything on every
 * arrival, which is what erased half-typed input. Here an arrival appends one
 * child to a viewport that owns its own region of the screen, and the composer
 * below is not touched at all.
 */

/** A message that arrived and opened under the receiving chain, or one we
 * sent. Nothing else reaches this list. */
export interface MessageEntry {
  kind: "message";
  id: string;
  nick: string;
  body: string;
  /** When this client received it, milliseconds since the epoch. Rendered as
   * local time. */
  ts: number;
}

/** `alarm` is for the one thing a user must not scroll past — somebody else
 * trying to join the conversation. Everything else the client says is `info`. */
export type NoticeTone = "info" | "alarm";

/** Something that happened to the connection rather than something a person
 * said. Kept in the same list so a dropped message appears where the user is
 * already looking instead of scrolling past in a log. */
export interface NoticeEntry {
  kind: "notice";
  id: string;
  text: string;
  ts: number;
  tone: NoticeTone;
}

export type Entry = MessageEntry | NoticeEntry;

const TIME_COLUMN_WIDTH = 6;

const NOTICE_COLOR: Record<NoticeTone, string> = {
  info: "#e0a35c",
  alarm: "#ff5f5f",
};

/** Local wall-clock time, fixed width. Hand-rolled rather than
 * `toLocaleTimeString` so the column is exactly five cells in every locale. */
export function localTime(ts: number): string {
  const at = new Date(ts);
  const pad = (value: number) => String(value).padStart(2, "0");
  return `${pad(at.getHours())}:${pad(at.getMinutes())}`;
}

export interface MessageListProps {
  entries: Entry[];
}

export function MessageList({ entries }: MessageListProps) {
  return (
    <scrollbox
      style={{ flexGrow: 1, paddingLeft: 1, paddingRight: 1 }}
      stickyScroll
      stickyStart="bottom"
    >
      {entries.map((entry) => (
        <EntryRow key={entry.id} entry={entry} />
      ))}
    </scrollbox>
  );
}

function EntryRow({ entry }: { entry: Entry }) {
  return (
    <box style={{ flexDirection: "row", flexShrink: 0 }}>
      <text style={{ width: TIME_COLUMN_WIDTH, flexShrink: 0, fg: "#5c6478" }}>
        {localTime(entry.ts)}
      </text>
      {entry.kind === "notice" ? <NoticeText entry={entry} /> : <MessageText entry={entry} />}
    </box>
  );
}

function MessageText({ entry }: { entry: MessageEntry }) {
  return (
    <text style={{ flexGrow: 1 }} wrapMode="word">
      {`${entry.nick}  ${entry.body}`}
    </text>
  );
}

function NoticeText({ entry }: { entry: NoticeEntry }) {
  return (
    <text style={{ flexGrow: 1, fg: NOTICE_COLOR[entry.tone] }} wrapMode="word">
      {entry.text}
    </text>
  );
}
