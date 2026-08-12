/**
 * The scrollable transcript. It is handed a finished list and renders it —
 * no protocol, no clock of its own, no knowledge of where an entry came from.
 *
 * The old client called `console.clear()` and reprinted everything on every
 * arrival, which is what erased half-typed input. Here an arrival appends one
 * child to a viewport that owns its own region of the screen, and the composer
 * below is not touched at all.
 */

/** A message that arrived decrypted and signature-verified, or one we sent. */
export interface MessageEntry {
  kind: "message";
  id: string;
  nick: string;
  body: string;
  /** Sender's timestamp, milliseconds since the epoch. Rendered as local time. */
  ts: number;
  /** Whether a human has confirmed this nickname's key out of band. */
  verified: boolean;
}

/** Something that happened to the connection rather than something a person
 * said. Kept in the same list so a dropped message appears where the user is
 * already looking instead of scrolling past in a log. */
export interface NoticeEntry {
  kind: "notice";
  id: string;
  text: string;
  ts: number;
}

export type Entry = MessageEntry | NoticeEntry;

/** `?` is a warning, not decoration: it means nobody has checked that this
 * nickname's key belongs to the person it claims. */
export const UNVERIFIED_MARKER = "?";
export const VERIFIED_MARKER = "✓";

const TIME_COLUMN_WIDTH = 6;

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
  const marker = entry.verified ? VERIFIED_MARKER : UNVERIFIED_MARKER;

  return (
    <text style={{ flexGrow: 1 }} wrapMode="word">
      {`${marker}${entry.nick}  ${entry.body}`}
    </text>
  );
}

function NoticeText({ entry }: { entry: NoticeEntry }) {
  return (
    <text style={{ flexGrow: 1, fg: "#e0a35c" }} wrapMode="word">
      {entry.text}
    </text>
  );
}
