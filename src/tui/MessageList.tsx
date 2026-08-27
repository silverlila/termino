/**
 * The transcript.
 *
 * Timestamps are hand-formatted: `toLocaleTimeString`'s width varies by locale and would
 * break the fixed time column.
 */

export interface MessageEntry {
  kind: "message";
  id: string;
  nick: string;
  body: string;
  ts: number;
}

export type NoticeTone = "info" | "alarm";

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

function localTime(ts: number): string {
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
