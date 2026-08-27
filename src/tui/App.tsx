import { useCallback, useEffect, useRef, useState } from "react";
import type { ConnectionState, Session, SessionHandlers } from "../session.ts";
import { COMMANDS, parseComposerInput } from "./commands.ts";
import { Composer } from "./Composer.tsx";
import {
  MessageList,
  type Entry,
  type MessageEntry,
  type NoticeEntry,
  type NoticeTone,
} from "./MessageList.tsx";
import { StatusBar } from "./StatusBar.tsx";

export interface AppProps {
  nick: string;
  connect: (handlers: SessionHandlers) => Promise<Session>;
  onExit: () => void;
}

export function App({ nick, connect, onExit }: AppProps) {
  const chat = useChat({ connect, onExit });

  return (
    <box
      style={{
         width: "100%",
         height: "100%",
         flexDirection: "column",
         backgroundColor: "#11141c"
     }}
    >
      <StatusBar
        nick={nick}
        sasWords={chat.sasWords}
        connection={chat.connection}
        peerPresent={chat.peerPresent}
      />
      <MessageList entries={chat.entries} />
      <Composer onSubmit={chat.submit} />
    </box>
  );
}

export type TranscriptLine = Entry;

const MAX_TRANSCRIPT_LINES = 2000;

export function appendCapped(
  previous: TranscriptLine[],
  line: TranscriptLine,
): TranscriptLine[] {
  const grown = [...previous, line];
  if (grown.length <= MAX_TRANSCRIPT_LINES) return grown;

  return grown.slice(grown.length - MAX_TRANSCRIPT_LINES);
}

function unopenedNotice(count: number): string {
  const messages = count === 1 ? "message" : "messages";
  return `could not open ${count} ${messages} — someone may be sending noise`;
}

export function gapNotice(nick: string, count: number): string {
  const messages = count === 1 ? "message" : "messages";
  return `⚠ ${count} ${messages} from ${nick} never arrived`;
}

const THIRD_PARTY_NOTICE = "⚠ a third party tried to join this channel";

function failedNotice(reason: string): string {
  return `⚠ ${reason}`;
}

type LineDraft = Omit<MessageEntry, "id"> | Omit<NoticeEntry, "id">;

interface Chat {
  entries: Entry[];
  connection: ConnectionState;
  peerPresent: boolean;
  sasWords: string;
  submit: (line: string) => void;
}

function useChat(options: Pick<AppProps, "connect" | "onExit">): Chat {
  const [lines, setLines] = useState<TranscriptLine[]>([]);
  const [connection, setConnection] = useState<ConnectionState>("connecting");
  const [sasWords, setSasWords] = useState("");
  const [peerPresent, setPeerPresent] = useState(false);
  const session = useRef<Session | null>(null);
  const nextId = useRef(0);
  const unopened = useRef<{ count: number; lineId: string | null }>({ count: 0, lineId: null });

  const append = useCallback((draft: LineDraft): string => {
    const id = String(nextId.current++);
    setLines((previous) => appendCapped(previous, { ...draft, id }));
    return id;
  }, []);

  const notice = useCallback(
    (text: string, tone: NoticeTone = "info") =>
      append({ kind: "notice", text, ts: Date.now(), tone }),
    [append],
  );

  const countUnopened = useCallback(() => {
    const state = unopened.current;
    state.count += 1;
    const text = unopenedNotice(state.count);

    if (state.lineId === null) {
      state.lineId = append({ kind: "notice", text, ts: Date.now(), tone: "info" });
      return;
    }

    const lineId = state.lineId;
    setLines((previous) =>
      previous.map((line) =>
        line.id === lineId && line.kind === "notice" ? { ...line, text } : line,
      ),
    );
  }, [append]);

  useEffect(() => {
    let mounted = true;

    options
      .connect({
        onMessage: (message) => {
          unopened.current = { count: 0, lineId: null };

          append({
            kind: "message",
            nick: message.nick,
            body: message.body,
            ts: message.ts,
          });
        },
        onConnectionChange: setConnection,
        onPeerJoined: (words) => {
          setSasWords(words);
          setPeerPresent(true);
        },
        onPeerGone: () => setPeerPresent(false),
        onGap: (nick, count) => notice(gapNotice(nick, count)),
        onThirdParty: () => notice(THIRD_PARTY_NOTICE, "alarm"),
        onDecryptError: countUnopened,
        onRelayError: (code) => notice(`the relay rejected a message: ${code}`),
      })
      .then(
        (started) => {
          if (!mounted) return started.close();
          session.current = started;
        },
        (error: Error) => {
          if (!mounted) return;
          setConnection("closed");
          notice(failedNotice(error.message), "alarm");
        },
      );

    return () => {
      mounted = false;
      session.current?.close();
      session.current = null;
    };
  }, []);

  const send = useCallback(
    (body: string) => {
      const active = session.current;
      if (active === null) return notice("not connected yet — nothing was sent");

      active.send(body).then(
        (sent) =>
          append({
            kind: "message",
            nick: sent.nick,
            body: sent.body,
            ts: sent.ts,
          }),
        (error: Error) => notice(`could not send: ${error.message}`),
      );
    },
    [append, notice],
  );

  const leave = useCallback(() => {
    session.current?.close();
    session.current = null;
    options.onExit();
  }, [options.onExit]);

  const submit = useCallback(
    (line: string) => {
      const input = parseComposerInput(line);

      if (input.kind === "unusable") return notice(input.reason);
      if (input.kind === "exit") return leave();

      if (input.kind === "help") {
        for (const command of COMMANDS) notice(`${command.usage} — ${command.summary}`);
        return;
      }

      send(input.body);
    },
    [leave, notice, send],
  );

  return { entries: lines, connection, sasWords, peerPresent, submit };
}
