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

/**
 * The whole screen. It owns the transcript and the connection state, and it
 * owns the session: the connection is opened from an effect here, so every
 * callback the session fires lands directly in React state.
 *
 * Nothing secret is a prop. React devtools serialises the props tree to a
 * local WebSocket when it is switched on, so a key passed down here would be
 * a key on the wire; the connection arrives as a closure with the secret
 * captured inside it, which is not serialisable.
 */

export interface AppProps {
  nick: string;
  /** Opens the session. Everything secret — the pre-shared key, the relay
   * address — is captured here rather than passed, and only the caller that
   * read them ever holds them. */
  connect: (handlers: SessionHandlers) => Promise<Session>;
  /** What `/exit` does. The screen decides *when* to leave; tearing down the
   * renderer and ending the process belongs to whoever built them, which is
   * `main.ts` — a component that calls `process.exit` cannot be tested. */
  onExit: () => void;
}

export function App({ nick, connect, onExit }: AppProps) {
  const chat = useChat({ nick, connect, onExit });

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
        presence={chat.presence}
      />
      <MessageList entries={chat.entries} />
      <Composer onSubmit={chat.submit} />
    </box>
  );
}

/**
 * A line of transcript as it was recorded, which is exactly what the list
 * renders. There is nothing left to fold in on the way — a message is shown as
 * it arrived, and the only thing that ever qualified it was a trust marker,
 * which no longer exists.
 */
export type TranscriptLine = Entry;

/**
 * How much transcript is kept. Nothing ever removed an entry before, so a long
 * session — or a peer sending at the relay's rate limit for an afternoon —
 * grew the array until the process died of it.
 */
export const MAX_TRANSCRIPT_LINES = 2000;

/** Appends, dropping from the front once the transcript is full. */
export function appendCapped(
  previous: TranscriptLine[],
  line: TranscriptLine,
  cap = MAX_TRANSCRIPT_LINES,
): TranscriptLine[] {
  const grown = [...previous, line];
  if (grown.length <= cap) return grown;

  return grown.slice(grown.length - cap);
}

/**
 * The one line a flood of unopenable frames gets.
 *
 * A handle travels in the clear, so anyone who learns one can subscribe and
 * send garbage to the other member of the channel. A notice per frame would
 * hand them the screen; a count on a single line says the same thing once.
 */
function unopenedNotice(count: number): string {
  const messages = count === 1 ? "message" : "messages";
  return `could not open ${count} ${messages} — someone may be sending noise`;
}

/** Messages that were numbered, stepped over, and never turned up. Numbering
 * is what makes a silent loss say something. */
export function gapNotice(nick: string, count: number): string {
  const messages = count === 1 ? "message" : "messages";
  return `⚠ ${count} ${messages} from ${nick} never arrived`;
}

export const THIRD_PARTY_NOTICE = "⚠ a third party tried to join this channel";

/** A line before the transcript has given it its position. */
type LineDraft = Omit<MessageEntry, "id"> | Omit<NoticeEntry, "id">;

interface Chat {
  entries: Entry[];
  connection: ConnectionState;
  presence: number;
  sasWords: string;
  /** One composer line: a message to send, or a command to run. */
  submit: (line: string) => void;
}

function useChat(options: AppProps): Chat {
  const [lines, setLines] = useState<TranscriptLine[]>([]);
  const [connection, setConnection] = useState<ConnectionState>("connecting");
  const [sasWords, setSasWords] = useState("");
  const session = useRef<Session | null>(null);
  const nextId = useRef(0);
  // The flood counter, and the line it is being written on. A ref because it
  // is read and written inside the session callbacks, which are built once.
  const unopened = useRef<{ count: number; lineId: string | null }>({ count: 0, lineId: null });

  /** Adds a line and hands back its id, so a line can be rewritten later. */
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

  // Rewrites the running count where it already sits rather than appending
  // another line: a trail of "…and one more" notices is the same flood with
  // extra steps.
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

  // Runs once. A session is bound to one secret for its whole life, so
  // re-running this on a prop change would tear down a live connection to
  // rebuild an identical one.
  useEffect(() => {
    let mounted = true;

    options
      .connect({
        onMessage: (message) => {
          // A message that opened means the flood, if there was one, is over:
          // the next one that fails starts its own count on its own line.
          unopened.current = { count: 0, lineId: null };

          append({
            kind: "message",
            nick: message.nick,
            body: message.body,
            ts: message.ts,
          });
        },
        onConnectionChange: setConnection,
        onPeerJoined: setSasWords,
        onGap: (nick, count) => notice(gapNotice(nick, count)),
        // The conversation has room for two. Somebody arriving with a third
        // key is either lost or trying something.
        onThirdParty: () => notice(THIRD_PARTY_NOTICE, "alarm"),
        // Both of these are things the user will never get to read. Saying
        // nothing would leave them believing they had heard everything said.
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
          notice(error.message, "alarm");
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

  // Closes the connection before handing back, so the keys are wiped and the
  // relay sees the departure as this screen goes away.
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

  return {
    entries: lines,
    connection,
    sasWords,
    // A session exists only once a peer's confirm has opened, so "connected"
    // and "somebody else is here" are the same fact until authenticated pings
    // can tell them apart.
    presence: connection === "open" ? 2 : 1,
    submit,
  };
}
