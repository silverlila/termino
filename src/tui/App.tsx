import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import type {
  ConnectionState,
  DiscardedMessage,
  Session,
  SessionHandlers,
} from "../session.ts";
import type { TrustRecords } from "../trust.ts";
import { COMMANDS, parseComposerInput } from "./commands.ts";
import { Composer } from "./Composer.tsx";
import { MessageList, type Entry, type NoticeTone } from "./MessageList.tsx";
import { StatusBar } from "./StatusBar.tsx";

/**
 * The whole screen. It owns the transcript and the connection state, and it
 * owns the session: the connection is opened from an effect here, so every
 * callback the session fires lands directly in React state.
 *
 * Nothing secret is a prop. React devtools serialises the props tree to a
 * local WebSocket when it is switched on, so a key passed down here would be
 * a key on the wire; the connection arrives as a closure with the keys
 * captured inside it, which is not serialisable.
 */

export interface AppProps {
  channel: string;
  nick: string;
  /** Own fingerprint, eight words, already rendered — the key that produced
   * it stays in the closure below. */
  fingerprint: string;
  /** Opens the session. Everything secret — the device key, the channel key,
   * the relay address, where the trust store lives — is captured here rather
   * than passed, and only the caller that derived them ever holds them. */
  connect: (handlers: SessionHandlers) => Promise<Session>;
  /** What `/exit` does. The screen decides *when* to leave; tearing down the
   * renderer and ending the process belongs to whoever built them, which is
   * `main.ts` — a component that calls `process.exit` cannot be tested. */
  onExit: () => void;
}

export function App({ channel, nick, fingerprint, connect, onExit }: AppProps) {
  const chat = useChat({ channel, nick, fingerprint, connect, onExit });

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
        channel={channel}
        fingerprint={fingerprint}
        connection={chat.connection}
        presence={chat.presence}
      />
      <MessageList entries={chat.entries} />
      <Composer onSubmit={chat.submit} />
    </box>
  );
}

/**
 * A line of transcript as it was recorded.
 *
 * It records *who* said it and never whether they were verified: verification
 * is a fact about that nickname's key right now, and `/verify` has to change
 * how every line already on screen is marked, not only the next one.
 */
interface MessageLine {
  kind: "message";
  id: string;
  nick: string;
  /** The key that signed this line, which is not necessarily the one that
   * nickname is signing with now — somebody else may have used the name
   * first. Verification is granted to a key, so the marker is decided
   * against this rather than against the nickname alone. */
  from: string;
  body: string;
  ts: number;
  /** Sent from this device. Your own key needs no out-of-band check. */
  own: boolean;
}

interface NoticeLine {
  kind: "notice";
  id: string;
  text: string;
  ts: number;
  tone: NoticeTone;
}

export type TranscriptLine = MessageLine | NoticeLine;

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
 * send garbage to every member of the channel. A notice per frame would hand
 * them the screen; a count on a single line says the same thing once.
 */
function unopenedNotice(count: number): string {
  const messages = count === 1 ? "message" : "messages";
  return `could not open ${count} ${messages} — someone may be sending noise`;
}

/** A line before the transcript has given it its position. */
type LineDraft = Omit<MessageLine, "id"> | Omit<NoticeLine, "id">;

interface Chat {
  entries: Entry[];
  connection: ConnectionState;
  presence: number;
  /** One composer line: a message to send, or a command to run. */
  submit: (line: string) => void;
}

function useChat(options: AppProps): Chat {
  const [lines, setLines] = useState<TranscriptLine[]>([]);
  const [trust, setTrust] = useState<TrustRecords>({});
  const [connection, setConnection] = useState<ConnectionState>("connecting");
  const [presence, setPresence] = useState(1);
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

  // Runs once. A session is bound to one channel and one identity for its
  // whole life, so re-running this on a prop change would tear down a live
  // connection to rebuild an identical one.
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
            from: message.from,
            body: message.body,
            ts: message.ts,
            own: false,
          });
        },
        onPresence: setPresence,
        onConnectionChange: setConnection,
        onTrustEvent: (event) => {
          setTrust(event.records);

          // The one thing in this interface that is worth interrupting
          // somebody for: the person behind this nickname is signing with a
          // key nobody has ever seen, which is what an impersonation looks
          // like from here and also what a reinstall looks like.
          if (event.state === "CHANGED")
            notice(`!! KEY CHANGED for ${event.nick} — verify out of band`, "alarm");
        },
        // Both of these are things the user will never get to read. Saying
        // nothing would leave them believing they had heard everything said.
        onDecryptError: countUnopened,
        onDiscardedMessage: (discarded) => notice(discardNotice(discarded)),
        onRelayError: (code) => notice(`the relay rejected a message: ${code}`),
      })
      .then(
        (started) => {
          if (!mounted) return started.close();
          session.current = started;

          // Whatever this device already knew before this session started: a
          // peer verified last week is marked verified from the first frame,
          // and the session says nothing about a key it recognises.
          setTrust(started.trustRecords());
        },
        (error: Error) => {
          if (!mounted) return;
          setConnection("closed");
          notice(`could not reach the relay: ${error.message}`);
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
            from: sent.from,
            body: sent.body,
            ts: sent.ts,
            own: true,
          }),
        (error: Error) => notice(`could not send: ${error.message}`),
      );
    },
    [append, notice],
  );

  const verify = useCallback(
    (nick: string, claimed: string) => {
      const active = session.current;
      if (active === null) return notice("not connected yet — nothing was verified");

      const { result, records } = active.verify(nick, claimed);
      setTrust(records);

      if (result === "unknown-nick")
        return notice(`nothing to verify: nothing has arrived from ${nick} yet`);

      // Loudly, and without printing the real fingerprint next to it: the
      // point of the comparison is that it happened somewhere else.
      if (result === "mismatch")
        return notice(`that fingerprint does not match ${nick}'s key — nothing changed`, "alarm");

      notice(`${nick} is verified`);
    },
    [notice],
  );

  // Closes the connection before handing back, so the relay sees the departure
  // and the other members' presence count drops as this screen goes away.
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
      if (input.kind === "verify") return verify(input.nick, input.fingerprint);

      if (input.kind === "help") {
        for (const command of COMMANDS) notice(`${command.usage} — ${command.summary}`);
        return;
      }

      send(input.body);
    },
    [leave, notice, send, verify],
  );

  // Rebuilt whenever either half changes: the transcript records who spoke and
  // the trust store records who has been checked, and the marker is the two
  // read together.
  const entries = useMemo<Entry[]>(
    () => lines.map((line) => toEntry(line, trust)),
    [lines, trust],
  );

  return { entries, connection, presence, submit };
}

/**
 * What the screen says about a message that was genuine and still not shown.
 * Both of these are somebody's second copy of one message: the first is a
 * deliberate act, the second is usually a clock, and the user can only tell
 * which if the reason is said out loud.
 */
function discardNotice({ nick, reason }: DiscardedMessage): string {
  if (reason === "replayed")
    return `discarded a second copy of a message from ${nick} — somebody sent it again`;

  return `discarded a message from ${nick} dated outside the freshness window — check both clocks`;
}

function toEntry(line: TranscriptLine, trust: TrustRecords): Entry {
  if (line.kind === "notice") return line;

  return {
    kind: "message",
    id: line.id,
    nick: line.nick,
    body: line.body,
    ts: line.ts,
    verified: isVerified(line, trust),
  };
}

/**
 * Whether the key that signed this line is one a human has checked.
 *
 * The stored key is compared, not only the flag: a nickname somebody else
 * used first leaves a line on screen signed by a key that was never verified,
 * and marking it `✓` the moment the real owner is verified would vouch for
 * exactly the message the marker exists to cast doubt on.
 */
function isVerified(line: MessageLine, trust: TrustRecords): boolean {
  if (line.own) return true;

  const record = trust[line.nick];
  if (record === undefined) return false;

  return record.verified && record.pubkey === line.from;
}
