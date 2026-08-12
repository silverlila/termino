import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import type { ChannelKeys } from "../../crypto/derive.ts";
import { fingerprint } from "../../crypto/fingerprint.ts";
import type { Identity } from "../../crypto/identity.ts";
import { startSession, type ConnectionState, type Session } from "../session.ts";
import type { TrustRecords } from "../trust.ts";
import { parseComposerInput } from "./commands.ts";
import { Composer } from "./Composer.tsx";
import { MessageList, type Entry, type NoticeTone } from "./MessageList.tsx";
import { StatusBar } from "./StatusBar.tsx";

/**
 * The whole screen. It owns the transcript and the connection state, and it
 * owns the session: `startSession` is called from an effect here, so every
 * callback the session fires lands directly in React state.
 *
 * The keys arrive already derived. Derivation costs ~850 ms of argon2id, and
 * paying it here would stall a renderer that is already on screen — so
 * `main.ts` finishes it before this component ever mounts.
 */

export interface AppProps {
  channel: string;
  nick: string;
  identity: Identity;
  keys: ChannelKeys;
  relayUrl: string;
  /** Where the trust store lives. A parameter so tests do not touch `~`. */
  terminoDir?: string;
}

export function App({ channel, nick, identity, keys, relayUrl, terminoDir }: AppProps) {
  const chat = useChat({ channel, nick, identity, keys, relayUrl, terminoDir });

  return (
    <box
      style={{ flexDirection: "column", width: "100%", height: "100%", backgroundColor: "#11141c" }}
    >
      <StatusBar
        channel={channel}
        nick={nick}
        fingerprint={fingerprint(identity.publicKey)}
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

type TranscriptLine = MessageLine | NoticeLine;

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

  const append = useCallback((draft: LineDraft) => {
    const id = String(nextId.current++);
    setLines((previous) => [...previous, { ...draft, id }]);
  }, []);

  const notice = useCallback(
    (text: string, tone: NoticeTone = "info") =>
      append({ kind: "notice", text, ts: Date.now(), tone }),
    [append],
  );

  // Runs once. A session is bound to one channel and one identity for its
  // whole life, so re-running this on a prop change would tear down a live
  // connection to rebuild an identical one.
  useEffect(() => {
    let mounted = true;

    startSession({
      keys: options.keys,
      nick: options.nick,
      identity: options.identity,
      relayUrl: options.relayUrl,
      terminoDir: options.terminoDir,
      handlers: {
        onMessage: (message) =>
          append({
            kind: "message",
            nick: message.nick,
            body: message.body,
            ts: message.ts,
            own: false,
          }),
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
        onDecryptError: (error) => notice(`could not open a message: ${error.message}`),
        onRelayError: (code) => notice(`the relay rejected a message: ${code}`),
      },
    }).then(
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
          append({ kind: "message", nick: sent.nick, body: sent.body, ts: sent.ts, own: true }),
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

  const submit = useCallback(
    (line: string) => {
      const input = parseComposerInput(line);

      if (input.kind === "unusable") return notice(input.reason);
      if (input.kind === "verify") return verify(input.nick, input.fingerprint);

      send(input.body);
    },
    [notice, send, verify],
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

function toEntry(line: TranscriptLine, trust: TrustRecords): Entry {
  if (line.kind === "notice") return line;

  return {
    kind: "message",
    id: line.id,
    nick: line.nick,
    body: line.body,
    ts: line.ts,
    verified: line.own || (trust[line.nick]?.verified ?? false),
  };
}
