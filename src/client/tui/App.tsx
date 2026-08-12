import { useCallback, useEffect, useRef, useState } from "react";
import type { ChannelKeys } from "../../crypto/derive.ts";
import { fingerprint } from "../../crypto/fingerprint.ts";
import type { Identity } from "../../crypto/identity.ts";
import { startSession, type ConnectionState, type Session } from "../session.ts";
import { Composer } from "./Composer.tsx";
import { MessageList, type Entry, type MessageEntry, type NoticeEntry } from "./MessageList.tsx";
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
      <Composer onSend={chat.send} />
    </box>
  );
}

/** An entry before the list has given it its position. */
type EntryDraft = Omit<MessageEntry, "id"> | Omit<NoticeEntry, "id">;

interface Chat {
  entries: Entry[];
  connection: ConnectionState;
  presence: number;
  send: (line: string) => void;
}

function useChat(options: AppProps): Chat {
  const [entries, setEntries] = useState<Entry[]>([]);
  const [connection, setConnection] = useState<ConnectionState>("connecting");
  const [presence, setPresence] = useState(1);
  const session = useRef<Session | null>(null);
  const nextId = useRef(0);

  const append = useCallback((draft: EntryDraft) => {
    const id = String(nextId.current++);
    setEntries((previous) => [...previous, { ...draft, id }]);
  }, []);

  const notice = useCallback(
    (text: string) => append({ kind: "notice", text, ts: Date.now() }),
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
            verified: message.verified,
          }),
        onPresence: setPresence,
        onConnectionChange: setConnection,
        // Both of these are things the user will never get to read. Saying
        // nothing would leave them believing they had heard everything said.
        onDecryptError: (error) => notice(`could not open a message: ${error.message}`),
        onRelayError: (code) => notice(`the relay rejected a message: ${code}`),
      },
    }).then(
      (started) => {
        if (!mounted) return started.close();
        session.current = started;
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
    (line: string) => {
      const active = session.current;
      if (active === null) return notice("not connected yet — nothing was sent");

      active.send(line).then(
        (sent) =>
          append({
            kind: "message",
            nick: sent.nick,
            body: sent.body,
            ts: sent.ts,
            // Your own key needs no out-of-band check; you are holding it.
            verified: true,
          }),
        (error: Error) => notice(`could not send: ${error.message}`),
      );
    },
    [append, notice],
  );

  return { entries, connection, presence, send };
}
