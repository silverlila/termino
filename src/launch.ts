import { UnknownWordError } from "../shared/crypto/fingerprint.ts";
import { generatePsk, InvalidPskError } from "../shared/crypto/psk.ts";
import { formatInvite, InvalidInviteError, parseInvite } from "../shared/protocol/invite.ts";
import { passphraseProblem, roomProblem, visible } from "../shared/protocol/text.ts";
import { inviteRelayUrl } from "./relay-url.ts";
import { startSession, type Session, type SessionHandlers } from "./session.ts";

export interface Chat {
  invite: string | null;
  connect(nick: string, handlers: SessionHandlers): Promise<Session>;
}

export type Joined = { ok: true; chat: Chat } | { ok: false; reason: string };

const NOT_AN_INVITE = [InvalidInviteError, InvalidPskError, UnknownWordError];

export function newChat(relayUrl: string): Chat {
  const psk = generatePsk();

  return {
    invite: formatInvite(psk, relayUrl),
    connect: (nick, handlers) => startSession({ psk, nick, relayUrl, handlers }),
  };
}

export function joinChat(inviteText: string): Joined {
  let invite;
  try {
    invite = parseInvite(inviteText);
  } catch (error) {
    if (NOT_AN_INVITE.some((kind) => error instanceof kind)) {
      return { ok: false, reason: visible((error as Error).message) };
    }
    throw error;
  }

  const { psk } = invite;
  const relayUrl = inviteRelayUrl(invite.relay);

  return {
    ok: true,
    chat: {
      invite: null,
      connect: (nick, handlers) => startSession({ psk, nick, relayUrl, handlers }),
    },
  };
}

export function passphraseChat(relayUrl: string, room: string, phrase: string): Joined {
  const problem = roomProblem(room) ?? passphraseProblem(phrase);
  if (problem !== null) return { ok: false, reason: problem };

  const passphrase = { room, phrase };

  return {
    ok: true,
    chat: {
      invite: null,
      connect: (nick, handlers) => startSession({ passphrase, nick, relayUrl, handlers }),
    },
  };
}
