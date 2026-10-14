/**
 * Turning a choice — start a chat, or join one — into a session bound to its secret.
 *
 * The secret is captured inside `connect` and never handed back: the TUI receives the
 * invite as text to show and copy, and a closure it cannot look into.
 */

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

// Everything parseInvite throws for text that is not an invite, as opposed to a bug.
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
      // The reasons quote the pasted text, and whoever sent it chose every byte.
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

/** A passphrase room meets on the relay this side chose: there is no invite to carry one,
 * so both people have to be using the same relay — the default, unless they agreed
 * another. */
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
