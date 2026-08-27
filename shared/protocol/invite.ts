/**
 * The invite: `<16 hyphen-joined words>@<host[:port]>`, carried out of band.
 *
 * The scheme is not part of the token, so a parsed invite always dials wss://host/ — an
 * invite minted against one scheme cannot be redeemed against another.
 *
 * This file imports psk.ts, so the relay's dependency cone must never reach it.
 */

import { pskToWords, wordsToPsk } from "../crypto/psk.ts";

export interface Invite {
  psk: Uint8Array;
  relay: string;
}

export class InvalidInviteError extends Error {
  constructor(reason: string) {
    super(`invalid invite: ${reason}`);
  }
}

export function formatInvite(psk: Uint8Array, relayUrl: string): string {
  return `${pskToWords(psk)}@${hostOf(relayUrl)}`;
}

export function parseInvite(text: string): Invite {
  const token = text.trim();

  const at = token.indexOf("@");
  if (at < 0) throw new InvalidInviteError("the host is missing — an invite is <words>@<host>");

  const hostPart = token.slice(at + 1);
  if (hostPart.length === 0) throw new InvalidInviteError("the host after @ is missing");

  const psk = wordsToPsk(token.slice(0, at));

  return { psk, relay: `wss://${hostAsWritten(hostPart)}/` };
}

function hostOf(relayUrl: string): string {
  let parsed: URL;
  try {
    parsed = new URL(relayUrl);
  } catch {
    throw new InvalidInviteError(`the relay is not a URL: ${relayUrl}`);
  }

  if (parsed.host.length === 0) throw new InvalidInviteError(`the relay URL has no host: ${relayUrl}`);

  return parsed.host;
}

function hostAsWritten(hostPart: string): string {
  let parsed: URL;
  try {
    parsed = new URL(`wss://${hostPart}/`);
  } catch {
    throw new InvalidInviteError(`not a host: ${hostPart}`);
  }

  if (parsed.host.toLowerCase() !== hostPart.toLowerCase()) {
    throw new InvalidInviteError(`not a plain host or host:port: ${hostPart}`);
  }

  return parsed.host;
}
