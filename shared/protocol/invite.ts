import { pskToWords, wordsToPsk } from "../crypto/psk.ts";

/**
 * The invite: the single token one person hands another, carrying both halves
 * of what is needed to talk — the secret and where to meet.
 *
 * ```
 * acorn-yoga-...-tank@relay.example:8787
 * ```
 *
 * `termino join ` is the command a person types in front of it, not part of
 * the token, and `parseInvite` does not accept it. One token is the point:
 * two things to copy across is one thing to get wrong, and a mismatched relay
 * fails as silence rather than as an error.
 *
 * This module imports crypto and so must never be reached from `server/` or
 * `shared/protocol/frame.ts` — `bun run check:relay-pure` enforces that the
 * relay's imports stop at `frame.ts`.
 */

export interface Invite {
  psk: Uint8Array;
  /** The URL to dial, canonically `wss://host[:port]/`. */
  relay: string;
}

export class InvalidInviteError extends Error {
  constructor(readonly reason: string) {
    super(`invalid invite: ${reason}`);
  }
}

/**
 * The scheme is not carried in the token. Only the host survives, and reading
 * it back always yields `wss://`, so a token minted against one scheme cannot
 * be redeemed against another without somebody noticing.
 */
export function formatInvite(psk: Uint8Array, relayUrl: string): string {
  return `${pskToWords(psk)}@${hostOf(relayUrl)}`;
}

/** Throws naming what is wrong: the word count found, the offending word, or
 * the missing host. A person retyping an invite needs to know which. */
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

/**
 * A host and an optional port, and nothing else. Anything a URL would absorb
 * into a path, a query or a userinfo section is rejected rather than quietly
 * dropped, so `...@evil.example/relay.example` cannot read as the host the
 * eye picks out of it.
 */
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
