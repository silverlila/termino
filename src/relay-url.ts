/**
 * A URL's hostname keeps the brackets on an IPv6 literal: loopback is "[::1]", never
 * "::1". No CA issues a certificate for localhost, so wss://localhost cannot be dialled
 * at all — a loopback relay is reached over ws://.
 */

const LOOPBACK_HOSTS = new Set(["localhost", "127.0.0.1", "[::1]"]);

export function isLoopback(hostname: string): boolean {
  return LOOPBACK_HOSTS.has(hostname);
}

export function inviteRelayUrl(fromInvite: string): string {
  const parsed = new URL(fromInvite);
  if (!isLoopback(parsed.hostname)) return fromInvite;

  parsed.protocol = "ws:";
  return parsed.toString();
}
