/**
 * Replay protection.
 *
 * A signature proves who wrote a message. It does not prove that they wrote it
 * *now*, or that this is the first time it has arrived — the relay forwards
 * whatever it is handed, and a handle travels in the clear, so anybody who can
 * watch the wire can subscribe and send a captured frame again. It decrypts, it
 * verifies, and without this it lands in the transcript as something freshly
 * said.
 *
 * Two checks, because neither is sufficient alone: a window, so a recording
 * cannot be played back tomorrow, and a set of what has already been delivered,
 * so it cannot be played back twice this minute.
 */

/**
 * How far either side of now a message may be dated. Wide enough that two
 * machines with ordinarily sloppy clocks still talk — this is the same order
 * as Kerberos' five minutes — and narrow enough that the set below stays
 * small. A clock more than this far out silences the peer with a notice
 * saying so, which is the honest failure: the alternative is accepting
 * anything anyone recorded, forever.
 */
export const FRESHNESS_WINDOW_MS = 5 * 60_000;

export type Freshness =
  /** Never delivered before, and dated inside the window. Show it. */
  | "fresh"
  /** This exact signature has already been delivered this session. */
  | "replayed"
  /** Dated further from now than the window, in either direction. */
  | "stale";

/**
 * Signature → the timestamp it carried, which is what says when it may be
 * forgotten. Keyed on the signature rather than the nonce: a member of the
 * channel can re-seal somebody else's signed payload under a fresh nonce, and
 * the signature is what stays the same across every copy of one message.
 */
export type SeenMessages = Map<string, number>;

export interface Admission {
  freshness: Freshness;
  /** The set as it now stands. Identical to the input unless the message was
   * admitted, so a caller rejecting one has nothing to store. */
  seen: SeenMessages;
}

function insideWindow(sentAt: number, now: number): boolean {
  return Math.abs(now - sentAt) <= FRESHNESS_WINDOW_MS;
}

/**
 * Decides whether a message that has already decrypted and verified may be
 * shown, and returns the set to carry into the next one.
 *
 * Admitting one drops every signature that has aged out of the window on the
 * way past, which is what keeps the set bounded by the message rate rather
 * than by the length of the session. Forgetting is safe: a second copy of a
 * message that old is refused as stale before the set is ever consulted.
 *
 * Two messages are the same message only if they carry the same signature,
 * which covers the sender, the nickname, the body, the channel and the
 * timestamp. Saying the same words twice produces a different signature,
 * because the second one is sent at a different millisecond.
 */
export function admit(
  seen: SeenMessages,
  signature: string,
  sentAt: number,
  now: number,
): Admission {
  if (!insideWindow(sentAt, now)) return { freshness: "stale", seen };
  if (seen.has(signature)) return { freshness: "replayed", seen };

  const next: SeenMessages = new Map();
  for (const [remembered, rememberedAt] of seen) {
    if (insideWindow(rememberedAt, now)) next.set(remembered, rememberedAt);
  }
  next.set(signature, sentAt);

  return { freshness: "fresh", seen: next };
}
