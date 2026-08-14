import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";

/**
 * The symmetric ratchet: one key per message, deleted once it has been used.
 *
 * A chain key hashes forward into the key for the next message and into its
 * own successor, and nothing hashes backward. From chain #5 a holder reaches
 * #6, #7, #8 forever and no arithmetic returns them to #4, so a key taken off
 * a running session opens the rest of it and nothing that came before. The old
 * key is not hidden — after `nextKey` it does not exist anywhere.
 *
 * The relay is not a reliable ordered channel: it can drop, reorder or
 * withhold. So a receiver handed a counter beyond the one it expected derives
 * the keys it stepped over and keeps them, rather than wedging the session on
 * one lost frame. Both of the bounds below exist because that cache is
 * something a hostile peer would otherwise grow for free.
 */

/** Distinct labels so the message key and the next chain key cannot collide. */
const MESSAGE_KEY_LABEL = "termino/mk/v2";
const CHAIN_KEY_LABEL = "termino/ck/v2";

/** Matches the chain keys the handshake hands out. */
const CHAIN_BYTES = 32;

/** AES-256-GCM: a 32-byte key and a 12-byte nonce, derived together as 44
 * bytes of one HKDF output. The nonce is derived rather than sent because the
 * key is used exactly once — deriving it costs nothing, removes 12 bytes from
 * every frame, and is safe in a way an all-zero nonce would stop being the
 * moment anything ever reused a key. */
const MESSAGE_KEY_BYTES = 32;
const NONCE_BYTES = 12;

/**
 * The most messages a single jump may skip, and the most keys the cache holds.
 * One maximal jump therefore fills the cache exactly.
 *
 * A bound is not optional: without the first, a peer sending counter 2³¹ makes
 * the receiver derive two billion keys; without the second, a peer sending
 * 256, 512, 768… accumulates keys for as long as the session runs.
 */
export const MAX_SKIP = 256;

const utf8 = (text: string) => new TextEncoder().encode(text);

export interface MessageKey {
  key: Uint8Array;
  nonce: Uint8Array;
}

export interface Advance extends MessageKey {
  /** The chain to use next. The chain passed in has been zeroed. */
  chain: Uint8Array;
}

/** Thrown when a counter cannot be serviced. Every case is a lost, replayed or
 * hostile frame, and each one is announced rather than dropped quietly. */
export class RatchetError extends Error {}

/**
 * Derives the key and nonce for one message and advances the chain.
 *
 * **Zeroes the chain it is given.** That mutation is the point: a chain key
 * left lying around recomputes every message key after it, so the caller is
 * given no way to keep using the old one by accident. Assign the returned
 * `chain` over it.
 */
export function nextKey(chain: Uint8Array): Advance {
  if (chain.length !== CHAIN_BYTES) {
    throw new RatchetError(`a chain key is ${CHAIN_BYTES} bytes, got ${chain.length}`);
  }

  const material = hkdf(
    sha256,
    chain,
    undefined,
    utf8(MESSAGE_KEY_LABEL),
    MESSAGE_KEY_BYTES + NONCE_BYTES,
  );
  const following = hkdf(sha256, chain, undefined, utf8(CHAIN_KEY_LABEL), CHAIN_BYTES);

  const key = material.slice(0, MESSAGE_KEY_BYTES);
  const nonce = material.slice(MESSAGE_KEY_BYTES);
  material.fill(0);
  chain.fill(0);

  return { key, nonce, chain: following };
}

export interface ReceivingChain {
  /** The key and nonce for one arriving counter. Throws `RatchetError` rather
   * than returning a key that would open the wrong message. */
  take(counter: number): MessageKey;
  /** Counters whose keys are cached and whose messages have not arrived,
   * lowest first — the open gaps, which is what a "never arrived" notice
   * counts. */
  skipped(): number[];
  /**
   * Zeroes the chain and every cached key. Nothing may be taken afterwards.
   *
   * Returns the buffers it overwrote, every one of them now all zeros. The
   * cache is private, so without this "the keys are gone" would be a claim
   * about state nothing outside can look at — and a security claim nobody can
   * check is one nobody should believe.
   */
  wipe(): Uint8Array[];
}

/**
 * The receiving half of one direction: a chain key, a counter, and the keys
 * for messages that were stepped over and may still turn up.
 *
 * A counter is serviced exactly once. That is what replaces replay protection
 * outright — a second copy of a message finds no key left to open it, so there
 * is no window to keep, no set of delivered signatures, and no dependence on
 * either machine's clock.
 */
export function startReceiving(chain: Uint8Array): ReceivingChain {
  if (chain.length !== CHAIN_BYTES) {
    throw new RatchetError(`a chain key is ${CHAIN_BYTES} bytes, got ${chain.length}`);
  }

  let current = chain;
  let nextCounter = 0;
  let wiped = false;

  // Insertion is always in ascending counter order, so the map's own order is
  // the gap order: the oldest entry is the first key, which is the one
  // eviction drops.
  const cache = new Map<number, MessageKey>();

  function advance(): MessageKey {
    const { key, nonce, chain: following } = nextKey(current);
    current = following;
    nextCounter += 1;

    return { key, nonce };
  }

  function remember(counter: number, messageKey: MessageKey): void {
    if (cache.size >= MAX_SKIP) {
      const oldest = cache.keys().next().value;

      if (oldest !== undefined) {
        wipeKey(cache.get(oldest));
        cache.delete(oldest);
      }
    }

    cache.set(counter, messageKey);
  }

  function take(counter: number): MessageKey {
    if (wiped) throw new RatchetError("the session's keys have been wiped");
    if (!Number.isSafeInteger(counter) || counter < 0) {
      throw new RatchetError(`message counter ${counter} is not a whole number`);
    }

    const cached = cache.get(counter);
    if (cached) {
      cache.delete(counter);
      return cached;
    }

    if (counter < nextCounter) {
      throw new RatchetError(`message ${counter} has already been delivered, or its key is gone`);
    }

    // Ahead of what the chain has reached by more than the cache can hold. A
    // real gap this large means the messages are unrecoverable anyway; a
    // counter of 2³¹ means somebody is asking for two billion derivations.
    if (counter - nextCounter > MAX_SKIP) {
      throw new RatchetError(
        `message ${counter} is more than ${MAX_SKIP} ahead of ${nextCounter} and cannot be opened`,
      );
    }

    while (nextCounter < counter) {
      const skippedCounter = nextCounter;
      remember(skippedCounter, advance());
    }

    return advance();
  }

  function skipped(): number[] {
    return [...cache.keys()];
  }

  function wipe(): Uint8Array[] {
    const cached = [...cache.values()].flatMap((entry) => [entry.key, entry.nonce]);
    const overwritten = [current, ...cached];

    current.fill(0);
    for (const messageKey of cache.values()) wipeKey(messageKey);
    cache.clear();
    wiped = true;

    return overwritten;
  }

  return { take, skipped, wipe };
}

/** Best-effort: it overwrites the buffer we hold and cannot reach a copy the
 * engine made. It still bounds how long the key is readable. */
function wipeKey(messageKey: MessageKey | undefined): void {
  messageKey?.key.fill(0);
  messageKey?.nonce.fill(0);
}
