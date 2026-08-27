/**
 * The symmetric ratchet: message keys by counter, with a bounded cache for messages that
 * arrive out of order.
 *
 * AES-256-GCM (seal.ts, via WebCrypto) takes a 32-byte key and a 12-byte nonce; both are
 * cut from one 44-byte HKDF output here. seal.ts declares neither size.
 *
 * `nextKey` zeroes the chain buffer it was handed, so callers must assign the returned
 * chain over the one they passed. Zeroing is best-effort: nothing in JavaScript can reach
 * a copy the engine made, so `fill(0)` bounds how long a key is readable and guarantees
 * nothing more.
 */

import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";

const MESSAGE_KEY_LABEL = "termino/mk/v2";
const CHAIN_KEY_LABEL = "termino/ck/v2";

const CHAIN_BYTES = 32;

const MESSAGE_KEY_BYTES = 32;
const NONCE_BYTES = 12;

export const MAX_SKIP = 256;

const utf8 = (text: string) => new TextEncoder().encode(text);

export interface MessageKey {
  key: Uint8Array;
  nonce: Uint8Array;
}

export interface Advance extends MessageKey {
  chain: Uint8Array;
}

export class RatchetError extends Error {}

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
  take(counter: number): MessageKey;
  skipped(): number[];
  wipe(): Uint8Array[];
}

export function startReceiving(chain: Uint8Array): ReceivingChain {
  if (chain.length !== CHAIN_BYTES) {
    throw new RatchetError(`a chain key is ${CHAIN_BYTES} bytes, got ${chain.length}`);
  }

  let current = chain;
  let nextCounter = 0;
  let wiped = false;

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

function wipeKey(messageKey: MessageKey | undefined): void {
  messageKey?.key.fill(0);
  messageKey?.nonce.fill(0);
}
