import { argon2id } from "@noble/hashes/argon2.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex } from "@noble/hashes/utils.js";

/**
 * FROZEN. These parameters are part of the wire contract, not a performance
 * knob: changing any of them changes every derived handle, so a client using
 * different values lands in a different channel while appearing to work.
 * The ~850 ms cost is the entire anti-guessing budget and is paid once per
 * session. derive.test.ts carries a known-answer vector that fails if this
 * object is edited. Never reduce `m`.
 */
const ARGON2ID = { t: 3, m: 65536, p: 1, dkLen: 32 } as const;

/**
 * The salt is derived from the channel name so that it is identical on every
 * machine — derivation must be deterministic — while still differing between
 * channels, so one channel's argon2id work never carries over to another.
 */
const SALT_LABEL = "termino/salt/v1|";

/** Distinct HKDF labels are what make the two outputs independent. */
const HANDLE_LABEL = "termino/handle/v1";
const MSGKEY_LABEL = "termino/msgkey/v1";

const HANDLE_BYTES = 16; // 32 lowercase hex chars on the wire
const MSGKEY_BYTES = 32; // AES-256-GCM

const utf8 = (text: string) => new TextEncoder().encode(text);

export interface ChannelKeys {
  /** Routing label. The only one of the two the relay ever sees. */
  handle: string;
  /** Message key. Never transmitted, never persisted. */
  msgKey: Uint8Array;
}

/**
 * Turns a channel name and password into the pair of values the rest of the
 * client needs. Deterministic: two people typing the same two strings on
 * different machines arrive at byte-identical results, which is what lets them
 * meet at the same handle without the relay ever learning the password.
 *
 * Blocks for roughly 850 ms. Call it before starting the renderer.
 */
export function deriveChannelKeys(channelName: string, password: string): ChannelKeys {
  const salt = sha256(utf8(SALT_LABEL + channelName));
  const secret = argon2id(password, salt, ARGON2ID);

  const handle = hkdf(sha256, secret, undefined, utf8(HANDLE_LABEL), HANDLE_BYTES);
  const msgKey = hkdf(sha256, secret, undefined, utf8(MSGKEY_LABEL), MSGKEY_BYTES);

  return { handle: bytesToHex(handle), msgKey };
}
