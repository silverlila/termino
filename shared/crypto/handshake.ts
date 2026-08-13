import { x25519 } from "@noble/curves/ed25519.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, concatBytes } from "@noble/hashes/utils.js";
import { words } from "./fingerprint.ts";
import { PSK_BYTES } from "./psk.ts";

/**
 * The per-session handshake: a fresh Diffie-Hellman exchange with the
 * pre-shared key folded into the derivation.
 *
 * The exchange is what gives forward secrecy — both ephemeral secret keys are
 * created at connect and dropped at disconnect, so once they are gone nobody,
 * including the two people who talked, can recompute the session key for
 * traffic somebody recorded.
 *
 * The pre-shared key is what gives authentication. Diffie-Hellman alone
 * produces a secret shared with *somebody*: a relay can run one exchange with
 * each side and read everything while both ends see a perfect encrypted
 * session. Folding the key in as the HKDF salt means an attacker who ran their
 * own exchange holds a valid shared secret and still cannot reach the root, so
 * the impersonation fails closed rather than succeeding silently.
 */

/** X25519, on both halves. */
const PUBLIC_KEY_BYTES = 32;

/** Every label is distinct so no two values derived here can collide. */
const SESSION_LABEL = "termino/session/v2";
const LO_HI_CHAIN_LABEL = "termino/chain/lohi/v2";
const HI_LO_CHAIN_LABEL = "termino/chain/hilo/v2";
const SAS_LABEL = "termino/sas/v2";

const ROOT_BYTES = 32;
const CHAIN_BYTES = 32;

/** 64 bits, rendered as eight words. Forging a second session whose words
 * match is not worth attempting, and eight words still read aloud in one
 * breath. */
const SAS_BYTES = 8;

const utf8 = (text: string) => new TextEncoder().encode(text);

export interface EphemeralKeys {
  secretKey: Uint8Array;
  publicKey: Uint8Array;
}

export interface SessionKeys {
  /** Everything below is derived from this; it is never sent. */
  root: Uint8Array;
  /** One chain per direction, so a message that opens under `recvChain` was
   * necessarily written by the only other party who holds it. */
  sendChain: Uint8Array;
  recvChain: Uint8Array;
  /** The eight words both people read aloud to each other. Equal on both
   * sides, and different in every session. */
  sasWords: string;
}

/** Thrown when the values a peer sent cannot make a session. Every case is an
 * attack or a corrupt frame, never a hiccup to retry through. */
export class HandshakeError extends Error {
  constructor(readonly reason: string) {
    super(`handshake failed: ${reason}`);
  }
}

/** The ephemeral keypair whose public half goes out in a `hello`. Generated
 * per session and never persisted. */
export function startHandshake(): EphemeralKeys {
  return x25519.keygen();
}

/**
 * Turns the peer's `hello` into the keys for the rest of the session.
 *
 * A pure function of its three arguments: both sides run it on the same two
 * public keys and the same secret, and land on identical bytes.
 */
export function completeHandshake(
  psk: Uint8Array,
  myEphemeral: EphemeralKeys,
  theirPublicKey: Uint8Array,
): SessionKeys {
  if (psk.length !== PSK_BYTES) {
    throw new HandshakeError(`the secret is ${PSK_BYTES} bytes, got ${psk.length}`);
  }
  if (theirPublicKey.length !== PUBLIC_KEY_BYTES) {
    throw new HandshakeError(
      `a public key is ${PUBLIC_KEY_BYTES} bytes, got ${theirPublicKey.length}`,
    );
  }

  const order = compareBytes(myEphemeral.publicKey, theirPublicKey);

  // Our own key back at us. Two fresh keys colliding is not something that
  // happens, so this is a hostile relay reflecting a hello — and a reflected
  // hello is the one case where both sides could otherwise agree on a key
  // while disagreeing about who they are talking to. There is also no
  // direction left to assign: neither key sorts lower.
  if (order === 0) {
    throw new HandshakeError("the peer's public key is our own — the hello was reflected back");
  }

  // Throws on a small-order key rather than returning the all-zero shared
  // secret every such key produces. Let it propagate: an all-zero secret is
  // somebody trying to fix the session key, not a transient failure.
  const shared = x25519.getSharedSecret(myEphemeral.secretKey, theirPublicKey);

  // Both public keys, in an order both sides compute the same way, bound into
  // the derivation. Without this an attacker can reorder or replay a hello and
  // leave the two sides agreeing on a key under different beliefs about who
  // sent what.
  const weSortLower = order < 0;
  const [lower, higher] = weSortLower
    ? [myEphemeral.publicKey, theirPublicKey]
    : [theirPublicKey, myEphemeral.publicKey];
  const transcript = bytesToHex(concatBytes(lower, higher));

  // The secret is the salt and the exchange output is the keying material.
  // This is the fold that makes the pre-shared key Termino's certificate.
  const root = hkdf(sha256, shared, psk, utf8(SESSION_LABEL + transcript), ROOT_BYTES);
  shared.fill(0);

  const lowerToHigher = hkdf(sha256, root, undefined, utf8(LO_HI_CHAIN_LABEL), CHAIN_BYTES);
  const higherToLower = hkdf(sha256, root, undefined, utf8(HI_LO_CHAIN_LABEL), CHAIN_BYTES);

  return {
    root,
    // Direction follows the byte order of the two keys, not who connected
    // first: the relay decides delivery order, so letting order decide roles
    // would hand the relay the roles.
    sendChain: weSortLower ? lowerToHigher : higherToLower,
    recvChain: weSortLower ? higherToLower : lowerToHigher,
    sasWords: words(hkdf(sha256, root, undefined, utf8(SAS_LABEL), SAS_BYTES)),
  };
}

/** Lexicographic on bytes, the ordering both sides agree on without
 * exchanging anything further. */
function compareBytes(left: Uint8Array, right: Uint8Array): number {
  for (let index = 0; index < left.length; index += 1) {
    const leftByte = left[index] ?? 0;
    const rightByte = right[index] ?? 0;

    if (leftByte !== rightByte) return leftByte - rightByte;
  }

  return left.length - right.length;
}
