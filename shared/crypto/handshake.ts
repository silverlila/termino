/**
 * The ephemeral X25519 exchange, folded with the pre-shared key to produce the session
 * root, the two chain keys and the SAS. Passphrase mode (passphrase.ts) replaces the
 * exchange with CPace and shares everything from the root down — `deriveSessionKeys`.
 *
 * @noble/curves rejects a low-order peer key: `x25519.getSharedSecret` throws rather than
 * returning the all-zero shared secret such a key produces. That failure leaves this file
 * as a bare Error, not a HandshakeError, and `src/session.ts` catches it generically.
 */

import { x25519 } from "@noble/curves/ed25519.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, concatBytes } from "@noble/hashes/utils.js";
import { words } from "./fingerprint.ts";
import { PSK_BYTES } from "./psk.ts";

const PUBLIC_KEY_BYTES = 32;

const SESSION_LABEL = "termino/session/v2";
const LO_HI_CHAIN_LABEL = "termino/chain/lohi/v2";
const HI_LO_CHAIN_LABEL = "termino/chain/hilo/v2";
const SAS_LABEL = "termino/sas/v2";

const ROOT_BYTES = 32;
const CHAIN_BYTES = 32;

const SAS_BYTES = 8;

const utf8 = (text: string) => new TextEncoder().encode(text);

export interface EphemeralKeys {
  secretKey: Uint8Array;
  publicKey: Uint8Array;
}

export interface SessionKeys {
  root: Uint8Array;
  sendChain: Uint8Array;
  recvChain: Uint8Array;
  sasWords: string;
}

export class HandshakeError extends Error {
  constructor(reason: string) {
    super(`handshake failed: ${reason}`);
  }
}

/** One side of a key exchange, whichever kind: what goes in its hello, and how the
 * other side's hello turns into session keys. */
export interface Exchange {
  publicKey: Uint8Array;
  associatedData: Uint8Array | null;
  complete(theirPublicKey: Uint8Array, theirAssociatedData: Uint8Array | null): SessionKeys;
}

export function inviteExchange(psk: Uint8Array): Exchange {
  const ephemeral = startHandshake();

  return {
    publicKey: ephemeral.publicKey,
    associatedData: null,
    complete: (theirPublicKey) => completeHandshake(psk, ephemeral, theirPublicKey),
  };
}

export function startHandshake(): EphemeralKeys {
  return x25519.keygen();
}

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

  refuseReflection(myEphemeral.publicKey, theirPublicKey);

  const shared = x25519.getSharedSecret(myEphemeral.secretKey, theirPublicKey);
  const keys = deriveSessionKeys(shared, psk, SESSION_LABEL, myEphemeral.publicKey, theirPublicKey);
  shared.fill(0);

  return keys;
}

export function refuseReflection(myPublicKey: Uint8Array, theirPublicKey: Uint8Array): void {
  if (compareBytes(myPublicKey, theirPublicKey) === 0) {
    throw new HandshakeError("the peer's public key is our own — the hello was reflected back");
  }
}

/**
 * From an exchange's output to the session: the root binds both public keys, sorted, into
 * its info, and direction is decided by the same sort — never by who connected first,
 * which the relay controls.
 */
export function deriveSessionKeys(
  secret: Uint8Array,
  salt: Uint8Array | undefined,
  label: string,
  myPublicKey: Uint8Array,
  theirPublicKey: Uint8Array,
): SessionKeys {
  const weSortLower = compareBytes(myPublicKey, theirPublicKey) < 0;
  const [lower, higher] = weSortLower ? [myPublicKey, theirPublicKey] : [theirPublicKey, myPublicKey];
  const transcript = bytesToHex(concatBytes(lower, higher));

  const root = hkdf(sha256, secret, salt, utf8(label + transcript), ROOT_BYTES);

  const lowerToHigher = hkdf(sha256, root, undefined, utf8(LO_HI_CHAIN_LABEL), CHAIN_BYTES);
  const higherToLower = hkdf(sha256, root, undefined, utf8(HI_LO_CHAIN_LABEL), CHAIN_BYTES);

  return {
    root,
    sendChain: weSortLower ? lowerToHigher : higherToLower,
    recvChain: weSortLower ? higherToLower : lowerToHigher,
    sasWords: words(hkdf(sha256, root, undefined, utf8(SAS_LABEL), SAS_BYTES)),
  };
}

function compareBytes(left: Uint8Array, right: Uint8Array): number {
  for (let index = 0; index < left.length; index += 1) {
    const leftByte = left[index] ?? 0;
    const rightByte = right[index] ?? 0;

    if (leftByte !== rightByte) return leftByte - rightByte;
  }

  return left.length - right.length;
}
