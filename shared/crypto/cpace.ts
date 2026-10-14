/**
 * CPace (draft-irtf-cfrg-cpace-21) on ristretto255 with SHA-512: a password-authenticated
 * key exchange. The password picks the generator the two Diffie–Hellman shares are built
 * on, so a recorded exchange gives nobody a way to test a guess offline — the only test
 * is a live exchange, which fails where both sides can see it.
 *
 * Names follow the draft (PRS, CI, sid, AD, ISK) so each function can be checked against
 * it line by line; test/shared/crypto/cpace.test.ts runs the draft's appendix B.3
 * vectors. Party roles are symmetric here, so the transcript is the ordered one (o_cat),
 * and each side's associated data must be unique (draft §10.1) — callers pass fresh
 * random bytes.
 *
 * Scalars are bigints, which JavaScript gives no way to overwrite: unlike the byte
 * buffers elsewhere in shared/crypto/, a scalar is gone only when it is collected.
 */

import { ristretto255, ristretto255_hasher } from "@noble/curves/ed25519.js";
import { bytesToNumberLE } from "@noble/curves/utils.js";
import { sha512 } from "@noble/hashes/sha2.js";
import { concatBytes } from "@noble/hashes/utils.js";

const Point = ristretto255.Point;
type Point = InstanceType<typeof Point>;

const DSI = new TextEncoder().encode("CPaceRistretto255");
const DSI_ISK = new TextEncoder().encode("CPaceRistretto255_ISK");
const ORDERED = new TextEncoder().encode("oc");

// SHA-512 consumes its input in 128-byte blocks.
const HASH_BLOCK_BYTES = 128;
const SCALAR_BYTES = 32;

export class CPaceError extends Error {
  constructor(reason: string) {
    super(`password exchange failed: ${reason}`);
  }
}

/** The draft's LEB128-prefixed length-value encoding. */
export function lvCat(...parts: Uint8Array[]): Uint8Array {
  return concatBytes(...parts.map(prependLength));
}

function prependLength(data: Uint8Array): Uint8Array {
  const length: number[] = [];
  let remaining = data.length;

  do {
    let byte = remaining & 0x7f;
    remaining >>>= 7;
    if (remaining > 0) byte |= 0x80;
    length.push(byte);
  } while (remaining > 0);

  return concatBytes(Uint8Array.from(length), data);
}

export function calculateGenerator(prs: Uint8Array, ci: Uint8Array, sid: Uint8Array): Point {
  // The zero padding fills the hash's first block with DSI and PRS alone, so the time
  // spent hashing does not depend on how long the password is.
  const padding = Math.max(
    0,
    HASH_BLOCK_BYTES - prependLength(prs).length - prependLength(DSI).length - 1,
  );
  const generatorString = lvCat(DSI, prs, new Uint8Array(padding), ci, sid);

  return ristretto255_hasher.deriveToCurve!(sha512(generatorString));
}

/** The draft's recommended sampling: 32 random bytes with the bits above 252 cleared. */
export function sampleScalar(): bigint {
  for (;;) {
    const bytes = crypto.getRandomValues(new Uint8Array(SCALAR_BYTES));
    bytes[SCALAR_BYTES - 1]! &= 0x0f;

    const scalar = scalarFromBytes(bytes) % Point.Fn.ORDER;
    bytes.fill(0);
    if (scalar !== 0n) return scalar;
  }
}

export function scalarFromBytes(littleEndian: Uint8Array): bigint {
  return bytesToNumberLE(littleEndian);
}

export function scalarMult(scalar: bigint, generator: Point): Uint8Array {
  return generator.multiply(scalar % Point.Fn.ORDER).toBytes();
}

/** The shared point, or a refusal: a share that does not decode, or that lands on the
 * identity, is exactly what an attacker sends to learn something. */
export function scalarMultVerified(scalar: bigint, theirShare: Uint8Array): Uint8Array {
  let decoded: Point;
  try {
    decoded = Point.fromBytes(theirShare);
  } catch {
    throw new CPaceError("the other side's share is not a valid point");
  }

  const shared = decoded.multiply(scalar % Point.Fn.ORDER);
  if (shared.is0()) throw new CPaceError("the other side's share is the identity");

  return shared.toBytes();
}

/** The intermediate session key, from the shared point and the ordered transcript. */
export function intermediateSessionKey(
  sid: Uint8Array,
  sharedPoint: Uint8Array,
  ours: { share: Uint8Array; ad: Uint8Array },
  theirs: { share: Uint8Array; ad: Uint8Array },
): Uint8Array {
  const transcript = orderedConcat(lvCat(ours.share, ours.ad), lvCat(theirs.share, theirs.ad));
  return sha512(concatBytes(lvCat(DSI_ISK, sid, sharedPoint), transcript));
}

function orderedConcat(left: Uint8Array, right: Uint8Array): Uint8Array {
  const [larger, smaller] = compareBytes(left, right) > 0 ? [left, right] : [right, left];
  return concatBytes(ORDERED, larger, smaller);
}

function compareBytes(left: Uint8Array, right: Uint8Array): number {
  const shared = Math.min(left.length, right.length);
  for (let index = 0; index < shared; index += 1) {
    if (left[index] !== right[index]) return left[index]! - right[index]!;
  }
  return left.length - right.length;
}
