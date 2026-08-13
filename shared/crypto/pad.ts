/**
 * Size-bucket padding, applied to the plaintext before it is sealed.
 *
 * AES-GCM ciphertext is exactly the plaintext length plus a 16-byte tag, so
 * without this the relay reads the length of every message to the byte — the
 * difference between "a message moved" and "they typed *yes*". Rounding up to
 * one of five buckets leaves it about 2.3 bits of length instead.
 *
 * The length travels as a two-byte big-endian prefix rather than a trailing
 * sentinel: what is padded here is JSON, and a sentinel scheme would have to
 * reason about which bytes JSON can legally end with.
 */

/** Powers of two from a floor comfortably above a short message, so "yes",
 * "no" and "on my way" are indistinguishable on the wire. */
export const BUCKETS: readonly number[] = [256, 512, 1024, 2048, 4096];

const LENGTH_PREFIX_BYTES = 2;

/** The most a bucket can carry, once the prefix has taken its two bytes. The
 * body cap in `shared/protocol/text.ts` is set so a serialised payload always
 * fits under this; the two numbers cannot be edited independently. */
const MAX_PADDED_BYTES = Math.max(...BUCKETS) - LENGTH_PREFIX_BYTES;

/** Thrown when a plaintext cannot be padded, or a padded buffer is not one
 * this module could have produced. */
export class PaddingError extends Error {
  constructor(readonly reason: string) {
    super(`invalid padding: ${reason}`);
  }
}

/**
 * Throws rather than truncating on an over-long input. Nothing the text rules
 * admit can reach that size, so it firing at all is a bug worth hearing about
 * — and truncating would silently corrupt a message somebody signed.
 */
export function pad(bytes: Uint8Array): Uint8Array {
  const bucket = BUCKETS.find((size) => bytes.length + LENGTH_PREFIX_BYTES <= size);
  if (bucket === undefined) {
    throw new PaddingError(`${bytes.length} bytes is over the usable maximum of ${MAX_PADDED_BYTES}`);
  }

  const padded = new Uint8Array(bucket);
  new DataView(padded.buffer).setUint16(0, bytes.length);
  padded.set(bytes, LENGTH_PREFIX_BYTES);

  return padded;
}

/**
 * Rejects anything malformed instead of returning what it can make of it.
 *
 * A padding oracle is not the worry — the AEAD tag is verified before this
 * runs, so only a buffer this client sealed, or one an attacker holding the
 * channel key produced, ever gets here. Accepting malformed padding would
 * simply hide bugs.
 */
export function unpad(padded: Uint8Array): Uint8Array {
  if (!BUCKETS.includes(padded.length)) {
    throw new PaddingError(`${padded.length} bytes is not one of the buckets`);
  }

  const view = new DataView(padded.buffer, padded.byteOffset, padded.byteLength);
  const length = view.getUint16(0);
  const end = LENGTH_PREFIX_BYTES + length;
  if (end > padded.length) {
    throw new PaddingError(`declared length ${length} runs past the ${padded.length}-byte buffer`);
  }

  const fill = padded.subarray(end);
  if (fill.some((byte) => byte !== 0)) {
    throw new PaddingError("fill region is not all zero");
  }

  return padded.slice(LENGTH_PREFIX_BYTES, end);
}
