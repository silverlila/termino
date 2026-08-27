/**
 * Length padding into fixed buckets.
 *
 * AES-GCM ciphertext is the plaintext length plus a 16-byte tag, so an unpadded message
 * shows the relay its exact size; rounding to a bucket is the only thing hiding it.
 *
 * `unpad` runs only on AEAD-verified bytes, which is what makes its error strings safe
 * to be non-constant-time. Nothing in the signature enforces that.
 */

export const BUCKETS: readonly number[] = [256, 512, 1024, 2048, 4096];

const LENGTH_PREFIX_BYTES = 2;

const MAX_PADDED_BYTES = Math.max(...BUCKETS) - LENGTH_PREFIX_BYTES;

export class PaddingError extends Error {
  constructor(reason: string) {
    super(`invalid padding: ${reason}`);
  }
}

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
