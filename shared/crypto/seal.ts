/** AES-GCM is used for the AEAD guarantee, not merely for confidentiality:
 * tampering with a sealed message must fail loudly rather than silently
 * producing altered plaintext. WebCrypto is built into Bun, so this costs no
 * dependency. */

const NONCE_BYTES = 12;

export interface Sealed {
  /** Fresh per message. Reusing one under the same key breaks AES-GCM badly. */
  nonce: Uint8Array;
  ciphertext: Uint8Array;
}

/** Thrown when a message cannot be authenticated: wrong key, or tampering. */
export class DecryptError extends Error {
  constructor(cause: unknown) {
    super("message failed to decrypt: wrong key or tampered ciphertext");
    this.cause = cause;
  }
}

/**
 * WebCrypto's parameters are typed as ArrayBuffer-backed views, while a plain
 * `Uint8Array` is typed over `ArrayBufferLike` — which also admits
 * `SharedArrayBuffer`, on which WebCrypto refuses to operate. Copying into a
 * fresh view satisfies that at the boundary; it costs one memcpy per message.
 */
function view(bytes: Uint8Array): Uint8Array<ArrayBuffer> {
  return Uint8Array.from(bytes);
}

async function importKey(msgKey: Uint8Array): Promise<CryptoKey> {
  return await crypto.subtle.importKey("raw", view(msgKey), "AES-GCM", false, [
    "encrypt",
    "decrypt",
  ]);
}

export async function seal(msgKey: Uint8Array, plaintext: Uint8Array): Promise<Sealed> {
  const key = await importKey(msgKey);
  const nonce = crypto.getRandomValues(new Uint8Array(NONCE_BYTES));

  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: view(nonce) },
    key,
    view(plaintext),
  );

  return { nonce, ciphertext: new Uint8Array(ciphertext) };
}

/** Throws DecryptError if the ciphertext does not authenticate. Never returns
 * altered plaintext. */
export async function open(
  msgKey: Uint8Array,
  nonce: Uint8Array,
  ciphertext: Uint8Array,
): Promise<Uint8Array> {
  const key = await importKey(msgKey);

  try {
    const plaintext = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: view(nonce) },
      key,
      view(ciphertext),
    );
    return new Uint8Array(plaintext);
  } catch (error) {
    throw new DecryptError(error);
  }
}
