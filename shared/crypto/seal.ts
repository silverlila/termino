/** AES-GCM is used for the AEAD guarantee, not merely for confidentiality:
 * tampering with a sealed message must fail loudly rather than silently
 * producing altered plaintext. WebCrypto is built into Bun, so this costs no
 * dependency.
 *
 * The nonce is a parameter rather than something generated here. Every key this
 * module is handed comes from the ratchet and is used for exactly one message,
 * and its nonce is derived alongside it — so the same key and nonce arriving
 * twice is a bug upstream, not something to paper over with fresh randomness. */

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

async function importKey(messageKey: Uint8Array): Promise<CryptoKey> {
  return await crypto.subtle.importKey("raw", view(messageKey), "AES-GCM", false, [
    "encrypt",
    "decrypt",
  ]);
}

export async function seal(
  messageKey: Uint8Array,
  nonce: Uint8Array,
  plaintext: Uint8Array,
): Promise<Uint8Array> {
  const key = await importKey(messageKey);

  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: view(nonce) },
    key,
    view(plaintext),
  );

  return new Uint8Array(ciphertext);
}

/** Throws DecryptError if the ciphertext does not authenticate. Never returns
 * altered plaintext. */
export async function open(
  messageKey: Uint8Array,
  nonce: Uint8Array,
  ciphertext: Uint8Array,
): Promise<Uint8Array> {
  const key = await importKey(messageKey);

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
