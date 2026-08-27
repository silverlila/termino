/**
 * AES-GCM sealing and opening.
 *
 * WebCrypto refuses SharedArrayBuffer-backed buffers — `NodeJS.BufferSource` excludes
 * them — so every key, nonce and payload is copied into a fresh non-shared Uint8Array
 * before it crosses into crypto.subtle: one memcpy per message. `view` therefore returns
 * a copy, not a view.
 */

export class DecryptError extends Error {
  constructor(cause: unknown) {
    super("message failed to decrypt: wrong key or tampered ciphertext");
    this.cause = cause;
  }
}

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
