import { Aes } from "https://deno.land/x/crypto@v0.10.1/aes.ts";
import {
  Cbc,
  Padding,
} from "https://deno.land/x/crypto@v0.10.1/block-modes.ts";

async function generateKeyFromPassphrase(
  passphrase: string
): Promise<Uint8Array> {
  const encoder = new TextEncoder();
  const data = encoder.encode(passphrase);
  const hash = await crypto.subtle.digest("SHA-256", data);
  return new Uint8Array(hash);
}

export async function encrypt(
  plainText: string,
  passphrase?: string | null
): Promise<string | null> {
  if (!passphrase) return null;

  const key = await generateKeyFromPassphrase(passphrase);
  const iv = crypto.getRandomValues(new Uint8Array(16));
  const cipher = new Cbc(Aes, key, iv, Padding.PKCS7);
  const encryptedData = cipher.encrypt(new TextEncoder().encode(plainText));
  const encryptedMessage = new Uint8Array([...iv, ...encryptedData]);

  return uint8ArrayToBase64(encryptedMessage);
}

export async function decrypt(
  cipherText: string,
  passphrase?: string | null
): Promise<string | null> {
  if (!passphrase) return null;
  const encryptedMessage = base64ToUint8Array(cipherText);

  const key = await generateKeyFromPassphrase(passphrase);
  const iv = encryptedMessage.slice(0, 16);
  const encryptedData = encryptedMessage.slice(16);
  const decipher = new Cbc(Aes, key, iv, Padding.PKCS7);
  const decryptedData = decipher.decrypt(encryptedData);
  return new TextDecoder().decode(decryptedData);
}

function base64ToUint8Array(base64: string): Uint8Array {
  const binary_string = atob(base64);
  const len = binary_string.length;
  const bytes = new Uint8Array(len);
  for (let i = 0; i < len; i++) {
    bytes[i] = binary_string.charCodeAt(i);
  }
  return bytes;
}

function uint8ArrayToBase64(bytes: Uint8Array): string {
  const binary = Array.prototype.map
    .call(bytes, (ch: number) => String.fromCharCode(ch))
    .join("");
  return btoa(binary);
}
