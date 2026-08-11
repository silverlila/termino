import { chmodSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { ed25519 } from "@noble/curves/ed25519.js";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";

/**
 * A per-device Ed25519 keypair. The channel password is shared by everyone in
 * the channel, so it authenticates nobody — without a per-device key, any
 * member could encrypt a message claiming to be from any other member.
 */

export const IDENTITY_FILE = "identity.key";

export function defaultTerminoDir(): string {
  return join(homedir(), ".termino");
}

export class IdentityFileError extends Error {
  constructor(readonly path: string, cause: unknown) {
    super(`could not read the identity key at ${path}; delete it to generate a new one`);
    this.cause = cause;
  }
}

export interface Identity {
  /** Never transmitted, never logged. */
  secretKey: Uint8Array;
  publicKey: Uint8Array;
  /** How the public key travels inside the encrypted payload. */
  publicKeyHex: string;
}

/**
 * Returns this device's identity, generating and persisting one on first run.
 * The directory is a parameter so tests can use a temporary one rather than
 * the real home directory.
 */
export function loadOrCreateIdentity(terminoDir: string = defaultTerminoDir()): Identity {
  const path = join(terminoDir, IDENTITY_FILE);

  if (existsSync(path)) return loadIdentity(path);

  const secretKey = ed25519.utils.randomSecretKey();
  mkdirSync(terminoDir, { recursive: true, mode: 0o700 });
  writeFileSync(path, `${bytesToHex(secretKey)}\n`, { mode: 0o600 });
  // writeFileSync's mode is subject to the process umask, so pin it explicitly.
  chmodSync(path, 0o600);

  return identityFrom(secretKey);
}

function loadIdentity(path: string): Identity {
  const stored = readFileSync(path, "utf8").trim();

  try {
    return identityFrom(hexToBytes(stored));
  } catch (error) {
    throw new IdentityFileError(path, error);
  }
}

function identityFrom(secretKey: Uint8Array): Identity {
  const publicKey = ed25519.getPublicKey(secretKey);
  return { secretKey, publicKey, publicKeyHex: bytesToHex(publicKey) };
}
