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

/** How a public key looks everywhere it is written down — on the wire, and in
 * the trust store. One home, so the two can never drift apart. */
export const PUBLIC_KEY_PATTERN = /^[0-9a-f]{64}$/;

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

  return createIdentity(terminoDir, path);
}

/**
 * Writes with `wx` — create-exclusively — rather than the default truncating
 * write. Two termino processes started at once on first run both see the file
 * missing and both generate a key; without `wx` the second silently overwrites
 * the first, and the losing process spends its whole session signing with a
 * key that no longer exists on disk, so its identity rotates behind the user's
 * back on the next launch. Losing the race is not an error — it just means
 * somebody else created this device's identity a moment ago, so read theirs.
 */
function createIdentity(terminoDir: string, path: string): Identity {
  const secretKey = ed25519.utils.randomSecretKey();
  mkdirSync(terminoDir, { recursive: true, mode: 0o700 });

  try {
    writeFileSync(path, `${bytesToHex(secretKey)}\n`, { flag: "wx", mode: 0o600 });
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
    return loadIdentity(path);
  }

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
