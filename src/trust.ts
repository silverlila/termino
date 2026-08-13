import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { hexToBytes } from "@noble/hashes/utils.js";
import { fingerprint } from "../shared/crypto/fingerprint.ts";
import { PUBLIC_KEY_PATTERN } from "../shared/crypto/identity.ts";
import { defaultTerminoDir, ensureTerminoDir } from "../shared/termino-dir.ts";

/**
 * Trust On First Use. The channel password is shared by everyone in the
 * channel, so it proves nothing about who wrote a message; the device key
 * does. This store remembers which key a nickname arrived with, so that a
 * *second* key for the same nickname is an event rather than a silent
 * substitution.
 *
 * It answers "is this the same person as last time", never "is this person
 * who they claim to be" — only a human comparing fingerprints out of band can
 * answer that, which is what `verified` records.
 */

export const KNOWN_KEYS_FILE = "known_keys.json";

export type TrustState = "NEW" | "KNOWN" | "CHANGED";

export interface TrustRecord {
  /** Hex Ed25519 public key last seen for this nickname. */
  pubkey: string;
  /** Set only by a human running `/verify`. Never inferred. */
  verified: boolean;
  /** When this *key* was first seen, not when the nickname was. */
  firstSeen: number;
}

/** Keyed on nickname — see the trust-store decision in the spec. */
export type TrustRecords = Record<string, TrustRecord>;

export class TrustFileError extends Error {
  constructor(
    readonly path: string,
    cause: unknown,
  ) {
    super(`could not read the trust store at ${path}; delete it to start over`);
    this.cause = cause;
  }
}

export function knownKeysPath(terminoDir: string = defaultTerminoDir()): string {
  return join(terminoDir, KNOWN_KEYS_FILE);
}

/** Pure. The whole TOFU decision, with no file and no clock in it. */
export function classify(existing: TrustRecord | undefined, pubkey: string): TrustState {
  if (existing === undefined) return "NEW";
  return existing.pubkey === pubkey ? "KNOWN" : "CHANGED";
}

export interface Observation {
  state: TrustState;
  /** The record as it now stands, whether or not it changed. */
  record: TrustRecord;
  /** A fresh map; the input is never mutated. Identical to the input when
   * nothing changed, so callers can skip writing the file. */
  records: TrustRecords;
}

/**
 * Records having seen `pubkey` under `nick`.
 *
 * A changed key overwrites the stored one and resets `verified`: whatever a
 * human checked before, they did not check this key. `firstSeen` moves with
 * it, because "this key showed up two minutes ago" is the useful fact and
 * the nickname's original date would imply the opposite.
 */
export function observe(
  records: TrustRecords,
  nick: string,
  pubkey: string,
  now: number,
): Observation {
  const existing = records[nick];
  const state = classify(existing, pubkey);

  if (state === "KNOWN" && existing !== undefined) {
    return { state, record: existing, records };
  }

  const record: TrustRecord = { pubkey, verified: false, firstSeen: now };
  return { state, record, records: { ...records, [nick]: record } };
}

/** Pure. `verifyPeer` is the only thing that should grant verification; this
 * is the flag transition underneath it. */
export function setVerified(
  records: TrustRecords,
  nick: string,
  verified: boolean,
): TrustRecords {
  const existing = records[nick];
  if (existing === undefined) return records;

  return { ...records, [nick]: { ...existing, verified } };
}

export type VerifyResult =
  /** The claim matched, and this nickname is now verified. */
  | "verified"
  /** The claim did not match. Nothing changed — a fingerprint that is nearly
   * right is exactly the case verification exists to catch. */
  | "mismatch"
  /** No key has ever been seen for this nickname, so there is nothing to
   * compare against. */
  | "unknown-nick";

export interface VerifyOutcome {
  result: VerifyResult;
  /** The store as it now stands. Identical to the input unless `result` is
   * `verified`, so callers can skip writing the file. */
  records: TrustRecords;
}

/**
 * Pure. Answers `/verify <nick> <fingerprint>`: does the fingerprint a human
 * read out over some other channel match the key this nickname has actually
 * been signing with?
 *
 * Only a human can grant this — no observation of the network ever sets
 * `verified`, because every message in a channel is encrypted under a key
 * every member holds.
 */
export function verifyPeer(records: TrustRecords, nick: string, claimed: string): VerifyOutcome {
  const existing = records[nick];
  if (existing === undefined) return { result: "unknown-nick", records };

  // `fingerprint` emits lowercase words joined by single spaces, so only the
  // side a human typed needs normalising.
  const stored = fingerprint(hexToBytes(existing.pubkey));
  if (normaliseFingerprint(claimed) !== stored) return { result: "mismatch", records };

  return { result: "verified", records: setVerified(records, nick, true) };
}

/**
 * A fingerprint is read aloud and typed back, and neither the ear nor the
 * keyboard preserves spacing or case. Collapsing both is what stops a correct
 * comparison from failing on a double space — the words themselves are chosen
 * so that a genuinely misheard one cannot match.
 */
export function normaliseFingerprint(text: string): string {
  return text.trim().toLowerCase().split(/\s+/).join(" ");
}

/** A missing file is a first run, not an error. */
export function loadTrustRecords(terminoDir: string = defaultTerminoDir()): TrustRecords {
  const path = knownKeysPath(terminoDir);
  if (!existsSync(path)) return {};

  try {
    return parseRecords(readFileSync(path, "utf8"));
  } catch (error) {
    // Never start from an empty store on a corrupt file: that would silently
    // downgrade every known peer to NEW and accept the next key it saw.
    throw new TrustFileError(path, error);
  }
}

export function saveTrustRecords(
  records: TrustRecords,
  terminoDir: string = defaultTerminoDir(),
): void {
  ensureTerminoDir(terminoDir);
  writeFileSync(knownKeysPath(terminoDir), `${JSON.stringify(records, null, 2)}\n`, {
    mode: 0o600,
  });
}

function parseRecords(text: string): TrustRecords {
  const parsed: unknown = JSON.parse(text);

  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    throw new Error("trust store is not a JSON object");
  }

  const records: TrustRecords = {};
  for (const [nick, value] of Object.entries(parsed)) {
    records[nick] = parseRecord(value);
  }

  return records;
}

function parseRecord(value: unknown): TrustRecord {
  if (typeof value !== "object" || value === null) throw new Error("record is not an object");

  const { pubkey, verified, firstSeen } = value as Record<string, unknown>;

  // Checked here rather than where it is used: `verifyPeer` renders the stored
  // key as a fingerprint, and a hand-edited file should be refused at load
  // like every other corruption, not thrown from under a keystroke.
  if (typeof pubkey !== "string" || !PUBLIC_KEY_PATTERN.test(pubkey))
    throw new Error("pubkey is not a hex ed25519 public key");
  if (typeof verified !== "boolean") throw new Error("verified is not a boolean");
  if (typeof firstSeen !== "number") throw new Error("firstSeen is not a number");

  return { pubkey, verified, firstSeen };
}
