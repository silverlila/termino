import { mkdirSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

/**
 * Where termino keeps its private files, and the one place that decides how
 * private they are.
 *
 * Both the identity key and the trust store live here, and neither is a fact
 * about the other — so the directory has its own home rather than one of them
 * borrowing it from the other.
 */

export function defaultTerminoDir(): string {
  return join(homedir(), ".termino");
}

/**
 * Creates the directory if it is missing. `0700` is owner-only on purpose:
 * this directory holds a secret key, and a mode set in two places is a mode
 * that eventually disagrees with itself.
 */
export function ensureTerminoDir(terminoDir: string): void {
  mkdirSync(terminoDir, { recursive: true, mode: 0o700 });
}
