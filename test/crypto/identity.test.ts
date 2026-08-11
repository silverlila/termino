import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { mkdtempSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { IDENTITY_FILE, IdentityFileError, loadOrCreateIdentity } from "../../src/crypto/identity.ts";

let terminoDir: string;

beforeEach(() => {
  terminoDir = join(mkdtempSync(join(tmpdir(), "termino-identity-")), ".termino");
});

afterEach(() => {
  rmSync(terminoDir, { recursive: true, force: true });
});

describe("loadOrCreateIdentity", () => {
  test("creates the key file with mode 0600 so other users cannot read it", () => {
    loadOrCreateIdentity(terminoDir);

    const mode = statSync(join(terminoDir, IDENTITY_FILE)).mode & 0o777;

    expect(mode.toString(8)).toBe("600");
  });

  test("a second load returns the same public key rather than generating a new one", () => {
    const first = loadOrCreateIdentity(terminoDir);
    const second = loadOrCreateIdentity(terminoDir);

    expect(second.publicKeyHex).toBe(first.publicKeyHex);
    expect(Array.from(second.secretKey)).toEqual(Array.from(first.secretKey));
  });

  test("creates the directory when it does not exist yet", () => {
    const identity = loadOrCreateIdentity(terminoDir);

    expect(statSync(terminoDir).isDirectory()).toBe(true);
    expect(identity.publicKey).toHaveLength(32);
  });

  test("two devices generate different identities", () => {
    const other = join(mkdtempSync(join(tmpdir(), "termino-identity-")), ".termino");

    const one = loadOrCreateIdentity(terminoDir);
    const two = loadOrCreateIdentity(other);

    expect(two.publicKeyHex).not.toBe(one.publicKeyHex);

    rmSync(other, { recursive: true, force: true });
  });

  test("the public key is 64 lowercase hex characters", () => {
    const identity = loadOrCreateIdentity(terminoDir);

    expect(identity.publicKeyHex).toMatch(/^[0-9a-f]{64}$/);
  });

  test("a corrupt key file reports what to do rather than failing obscurely", () => {
    loadOrCreateIdentity(terminoDir);
    writeFileSync(join(terminoDir, IDENTITY_FILE), "not a key\n");

    expect(() => loadOrCreateIdentity(terminoDir)).toThrow(IdentityFileError);
  });
});
