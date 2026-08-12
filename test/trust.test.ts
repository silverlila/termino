import { afterEach, beforeEach, describe, expect, it } from "bun:test";
import { mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  classify,
  knownKeysPath,
  loadTrustRecords,
  normaliseFingerprint,
  observe,
  saveTrustRecords,
  setVerified,
  TrustFileError,
  verifyPeer,
  type TrustRecords,
} from "../src/trust.ts";

const ALICE_KEY = "a".repeat(64);
const OTHER_KEY = "b".repeat(64);

/** Recorded from `fingerprint.ts`, not recomputed here: a test that derives
 * the expected value the way the code does can never disagree with it. */
const ALICE_FINGERPRINT = "tech topic leopard fruit knife brain purple club";
const OTHER_FINGERPRINT = "fluid parade farm crop quail label census honey";

let terminoDir: string;

beforeEach(() => {
  terminoDir = mkdtempSync(join(tmpdir(), "termino-trust-"));
});

afterEach(() => {
  rmSync(terminoDir, { recursive: true, force: true });
});

describe("trust on first use", () => {
  it("reports a first-seen nickname as NEW", () => {
    expect(observe({}, "alice", ALICE_KEY, 1000).state).toBe("NEW");
  });

  it("reports the same key for the same nickname as KNOWN", () => {
    const first = observe({}, "alice", ALICE_KEY, 1000);
    expect(observe(first.records, "alice", ALICE_KEY, 2000).state).toBe("KNOWN");
  });

  it("reports a different key for the same nickname as CHANGED", () => {
    const first = observe({}, "alice", ALICE_KEY, 1000);
    expect(observe(first.records, "alice", OTHER_KEY, 2000).state).toBe("CHANGED");
  });

  it("treats two nicknames as unrelated", () => {
    const first = observe({}, "alice", ALICE_KEY, 1000);
    expect(observe(first.records, "bob", OTHER_KEY, 2000).state).toBe("NEW");
  });

  it("records a new nickname as unverified", () => {
    expect(observe({}, "alice", ALICE_KEY, 1000).record).toEqual({
      pubkey: ALICE_KEY,
      verified: false,
      firstSeen: 1000,
    });
  });

  it("never mutates the records it was given", () => {
    const records: TrustRecords = {};
    observe(records, "alice", ALICE_KEY, 1000);
    expect(records).toEqual({});
  });

  it("returns the identical records object when nothing changed", () => {
    const first = observe({}, "alice", ALICE_KEY, 1000);
    const second = observe(first.records, "alice", ALICE_KEY, 2000);

    // Callers use this to decide whether to write the file at all.
    expect(second.records).toBe(first.records);
  });

  it("keeps the original firstSeen while the key is unchanged", () => {
    const first = observe({}, "alice", ALICE_KEY, 1000);
    const second = observe(first.records, "alice", ALICE_KEY, 9999);

    expect(second.record.firstSeen).toBe(1000);
  });
});

describe("a changed key", () => {
  it("replaces the stored key", () => {
    const first = observe({}, "alice", ALICE_KEY, 1000);
    const changed = observe(first.records, "alice", OTHER_KEY, 2000);

    expect(changed.record.pubkey).toBe(OTHER_KEY);
  });

  it("resets verified, because nobody checked this key", () => {
    const first = observe({}, "alice", ALICE_KEY, 1000);
    const verified = setVerified(first.records, "alice", true);
    expect(verified.alice?.verified).toBe(true);

    const changed = observe(verified, "alice", OTHER_KEY, 2000);
    expect(changed.record.verified).toBe(false);
  });

  it("dates the record from when the new key appeared", () => {
    const first = observe({}, "alice", ALICE_KEY, 1000);
    const changed = observe(first.records, "alice", OTHER_KEY, 2000);

    expect(changed.record.firstSeen).toBe(2000);
  });

  it("settles back to KNOWN once the new key has been seen", () => {
    const first = observe({}, "alice", ALICE_KEY, 1000);
    const changed = observe(first.records, "alice", OTHER_KEY, 2000);

    expect(observe(changed.records, "alice", OTHER_KEY, 3000).state).toBe("KNOWN");
  });
});

describe("classify", () => {
  it("decides without a file or a clock", () => {
    const record = { pubkey: ALICE_KEY, verified: false, firstSeen: 0 };

    expect(classify(undefined, ALICE_KEY)).toBe("NEW");
    expect(classify(record, ALICE_KEY)).toBe("KNOWN");
    expect(classify(record, OTHER_KEY)).toBe("CHANGED");
  });
});

describe("marking a peer verified", () => {
  it("flips the flag for that nickname only", () => {
    const withAlice = observe({}, "alice", ALICE_KEY, 1000).records;
    const withBob = observe(withAlice, "bob", OTHER_KEY, 1000).records;

    const verified = setVerified(withBob, "alice", true);

    expect(verified.alice?.verified).toBe(true);
    expect(verified.bob?.verified).toBe(false);
  });

  it("ignores a nickname it has never seen", () => {
    expect(setVerified({}, "nobody", true)).toEqual({});
  });

  it("does not mutate the records it was given", () => {
    const records = observe({}, "alice", ALICE_KEY, 1000).records;
    setVerified(records, "alice", true);

    expect(records.alice?.verified).toBe(false);
  });
});

describe("verifying a peer against a fingerprint read out of band", () => {
  const seen = observe({}, "alice", ALICE_KEY, 1000).records;

  it("marks the peer verified when the fingerprint matches the stored key", () => {
    const outcome = verifyPeer(seen, "alice", ALICE_FINGERPRINT);

    expect(outcome.result).toBe("verified");
    expect(outcome.records.alice?.verified).toBe(true);
  });

  it("accepts a fingerprint typed back in the wrong case and spacing", () => {
    const shouted = `  ${ALICE_FINGERPRINT.toUpperCase().replace(/ /g, "   ")}  `;

    expect(verifyPeer(seen, "alice", shouted).result).toBe("verified");
  });

  it("changes nothing when the fingerprint belongs to a different key", () => {
    expect(verifyPeer(seen, "alice", OTHER_FINGERPRINT).result).toBe("mismatch");
    expect(seen.alice?.verified).toBe(false);
  });

  it("changes nothing when a single word is wrong", () => {
    const nearly = ALICE_FINGERPRINT.replace("leopard", "crop");

    expect(verifyPeer(seen, "alice", nearly).result).toBe("mismatch");
  });

  it("reports a nickname it has never seen a key for", () => {
    expect(verifyPeer(seen, "mallory", ALICE_FINGERPRINT).result).toBe("unknown-nick");
  });

  it("verifies only the nickname named", () => {
    const withBob = observe(seen, "bob", OTHER_KEY, 1000).records;
    const outcome = verifyPeer(withBob, "alice", ALICE_FINGERPRINT);

    expect(outcome.result).toBe("verified");
    expect(outcome.records.alice?.verified).toBe(true);
    expect(outcome.records.bob?.verified).toBe(false);
  });

  it("stops trusting a verified nickname once its key changes", () => {
    const outcome = verifyPeer(seen, "alice", ALICE_FINGERPRINT);
    expect(outcome.result).toBe("verified");

    const changed = observe(outcome.records, "alice", OTHER_KEY, 2000);
    expect(changed.state).toBe("CHANGED");
    expect(changed.record.verified).toBe(false);

    // And the fingerprint that used to be right no longer is.
    expect(verifyPeer(changed.records, "alice", ALICE_FINGERPRINT).result).toBe("mismatch");
  });
});

describe("normaliseFingerprint", () => {
  it("collapses the things a phone call and a keyboard do not preserve", () => {
    expect(normaliseFingerprint("  Tech   TOPIC\tleopard ")).toBe("tech topic leopard");
  });
});

describe("persistence", () => {
  it("returns an empty store on first run rather than failing", () => {
    expect(loadTrustRecords(terminoDir)).toEqual({});
  });

  it("survives a round trip through the file", () => {
    const records = observe({}, "alice", ALICE_KEY, 1000).records;
    saveTrustRecords(records, terminoDir);

    expect(loadTrustRecords(terminoDir)).toEqual(records);
  });

  it("remembers a key across restarts, so the second sighting is KNOWN", () => {
    saveTrustRecords(observe({}, "alice", ALICE_KEY, 1000).records, terminoDir);

    const reloaded = loadTrustRecords(terminoDir);
    expect(observe(reloaded, "alice", ALICE_KEY, 2000).state).toBe("KNOWN");
    expect(observe(reloaded, "alice", OTHER_KEY, 2000).state).toBe("CHANGED");
  });

  it("persists the verified field from the first release", () => {
    const records = setVerified(observe({}, "alice", ALICE_KEY, 1000).records, "alice", true);
    saveTrustRecords(records, terminoDir);

    const onDisk = JSON.parse(readFileSync(knownKeysPath(terminoDir), "utf8"));
    expect(onDisk.alice).toEqual({ pubkey: ALICE_KEY, verified: true, firstSeen: 1000 });
  });

  it("writes the store readable only by its owner", () => {
    saveTrustRecords(observe({}, "alice", ALICE_KEY, 1000).records, terminoDir);

    const mode = statSync(knownKeysPath(terminoDir)).mode & 0o777;
    expect(mode.toString(8)).toBe("600");
  });

  it("creates the termino directory if it is missing", () => {
    const nested = join(terminoDir, "does", "not", "exist");
    saveTrustRecords(observe({}, "alice", ALICE_KEY, 1000).records, nested);

    expect(loadTrustRecords(nested).alice?.pubkey).toBe(ALICE_KEY);
  });

  describe("a corrupt store", () => {
    // Starting fresh would downgrade every known peer to NEW and silently
    // accept whatever key arrived next, which is the failure TOFU exists to
    // prevent. Refusing to start is the safe direction.
    const corrupt: Record<string, string> = {
      "truncated JSON": '{"alice": {"pubkey"',
      "an array": "[]",
      "a record missing verified": '{"alice":{"pubkey":"aa","firstSeen":1}}',
      "a record with the wrong type": '{"alice":{"pubkey":1,"verified":false,"firstSeen":1}}',
      // `verifyPeer` renders this key as a fingerprint under a keystroke, so a
      // hand-edited one is refused here rather than thrown from the composer.
      "a record whose pubkey is not a key":
        '{"alice":{"pubkey":"nope","verified":false,"firstSeen":1}}',
    };

    for (const [description, contents] of Object.entries(corrupt)) {
      it(`refuses to start from ${description}`, () => {
        saveTrustRecords({}, terminoDir);
        writeFileSync(knownKeysPath(terminoDir), contents);

        expect(() => loadTrustRecords(terminoDir)).toThrow(TrustFileError);
      });
    }
  });
});
