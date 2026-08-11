import { describe, expect, test } from "bun:test";
import { bytesToHex } from "@noble/hashes/utils.js";
import { deriveChannelKeys } from "../../src/crypto/derive.ts";

/**
 * Known-answer vector, recorded on first implementation against the argon2id
 * parameters and HKDF labels frozen in the spec.
 *
 * Its job is drift detection, not independent verification: it fails the moment
 * anybody edits `ARGON2ID`, a label, or an output length. That failure is the
 * point — such a change is invisible at runtime and silently partitions users
 * onto mutually unreachable channels. If this test fails, the correct response
 * is almost always to revert the change, not to re-record the vector.
 */
const VECTOR = {
  channelName: "termino-test-vector",
  password: "correct horse battery staple",
  handle: "746e1a11a6f8e7871db14ff84ab08a03",
  msgKey: "a5f15c2daa6ff08b2ec286cc0476841ff43b38f4aaa1c0ec0ab6936b5aa7f753",
};

// Each derivation costs ~900 ms, so they are computed once at module scope and
// shared across assertions rather than re-derived per test.
const base = deriveChannelKeys(VECTOR.channelName, VECTOR.password);
const baseAgain = deriveChannelKeys(VECTOR.channelName, VECTOR.password);
const otherPassword = deriveChannelKeys(VECTOR.channelName, "a different password");
const otherChannel = deriveChannelKeys("a-different-channel", VECTOR.password);

describe("deriveChannelKeys", () => {
  test("produces the recorded known-answer handle and message key", () => {
    expect(base.handle).toBe(VECTOR.handle);
    expect(bytesToHex(base.msgKey)).toBe(VECTOR.msgKey);
  });

  test("is deterministic: two independent calls agree byte for byte", () => {
    expect(baseAgain.handle).toBe(base.handle);
    expect(bytesToHex(baseAgain.msgKey)).toBe(bytesToHex(base.msgKey));
  });

  test("changing only the password changes both the handle and the message key", () => {
    expect(otherPassword.handle).not.toBe(base.handle);
    expect(bytesToHex(otherPassword.msgKey)).not.toBe(bytesToHex(base.msgKey));
  });

  test("changing only the channel name changes both the handle and the message key", () => {
    expect(otherChannel.handle).not.toBe(base.handle);
    expect(bytesToHex(otherChannel.msgKey)).not.toBe(bytesToHex(base.msgKey));
  });

  test("the handle is 32 lowercase hex characters, as the relay requires", () => {
    expect(base.handle).toMatch(/^[0-9a-f]{32}$/);
  });

  test("the message key is 32 bytes, sized for AES-256-GCM", () => {
    expect(base.msgKey).toHaveLength(32);
  });

  test("the handle and the message key are independent values", () => {
    expect(bytesToHex(base.msgKey)).not.toContain(base.handle);
  });
});
