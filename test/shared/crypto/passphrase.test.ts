import { describe, expect, it } from "bun:test";
import { bytesToHex, concatBytes } from "@noble/hashes/utils.js";
import { calculateGenerator, CPaceError } from "../../../shared/crypto/cpace.ts";
import { HandshakeError } from "../../../shared/crypto/handshake.ts";
import {
  deriveRoomHandle,
  normalizeRoom,
  passphraseExchange,
  passphraseGenerator,
  PASSPHRASE_CHANNEL_LABEL,
  PASSPHRASE_SESSION_LABEL,
  ROOM_HANDLE_LABEL,
} from "../../../shared/crypto/passphrase.ts";
import { deriveHandle } from "../../../shared/crypto/psk.ts";

const ROOM = "silver-and-ana";
const PHRASE = "the blue house on the corner";

function meet(a: ReturnType<typeof passphraseExchange>, b: ReturnType<typeof passphraseExchange>) {
  return [
    a.complete(b.publicKey, b.associatedData),
    b.complete(a.publicKey, a.associatedData),
  ] as const;
}

describe("two people with the same room and phrase", () => {
  it("agree on session words and on each other's chains", () => {
    const [alice, bob] = meet(passphraseExchange(ROOM, PHRASE), passphraseExchange(ROOM, PHRASE));

    expect(alice.sasWords).toBe(bob.sasWords);
    expect(bytesToHex(alice.sendChain)).toBe(bytesToHex(bob.recvChain));
    expect(bytesToHex(alice.recvChain)).toBe(bytesToHex(bob.sendChain));
  });

  it("agree however differently they typed the room, and get the same address", () => {
    const [alice, bob] = meet(
      passphraseExchange("  Silver-And-Ana ", PHRASE),
      passphraseExchange("silver-and-ana", PHRASE),
    );

    expect(alice.sasWords).toBe(bob.sasWords);
    expect(deriveRoomHandle("  Silver-And-Ana ")).toBe(deriveRoomHandle("silver-and-ana"));
  });

  it("get a fresh session every time, so nothing recorded from one opens the next", () => {
    const [first] = meet(passphraseExchange(ROOM, PHRASE), passphraseExchange(ROOM, PHRASE));
    const [second] = meet(passphraseExchange(ROOM, PHRASE), passphraseExchange(ROOM, PHRASE));

    expect(first.sasWords).not.toBe(second.sasWords);
    expect(bytesToHex(first.sendChain)).not.toBe(bytesToHex(second.sendChain));
  });
});

describe("the same phrase", () => {
  it("in two different rooms meets nobody: the room is part of what the phrase picks", () => {
    const [alice, bob] = meet(passphraseExchange("one room", PHRASE), passphraseExchange("another room", PHRASE));

    expect(alice.sasWords).not.toBe(bob.sasWords);
  });

  it("agrees however its accents were composed, and with spaces around it", () => {
    const [alice, bob] = meet(
      passphraseExchange(ROOM, "caf\u00e9 au lait"),
      passphraseExchange(ROOM, "  cafe\u0301 au lait "),
    );

    expect(alice.sasWords).toBe(bob.sasWords);
  });
});

describe("a different phrase", () => {
  it("produces keys that do not match, rather than an error either side could test", () => {
    const [alice, mallory] = meet(
      passphraseExchange(ROOM, PHRASE),
      passphraseExchange(ROOM, "the blue house on the corneR"),
    );

    expect(alice.sasWords).not.toBe(mallory.sasWords);
    expect(bytesToHex(alice.sendChain)).not.toBe(bytesToHex(mallory.recvChain));
  });

  it("is not changed in case, unlike the room", () => {
    const [alice, bob] = meet(
      passphraseExchange(ROOM, PHRASE),
      passphraseExchange(ROOM, PHRASE.toUpperCase()),
    );

    expect(alice.sasWords).not.toBe(bob.sasWords);
  });
});

describe("the wire contract", () => {
  it("pins the three passphrase labels, each distinct from invite mode's", () => {
    expect(ROOM_HANDLE_LABEL).toBe("termino/room/v2");
    expect(PASSPHRASE_CHANNEL_LABEL).toBe("termino/passphrase/v2");
    expect(PASSPHRASE_SESSION_LABEL).toBe("termino/session/passphrase/v2");
  });

  it("gives a room the address HKDF gives it, checked with node:crypto rather than @noble", () => {
    expect(deriveRoomHandle(ROOM)).toBe("8dd075f2904541a30d8406768e385bcf");
  });

  it("builds the generator from the phrase and a channel identifier of label then room", () => {
    const channelIdentifier = concatBytes(
      Uint8Array.of(21),
      new TextEncoder().encode("termino/passphrase/v2"),
      Uint8Array.of(14),
      new TextEncoder().encode("silver-and-ana"),
    );
    const expected = calculateGenerator(new TextEncoder().encode(PHRASE), channelIdentifier, new Uint8Array());

    expect(bytesToHex(passphraseGenerator(ROOM, PHRASE))).toBe(bytesToHex(expected.toBytes()));
    expect(bytesToHex(passphraseGenerator(ROOM, PHRASE))).toBe(
      "c46cbae8a8b6f07764f604c635eb9a30c15ce6daa2fc20d5e0df3b688bbdc711",
    );
  });
});

describe("the room's address", () => {
  it("does not depend on the phrase, so the relay sees nothing derived from it", () => {
    expect(deriveRoomHandle(ROOM)).toMatch(/^[0-9a-f]{32}$/);
    expect(normalizeRoom(" Ünïcode ROOM ")).toBe("ünïcode room");
  });

  it("is never an invite's address, even built from the same bytes", () => {
    const room = "sixteen-char-rm!";
    expect(deriveRoomHandle(room)).not.toBe(deriveHandle(new TextEncoder().encode(room)));
  });

  it("is the same however the room's spaces, case and Greek final sigma were typed", () => {
    expect(deriveRoomHandle("my  room")).toBe(deriveRoomHandle("my room"));
    expect(deriveRoomHandle("ΑΣ")).toBe(deriveRoomHandle("Ασ"));
    expect(deriveRoomHandle("caf\u00e9")).toBe(deriveRoomHandle("cafe\u0301"));
  });

  it("is different for different rooms", () => {
    expect(deriveRoomHandle("one room")).not.toBe(deriveRoomHandle("another room"));
  });
});

describe("associated data", () => {
  it("is sixteen fresh random bytes on every exchange, as the draft requires of both sides", () => {
    const one = passphraseExchange(ROOM, PHRASE);
    const other = passphraseExchange(ROOM, PHRASE);

    expect(one.associatedData).toHaveLength(16);
    expect(bytesToHex(one.associatedData ?? new Uint8Array())).not.toBe(
      bytesToHex(other.associatedData ?? new Uint8Array()),
    );
  });
});

describe("a hello that must be refused", () => {
  it("refuses our own share sent back to us", () => {
    const alice = passphraseExchange(ROOM, PHRASE);

    expect(() => alice.complete(alice.publicKey, alice.associatedData)).toThrow(/reflected/);
  });

  it("refuses a hello without associated data, as an invite's hello would be", () => {
    const alice = passphraseExchange(ROOM, PHRASE);
    const bob = passphraseExchange(ROOM, PHRASE);

    expect(() => alice.complete(bob.publicKey, null)).toThrow(HandshakeError);
  });

  it("refuses associated data of the wrong size", () => {
    const alice = passphraseExchange(ROOM, PHRASE);
    const bob = passphraseExchange(ROOM, PHRASE);

    expect(() => alice.complete(bob.publicKey, new Uint8Array(8))).toThrow(HandshakeError);
  });

  it("refuses a share that is not a point, and the identity", () => {
    const alice = passphraseExchange(ROOM, PHRASE);
    const associatedData = new Uint8Array(16);

    expect(() => alice.complete(new Uint8Array(32).fill(0xff), associatedData)).toThrow(CPaceError);
    expect(() => alice.complete(new Uint8Array(32), associatedData)).toThrow(/identity/);
  });
});
