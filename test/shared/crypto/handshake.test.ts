import { describe, expect, it } from "bun:test";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import {
  completeHandshake,
  type EphemeralKeys,
  HandshakeError,
  startHandshake,
} from "../../../shared/crypto/handshake.ts";
import { generatePsk } from "../../../shared/crypto/psk.ts";

const PSK = generatePsk();

/**
 * Two fixed keypairs and a fixed secret, with everything the handshake derives
 * from them recorded on first implementation and permanent from here. Editing
 * a label, the transcript ordering or the chain assignment changes these
 * values, and a client that changed any of them would talk to nobody while
 * appearing to work.
 *
 * The keypairs are written out rather than generated from a seed because
 * `check:no-v1` allows the `@noble/curves` module that exports X25519 to be
 * imported in exactly one file — the handshake itself — so a test cannot reach
 * the curve directly.
 * `lower` and `higher` name which of the two public keys sorts lower, which is
 * what decides the direction of each chain.
 */
const VECTOR = {
  psk: hexToBytes("00ff10a53c7b91e2048d6f3aab5c27de"),
  lower: keys(
    "2222222222222222222222222222222222222222222222222222222222222222",
    "0faa684ed28867b97f4a6a2dee5df8ce974e76b7018e3f22a1c4cf2678570f20",
  ),
  higher: keys(
    "1111111111111111111111111111111111111111111111111111111111111111",
    "7b4e909bbe7ffe44c465a220037d608ee35897d31ef972f07f74892cb0f73f13",
  ),
  root: "28c20fac1f73224ab1f11222a7f7388e7af7576c7756becccd918d08e4e33ba6",
  /** The lo→hi chain: what the lower key sends on and the higher key reads. */
  lowerToHigher: "6028bd4ce96cd06183b56ee4ade30752393a711d09aa9207b73f02d0637ba7ce",
  higherToLower: "115b512d45468f674be58f9a7b8486b3104baa60da1f80ba9973b1ca853e0aa2",
  sasWords: "cube fossil surf census crop width shade easel",
};

function keys(secretKey: string, publicKey: string): EphemeralKeys {
  return { secretKey: hexToBytes(secretKey), publicKey: hexToBytes(publicKey) };
}

describe("two parties holding the same pre-shared key", () => {
  it("agree on one root, on crossed chains, and on the same session words", () => {
    const alice = startHandshake();
    const bob = startHandshake();

    const hers = completeHandshake(PSK, alice, bob.publicKey);
    const his = completeHandshake(PSK, bob, alice.publicKey);

    expect(hers.root).toEqual(his.root);
    expect(hers.sendChain).toEqual(his.recvChain);
    expect(hers.recvChain).toEqual(his.sendChain);
    expect(hers.sasWords).toBe(his.sasWords);
  });

  it("agree on eight session words a person can read aloud", () => {
    const alice = startHandshake();
    const bob = startHandshake();

    const { sasWords } = completeHandshake(PSK, alice, bob.publicKey);

    expect(sasWords.split(" ")).toHaveLength(8);
    expect(sasWords).toMatch(/^[a-z]+( [a-z]+){7}$/);
  });

  it("sends and receives on different chains, so each direction has its own", () => {
    const alice = startHandshake();
    const bob = startHandshake();

    const hers = completeHandshake(PSK, alice, bob.publicKey);

    expect(hers.sendChain).not.toEqual(hers.recvChain);
  });

  it("derives an unrelated session the next time, on the very same secret", () => {
    // The whole point of the exchange: the secret two people carry does not
    // decide the keys, so a recording of one session is not opened by the
    // secret turning up later.
    const first = completeHandshake(PSK, startHandshake(), startHandshake().publicKey);
    const second = completeHandshake(PSK, startHandshake(), startHandshake().publicKey);

    expect(first.root).not.toEqual(second.root);
    expect(first.sasWords).not.toBe(second.sasWords);
  });

  it("agree that the lower public key sends on the lo→hi chain, by a known answer", () => {
    const fromLower = completeHandshake(VECTOR.psk, VECTOR.lower, VECTOR.higher.publicKey);
    const fromHigher = completeHandshake(VECTOR.psk, VECTOR.higher, VECTOR.lower.publicKey);

    expect(bytesToHex(fromLower.root)).toBe(VECTOR.root);
    expect(bytesToHex(fromLower.sendChain)).toBe(VECTOR.lowerToHigher);
    expect(bytesToHex(fromLower.recvChain)).toBe(VECTOR.higherToLower);
    expect(bytesToHex(fromHigher.sendChain)).toBe(VECTOR.higherToLower);
    expect(fromLower.sasWords).toBe(VECTOR.sasWords);
  });
});

describe("a session derived without the psk", () => {
  it("differs from the real one even for somebody who ran a valid exchange", () => {
    // Modelled generously: this attacker is handed one side's ephemeral secret
    // key, so their Diffie-Hellman output is the genuine one. Without the
    // pre-shared key that the derivation takes as its salt, they still land
    // somewhere else.
    const alice = startHandshake();
    const bob = startHandshake();

    const honest = completeHandshake(PSK, alice, bob.publicKey);
    const guessed = completeHandshake(generatePsk(), alice, bob.publicKey);

    expect(guessed.root).not.toEqual(honest.root);
    expect(guessed.sendChain).not.toEqual(honest.sendChain);
    expect(guessed.sasWords).not.toBe(honest.sasWords);
  });

  it("leaves a man in the middle with two sessions neither side can open", () => {
    const alice = startHandshake();
    const bob = startHandshake();
    const relay = startHandshake();
    const guess = generatePsk();

    // The relay answers each side with its own hello and runs two exchanges.
    const aliceWithRelay = completeHandshake(PSK, alice, relay.publicKey);
    const bobWithRelay = completeHandshake(PSK, bob, relay.publicKey);
    const relayWithAlice = completeHandshake(guess, relay, alice.publicKey);
    const relayWithBob = completeHandshake(guess, relay, bob.publicKey);

    // Each side's confirm arrives on a chain the relay does not hold, so it
    // fails to open and the session is refused rather than silently read.
    expect(relayWithAlice.recvChain).not.toEqual(aliceWithRelay.sendChain);
    expect(relayWithBob.recvChain).not.toEqual(bobWithRelay.sendChain);
    expect(aliceWithRelay.root).not.toEqual(bobWithRelay.root);
  });

  it("refuses a secret of the wrong length rather than deriving from it", () => {
    const alice = startHandshake();
    const bob = startHandshake();

    expect(() => completeHandshake(new Uint8Array(8), alice, bob.publicKey)).toThrow(
      HandshakeError,
    );
    expect(() => completeHandshake(new Uint8Array(8), alice, bob.publicKey)).toThrow(/16 bytes/);
  });
});

describe("a hostile hello", () => {
  it("rejects a hello reflected back at its sender", () => {
    // A relay that echoes a hello instead of forwarding the peer's would
    // otherwise have both sides derive a key from one keypair, agreeing
    // perfectly while talking to nobody.
    const alice = startHandshake();

    expect(() => completeHandshake(PSK, alice, alice.publicKey)).toThrow(HandshakeError);
    expect(() => completeHandshake(PSK, alice, alice.publicKey)).toThrow(/reflected/);
  });

  it("swapping the hello order does not change the derived root", () => {
    // The transcript sorts the two public keys before binding them in, so the
    // derivation does not depend on which hello arrived first — which is what
    // the relay controls. Reordering delivery gains an attacker nothing.
    const alice = startHandshake();
    const bob = startHandshake();

    const asDelivered = completeHandshake(PSK, alice, bob.publicKey);
    const reordered = completeHandshake(PSK, bob, alice.publicKey);

    expect(reordered.root).toEqual(asDelivered.root);
  });

  it("derives a different root when the hello came from a different peer", () => {
    const alice = startHandshake();
    const bob = startHandshake();
    const stranger = startHandshake();

    const withBob = completeHandshake(PSK, alice, bob.publicKey);
    const withStranger = completeHandshake(PSK, alice, stranger.publicKey);

    expect(withStranger.root).not.toEqual(withBob.root);
    expect(withStranger.sasWords).not.toBe(withBob.sasWords);
  });

  it("throws on a small-order public key instead of deriving an all-zero secret", () => {
    // A public key of every-byte-zero forces the exchange to output zeros, so
    // the attacker knows the shared secret. The curve refuses it, and that
    // throw is left to propagate: it is an attack, not a hiccup.
    const alice = startHandshake();

    expect(() => completeHandshake(PSK, alice, new Uint8Array(32))).toThrow();
  });

  it("rejects a public key of the wrong length", () => {
    const alice = startHandshake();

    expect(() => completeHandshake(PSK, alice, new Uint8Array(31))).toThrow(HandshakeError);
    expect(() => completeHandshake(PSK, alice, new Uint8Array(31))).toThrow(/32 bytes/);
  });
});
