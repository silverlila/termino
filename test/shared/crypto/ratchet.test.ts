import { describe, expect, it } from "bun:test";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import {
  MAX_SKIP,
  type MessageKey,
  nextKey,
  RatchetError,
  startReceiving,
} from "../../../shared/crypto/ratchet.ts";

const ZEROED_CHAIN = new Uint8Array(32);

/**
 * One fixed chain key and the first three messages it produces, recorded on
 * first implementation and permanent from here. Editing either label, the
 * order of the key and the nonce inside the derived material, or their
 * lengths changes these values — and two clients disagreeing about any of it
 * would fail to open a single message while every test that only checks
 * self-consistency stayed green.
 */
const VECTOR = {
  chain: "d6c4b2a0918273645546372819a0b1c2d3e4f5061728394a5b6c7d8e9fa0b1c2",
  messages: [
    {
      key: "3367250715da287cdf33d98057ad2a02dbf8ce137cea95cdff2e06a14bb00480",
      nonce: "d85cbf5057f3f550e55b20fa",
    },
    {
      key: "f19f3156ceb9f59c7e5bc95ed96bbff2d2d7ac31fa02d7a39b02470e847a17b2",
      nonce: "3e550887b28a98974daca4e7",
    },
    {
      key: "417d7a27ee1606425663ce1710be4932faf8f3cda4bc75e36a0c7e1e2b0eec96",
      nonce: "2955c149d6e23c74f1ebfe9e",
    },
  ],
};

/** The sending side of a chain: the keys a peer would produce, in order. */
function send(chain: Uint8Array, count: number): MessageKey[] {
  const sent: MessageKey[] = [];
  let current = chain;

  for (let counter = 0; counter < count; counter += 1) {
    const { key, nonce, chain: following } = nextKey(current);
    sent.push({ key, nonce });
    current = following;
  }

  return sent;
}

function chainOf(fill: number): Uint8Array {
  return new Uint8Array(32).fill(fill);
}

describe("a chain key", () => {
  it("derives a distinct key and nonce per message", () => {
    const sent = send(chainOf(9), 3);

    expect(sent[0]?.key).toHaveLength(32);
    expect(sent[0]?.nonce).toHaveLength(12);
    expect(sent[0]?.key).not.toEqual(sent[1]?.key);
    expect(sent[1]?.key).not.toEqual(sent[2]?.key);
    expect(sent[0]?.nonce).not.toEqual(sent[1]?.nonce);
    expect(sent[1]?.nonce).not.toEqual(sent[2]?.nonce);
  });

  it("derives a key that is not the chain it came from", () => {
    const chain = chainOf(9);

    const first = nextKey(chain);

    expect(first.key).not.toEqual(first.chain);
    expect(first.chain).not.toEqual(chainOf(9));
  });

  it("advancing the chain does not expose the previous key", () => {
    // sha256 cannot be inverted, so the one-way property is not something a
    // test can attempt directly. What is observable is that the ratchet leaves
    // nothing to invert: the chain the caller handed in reads as zeros
    // afterwards, and the module exports no operation taking a chain
    // backwards.
    const chain = chainOf(9);

    const first = nextKey(chain);
    const second = nextKey(first.chain);

    expect(chain).toEqual(ZEROED_CHAIN);
    expect(first.chain).toEqual(ZEROED_CHAIN);
    expect(second.key).not.toEqual(first.key);
  });

  it("pins the key schedule with a known answer", () => {
    const sent = send(hexToBytes(VECTOR.chain), VECTOR.messages.length);

    expect(sent.map((message) => bytesToHex(message.key))).toEqual(
      VECTOR.messages.map((message) => message.key),
    );
    expect(sent.map((message) => bytesToHex(message.nonce))).toEqual(
      VECTOR.messages.map((message) => message.nonce),
    );
  });

  it("refuses a chain key of the wrong length rather than deriving from it", () => {
    expect(() => nextKey(new Uint8Array(16))).toThrow(RatchetError);
    expect(() => nextKey(new Uint8Array(16))).toThrow(/32 bytes/);
  });
});

describe("a receiver handed messages out of order", () => {
  it("opens messages arriving 0, 2, 1", () => {
    // "Opens" is exactly this: the receiver reaches the same key and nonce the
    // sender used for that counter, whatever order the relay delivered them
    // in, and 1 arriving after 2 leaves the chain fit to carry on.
    const sent = send(chainOf(4), 4);
    const receiver = startReceiving(chainOf(4));

    expect(receiver.take(0)).toEqual(sent[0] as MessageKey);
    expect(receiver.take(2)).toEqual(sent[2] as MessageKey);
    expect(receiver.take(1)).toEqual(sent[1] as MessageKey);
    expect(receiver.take(3)).toEqual(sent[3] as MessageKey);
  });

  it("reports a gap that is still open, and forgets one that fills", () => {
    const receiver = startReceiving(chainOf(4));

    receiver.take(0);
    receiver.take(3);

    expect(receiver.skipped()).toEqual([1, 2]);

    receiver.take(1);

    expect(receiver.skipped()).toEqual([2]);
  });

  it("accepts a counter exactly MAX_SKIP ahead", () => {
    const sent = send(chainOf(4), MAX_SKIP + 1);
    const receiver = startReceiving(chainOf(4));

    expect(receiver.take(MAX_SKIP)).toEqual(sent[MAX_SKIP] as MessageKey);
    expect(receiver.skipped()).toHaveLength(MAX_SKIP);
    expect(receiver.take(0)).toEqual(sent[0] as MessageKey);
  });

  it("refuses a counter MAX_SKIP + 1 ahead", () => {
    // Otherwise a peer sending counter 2³¹ has the receiver derive two billion
    // keys on its behalf.
    const receiver = startReceiving(chainOf(4));

    expect(() => receiver.take(MAX_SKIP + 1)).toThrow(RatchetError);
    expect(() => receiver.take(2 ** 31)).toThrow(/more than 256 ahead/);
    expect(receiver.skipped()).toEqual([]);
  });

  it("refuses a counter already delivered", () => {
    // A per-message key used exactly once is what makes replay structurally
    // impossible: the second copy finds no key left.
    const receiver = startReceiving(chainOf(4));

    receiver.take(0);
    receiver.take(2);

    expect(() => receiver.take(0)).toThrow(/already been delivered/);
    expect(() => receiver.take(2)).toThrow(/already been delivered/);

    receiver.take(1);

    expect(() => receiver.take(1)).toThrow(RatchetError);
  });

  it("refuses a counter that is not a whole number", () => {
    const receiver = startReceiving(chainOf(4));

    expect(() => receiver.take(-1)).toThrow(RatchetError);
    expect(() => receiver.take(1.5)).toThrow(/whole number/);
  });

  it("drops the lowest entry when the skip cache is full", () => {
    // The jump bound alone does not bound the cache: a peer sending 256, 512,
    // 768… stays inside it on every single jump and accumulates keys forever.
    const receiver = startReceiving(chainOf(4));

    receiver.take(MAX_SKIP);
    receiver.take(MAX_SKIP * 2 + 1);

    expect(receiver.skipped()).toHaveLength(MAX_SKIP);
    expect(receiver.skipped()[0]).toBe(MAX_SKIP + 1);
    expect(() => receiver.take(0)).toThrow(RatchetError);
    expect(() => receiver.take(MAX_SKIP - 1)).toThrow(RatchetError);
  });
});

describe("a receiver being torn down", () => {
  it("wipes the chain it was handed", () => {
    const chain = chainOf(4);
    const receiver = startReceiving(chain);

    receiver.wipe();

    expect(chain).toEqual(ZEROED_CHAIN);
  });

  it("drops every cached key", () => {
    // The cached keys are not reachable from out here — that is the point of
    // the cache being private — so what a caller can observe is that no gap,
    // and therefore no key held open for one, survives the wipe.
    const receiver = startReceiving(chainOf(4));

    receiver.take(2);
    receiver.wipe();

    expect(receiver.skipped()).toEqual([]);
  });

  it("refuses to derive anything after it has been wiped", () => {
    const receiver = startReceiving(chainOf(4));

    receiver.wipe();

    expect(() => receiver.take(0)).toThrow(/wiped/);
  });
});
