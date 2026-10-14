import { describe, expect, it } from "bun:test";
import {
  fullBucket,
  MAX_SUBSCRIBERS_PER_HANDLE,
  RATE_LIMIT_MESSAGES,
  RATE_LIMIT_WINDOW_MS,
  takeToken,
} from "../../server/channel.ts";

/**
 * The limiter both relays share, on its own: every case is decidable from the numbers,
 * with no socket and no clock but the one passed in.
 */

describe("the numbers both relays enforce", () => {
  it("are two people per channel and five frames per ten seconds", () => {
    // Literals, not derived: these are the wire contract, and a change to either is a
    // change every deployed relay and client has to agree on.
    expect(MAX_SUBSCRIBERS_PER_HANDLE).toBe(2);
    expect(RATE_LIMIT_MESSAGES).toBe(5);
    expect(RATE_LIMIT_WINDOW_MS).toBe(10_000);
  });
});

describe("token bucket", () => {
  it("allows a full window's worth of messages", () => {
    let bucket = fullBucket(0);

    for (let sent = 0; sent < RATE_LIMIT_MESSAGES; sent++) {
      const result = takeToken(bucket, 0);
      expect(result.allowed).toBe(true);
      bucket = result.bucket;
    }

    expect(takeToken(bucket, 0).allowed).toBe(false);
  });

  it("refills over the window", () => {
    let bucket = fullBucket(0);
    for (let sent = 0; sent < RATE_LIMIT_MESSAGES; sent++) bucket = takeToken(bucket, 0).bucket;

    expect(takeToken(bucket, RATE_LIMIT_WINDOW_MS).allowed).toBe(true);
  });

  it("refills partially, part way through the window", () => {
    let bucket = fullBucket(0);
    for (let sent = 0; sent < RATE_LIMIT_MESSAGES; sent++) bucket = takeToken(bucket, 0).bucket;

    // One fifth of the window buys back exactly one message.
    expect(takeToken(bucket, RATE_LIMIT_WINDOW_MS / RATE_LIMIT_MESSAGES).allowed).toBe(true);
  });

  it("never accumulates more than a full bucket, however long the silence", () => {
    const rested = takeToken(fullBucket(0), RATE_LIMIT_WINDOW_MS * 1000).bucket;
    expect(rested.tokens).toBe(RATE_LIMIT_MESSAGES - 1);
  });

  it("does not refill if the clock goes backwards", () => {
    let bucket = fullBucket(1000);
    for (let sent = 0; sent < RATE_LIMIT_MESSAGES; sent++) bucket = takeToken(bucket, 1000).bucket;

    expect(takeToken(bucket, 0).allowed).toBe(false);
  });
});

