import { describe, expect, it } from "bun:test";
import { admit, FRESHNESS_WINDOW_MS, type SeenMessages } from "../src/replay.ts";

/**
 * Replay protection as arithmetic: a signature already delivered, and a
 * timestamp outside the window either side of now. No socket, no clock.
 */

const SIGNATURE = "c2lnbmF0dXJlIG9uZQ==";
const OTHER_SIGNATURE = "c2lnbmF0dXJlIHR3bw==";

/** A fixed instant, so every expectation below is a literal offset from it. */
const NOW = 1786531200000;

const nothingSeen = (): SeenMessages => new Map();

describe("admitting a message that has not been seen", () => {
  it("reports it fresh", () => {
    expect(admit(nothingSeen(), SIGNATURE, NOW, NOW).freshness).toBe("fresh");
  });

  it("remembers it, so the same signature cannot arrive twice", () => {
    const first = admit(nothingSeen(), SIGNATURE, NOW, NOW);

    expect(admit(first.seen, SIGNATURE, NOW, NOW).freshness).toBe("replayed");
  });

  it("still remembers it after other messages have gone by", () => {
    const first = admit(nothingSeen(), SIGNATURE, NOW, NOW);
    const second = admit(first.seen, OTHER_SIGNATURE, NOW + 1000, NOW + 1000);

    expect(admit(second.seen, SIGNATURE, NOW, NOW + 2000).freshness).toBe("replayed");
  });

  it("treats a different signature as a different message", () => {
    const first = admit(nothingSeen(), SIGNATURE, NOW, NOW);

    expect(admit(first.seen, OTHER_SIGNATURE, NOW, NOW).freshness).toBe("fresh");
  });

  it("leaves the set it was given alone", () => {
    const seen = nothingSeen();

    admit(seen, SIGNATURE, NOW, NOW);

    expect(seen.size).toBe(0);
  });
});

describe("a message dated outside the window", () => {
  it("reports one older than the window as stale", () => {
    const sentAt = NOW - FRESHNESS_WINDOW_MS - 1;

    expect(admit(nothingSeen(), SIGNATURE, sentAt, NOW).freshness).toBe("stale");
  });

  it("reports one dated further ahead than the window as stale", () => {
    const sentAt = NOW + FRESHNESS_WINDOW_MS + 1;

    expect(admit(nothingSeen(), SIGNATURE, sentAt, NOW).freshness).toBe("stale");
  });

  it("admits one exactly at the edge of the window", () => {
    const sentAt = NOW - FRESHNESS_WINDOW_MS;

    expect(admit(nothingSeen(), SIGNATURE, sentAt, NOW).freshness).toBe("fresh");
  });

  it("does not remember it, so a stale message costs nothing to reject", () => {
    const sentAt = NOW - FRESHNESS_WINDOW_MS - 1;
    const seen = nothingSeen();

    expect(admit(seen, SIGNATURE, sentAt, NOW).seen).toBe(seen);
  });
});

describe("what the set carries over time", () => {
  it("forgets a signature once its timestamp has aged out of the window", () => {
    const first = admit(nothingSeen(), SIGNATURE, NOW, NOW);
    const muchLater = NOW + 2 * FRESHNESS_WINDOW_MS;

    const second = admit(first.seen, OTHER_SIGNATURE, muchLater, muchLater);

    // Safe to forget: a second copy of that message would now be refused as
    // stale, which is what the window is for.
    expect(second.seen.has(SIGNATURE)).toBe(false);
    expect(second.seen.has(OTHER_SIGNATURE)).toBe(true);
  });

  it("hands back the same set when it rejects a repeat", () => {
    const first = admit(nothingSeen(), SIGNATURE, NOW, NOW);

    expect(admit(first.seen, SIGNATURE, NOW, NOW).seen).toBe(first.seen);
  });
});
