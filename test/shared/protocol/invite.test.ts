import { describe, expect, it } from "bun:test";
import { generatePsk, InvalidPskError, pskToWords } from "../../../shared/crypto/psk.ts";
import { formatInvite, InvalidInviteError, parseInvite } from "../../../shared/protocol/invite.ts";

const PSK = generatePsk();
const WORDS = pskToWords(PSK);
const RELAY = "wss://relay.example:8787/";

describe("an invite", () => {
  it("round-trips an invite", () => {
    expect(parseInvite(formatInvite(PSK, RELAY))).toEqual({ psk: PSK, relay: RELAY });
  });

  it("is the words, an @, and the relay host — nothing else", () => {
    expect(formatInvite(PSK, RELAY)).toBe(`${WORDS}@relay.example:8787`);
  });

  it("carries a relay with no port, and reads it back on the default", () => {
    expect(parseInvite(formatInvite(PSK, "wss://relay.example/")).relay).toBe(
      "wss://relay.example/",
    );
  });

  it("carries a bracketed IPv6 literal", () => {
    expect(parseInvite(formatInvite(PSK, "wss://[::1]:8787/"))).toEqual({
      psk: PSK,
      relay: "wss://[::1]:8787/",
    });
  });

  it("trims surrounding whitespace, which a copy-paste picks up", () => {
    expect(parseInvite(`  ${WORDS}@relay.example:8787\n`).relay).toBe(RELAY);
  });
});

describe("a malformed invite", () => {
  it("rejects the wrong number of words", () => {
    const short = WORDS.split("-").slice(0, 15).join("-");

    expect(() => parseInvite(`${short}@relay.example`)).toThrow(InvalidPskError);
    expect(() => parseInvite(`${short}@relay.example`)).toThrow(/found 15/);
  });

  it("rejects a word not in the list", () => {
    const mistyped = `${WORDS.split("-").slice(0, 15).join("-")}-brick@relay.example`;

    expect(() => parseInvite(mistyped)).toThrow(/brick/);
  });

  it("rejects a word run separated by spaces", () => {
    // The grammar joins the 16 words with hyphens. Spaces mean the token was
    // broken in transit, and a broken token must fail rather than resolve to
    // the same channel by a spelling nobody agreed on.
    const spaced = WORDS.replaceAll("-", " ");

    expect(() => parseInvite(`${spaced}@relay.example:8787`)).toThrow(InvalidPskError);
    expect(() => parseInvite(`${spaced}@relay.example:8787`)).toThrow(/hyphens/);
  });

  it("rejects a missing host", () => {
    expect(() => parseInvite(`${WORDS}@`)).toThrow(InvalidInviteError);
    expect(() => parseInvite(`${WORDS}@`)).toThrow(/host/);
    expect(() => parseInvite(WORDS)).toThrow(/host/);
  });

  it("rejects the command a person types in front of the token", () => {
    // `termino join ` is the command, not part of the invite: accepting it
    // would make the token two different strings depending on where it came
    // from, and only one of them would survive being pasted somewhere else.
    expect(() => parseInvite(`termino join ${WORDS}@relay.example`)).toThrow(InvalidPskError);
  });

  it("rejects anything after the host, so a path cannot hide the real host", () => {
    expect(() => parseInvite(`${WORDS}@evil.example/relay.example`)).toThrow(InvalidInviteError);
    expect(() => parseInvite(`${WORDS}@user@relay.example`)).toThrow(InvalidInviteError);
  });
});
