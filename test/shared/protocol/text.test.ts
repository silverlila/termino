import { describe, expect, it } from "bun:test";
import {
  bodyProblem,
  MAX_BODY_BYTES,
  MAX_NICK_BYTES,
  nickProblem,
} from "../../../shared/protocol/text.ts";

/**
 * The rule that decides what may be rendered in somebody else's terminal.
 * Both directions read it, so a case here is a case about the sending path and
 * the receiving path at once.
 *
 * The hostile characters are written as `\uXXXX` escapes: they are the real
 * bytes at runtime, and written literally they would be invisible in every
 * editor and one careless copy/paste away from being lost.
 */

describe("a message body", () => {
  it("rejects a C0 control character", () => {
    // ESC, the first byte of every escape sequence there is.
    expect(bodyProblem("hi\u001B]52;c;cGF3bmVk\u0007")).toContain("U+001B");
    expect(bodyProblem("bell\u0007")).toContain("U+0007");
    expect(bodyProblem("null\u0000byte")).toContain("U+0000");
  });

  it("rejects a newline", () => {
    // Its own case, and not only because U+000A is a C0 control: a newline
    // forges a transcript line under somebody else's name, so a later
    // relaxation of the rule for multi-line messages has to fail here first.
    expect(bodyProblem("ok\n00:00 ?alice  forged line")).toContain("U+000A");
    expect(bodyProblem("ok\r\nforged")).not.toBeNull();
  });

  it("rejects DEL and C1", () => {
    expect(bodyProblem("del\u007F")).toContain("U+007F");
    // An 8-bit terminal reads U+009B as CSI — an escape sequence with no ESC.
    expect(bodyProblem("csi\u009B31m")).toContain("U+009B");
  });

  it("rejects U+2028 and U+2029", () => {
    expect(bodyProblem("line\u2028separator")).toContain("U+2028");
    expect(bodyProblem("paragraph\u2029separator")).toContain("U+2029");
  });

  it("rejects bidi overrides", () => {
    expect(bodyProblem("\u202Ereversed")).toContain("U+202E");
    expect(bodyProblem("\u202Aembedded")).toContain("U+202A");
    expect(bodyProblem("\u2066isolated")).toContain("U+2066");
    expect(bodyProblem("\u2069popped")).toContain("U+2069");
  });

  it("rejects a body over 1900 UTF-8 bytes", () => {
    expect(MAX_BODY_BYTES).toBe(1900);
    expect(bodyProblem("a".repeat(1900))).toBeNull();
    expect(bodyProblem("a".repeat(1901))).toContain("1901");

    // Counted in bytes, not characters: 950 of these is 1900 bytes, and one
    // more is over the limit while `String.length` still reads 951.
    expect(bodyProblem("é".repeat(950))).toBeNull();
    expect(bodyProblem("é".repeat(951))).not.toBeNull();
  });

  it("names the offending character without repeating it", () => {
    // The reason is shown on the screen this rule exists to protect, so it
    // must not carry the escape sequence it is reporting.
    expect(bodyProblem("hi\u001B[2J")).not.toContain("\u001B");
  });
});

describe("a nickname", () => {
  it("rejects a nick containing an ASCII space", () => {
    expect(nickProblem("al ice")).toContain("U+0020");
  });

  it("rejects a nick containing U+00A0", () => {
    // A no-break space renders exactly like a space, so "al ice" spelt with
    // one is a second nickname that reads as the first.
    expect(nickProblem("al\u00A0ice")).toContain("U+00A0");
  });

  it("rejects a nick containing U+200B", () => {
    // Zero width: "alice" and "ali<U+200B>ce" are indistinguishable on screen.
    expect(nickProblem("ali\u200Bce")).toContain("U+200B");
    expect(nickProblem("ali\uFEFFce")).toContain("U+FEFF");
    expect(nickProblem("ali\u2060ce")).toContain("U+2060");
  });

  it("rejects the same control characters a body does", () => {
    expect(nickProblem("bob\u001B[31m")).toContain("U+001B");
    expect(nickProblem("bob\u202E")).toContain("U+202E");
  });

  it("rejects a nick over 32 UTF-8 bytes", () => {
    expect(MAX_NICK_BYTES).toBe(32);
    expect(nickProblem("a".repeat(32))).toBeNull();
    expect(nickProblem("a".repeat(33))).toContain("33");
  });
});

describe("ordinary text", () => {
  it("accepts ordinary non-ASCII text", () => {
    // The case that stops the rule being "reject everything": people write in
    // more than ASCII, and the attack is control characters, not letters.
    expect(bodyProblem("déjà vu — shipping it now 🚀 ✅")).toBeNull();
    expect(bodyProblem("привет, ここは日本語です")).toBeNull();
    expect(nickProblem("zoë")).toBeNull();
    expect(nickProblem("鈴木")).toBeNull();
    expect(nickProblem("alice🚀")).toBeNull();
  });

  it("accepts an empty value, which is a separate question", () => {
    // Whether an empty body is worth sending is the composer's business; this
    // module only decides what is safe to render.
    expect(bodyProblem("")).toBeNull();
    expect(nickProblem("")).toBeNull();
  });
});
