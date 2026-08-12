import { describe, expect, it } from "bun:test";
import { COMMANDS, parseComposerInput, VERIFY_USAGE } from "../../src/tui/commands.ts";

/**
 * The composer's grammar on its own, with no screen and no session: every
 * case here is decidable from the string alone, which is the point of keeping
 * parsing separate from acting.
 */

describe("an ordinary line", () => {
  it("is a message", () => {
    expect(parseComposerInput("shipping it now")).toEqual({
      kind: "message",
      body: "shipping it now",
    });
  });

  it("keeps a slash that is not the first character", () => {
    expect(parseComposerInput("and/or tomorrow")).toEqual({
      kind: "message",
      body: "and/or tomorrow",
    });
  });
});

describe("/exit", () => {
  it("asks to leave", () => {
    expect(parseComposerInput("/exit")).toEqual({ kind: "exit" });
  });

  it("still asks to leave when typed with trailing space", () => {
    expect(parseComposerInput("  /exit  ")).toEqual({ kind: "exit" });
  });
});

describe("/help", () => {
  it("asks for the command list", () => {
    expect(parseComposerInput("/help")).toEqual({ kind: "help" });
  });

  it("lists only commands the parser recognises, so the two cannot drift apart", () => {
    for (const command of COMMANDS) {
      const [name = ""] = command.usage.split(" ");
      const input = parseComposerInput(name);

      // Typed bare, a command may still complain that it wants arguments.
      // What it must never do is deny knowing its own name.
      if (input.kind === "unusable") expect(input.reason).not.toContain("unknown command");
    }
  });
});

describe("/verify", () => {
  it("takes the whole remainder of the line as the fingerprint", () => {
    expect(parseComposerInput("/verify bob soul gospel lunar risk")).toEqual({
      kind: "verify",
      nick: "bob",
      fingerprint: "soul gospel lunar risk",
    });
  });

  it("is unusable with no fingerprint", () => {
    expect(parseComposerInput("/verify bob")).toEqual({ kind: "unusable", reason: VERIFY_USAGE });
  });

  it("is unusable with nothing at all", () => {
    expect(parseComposerInput("/verify")).toEqual({ kind: "unusable", reason: VERIFY_USAGE });
  });
});

describe("anything else beginning with a slash", () => {
  it("is unusable, and points at /help rather than guessing", () => {
    const input = parseComposerInput("/frobnicate the widget");

    expect(input.kind).toBe("unusable");
    if (input.kind !== "unusable") throw new Error("unreachable");
    expect(input.reason).toContain("/frobnicate");
    expect(input.reason).toContain("/help");
  });
});
