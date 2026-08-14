import { afterEach, describe, expect, it } from "bun:test";
import { generatePsk } from "../shared/crypto/psk.ts";
import { formatInvite, parseInvite } from "../shared/protocol/invite.ts";
import {
  checkPromptedNick,
  inviteRelayUrl,
  loadRenderer,
  parseArgs,
  SCROLLBACK_WARNING,
  UsageError,
  type JoinCommand,
  type NewCommand,
} from "../src/main.ts";

/**
 * The CLI, at the seams a test can reach. `runNew`, `runJoin` and `main` are
 * not among them: they prompt on stdin and end in a renderer that hangs
 * without a TTY.
 */

const originalDev = process.env.DEV;

afterEach(() => {
  if (originalDev === undefined) delete process.env.DEV;
  else process.env.DEV = originalDev;
});

describe("devtools", () => {
  it("clears DEV before importing the renderer", async () => {
    // `@opentui/react` reads this as it evaluates, and on `true` it connects
    // React devtools to a local WebSocket — which serialises the element tree
    // with its props. Nothing secret is a prop any more, and the flag is
    // cleared as well: one forgotten path should not be enough to leak a key.
    process.env.DEV = "true";

    await loadRenderer();

    expect(process.env.DEV).toBeUndefined();
  });
});

function asNew(argv: string[]): NewCommand {
  const command = parseArgs(argv);
  if (command.mode !== "new") throw new Error(`expected new, got: ${command.mode}`);
  return command;
}

function asJoin(argv: string[]): JoinCommand {
  const command = parseArgs(argv);
  if (command.mode !== "join") throw new Error(`expected join, got: ${command.mode}`);
  return command;
}

describe("the subcommands", () => {
  it("takes new with a relay", () => {
    expect(asNew(["new", "--relay", "wss://relay.example:8787"])).toEqual({
      mode: "new",
      nick: undefined,
      relay: "wss://relay.example:8787",
    });
  });

  it("requires --relay on new, naming the flag", () => {
    // No silent default: a localhost one would mint invites that work on one
    // machine and fail as silence everywhere else.
    expect(() => parseArgs(["new"])).toThrow(UsageError);
    expect(() => parseArgs(["new"])).toThrow(/--relay/);
  });

  it("takes join with an invite, and no relay flag", () => {
    expect(asJoin(["join", "acorn-yoga@relay.example"])).toEqual({
      mode: "join",
      nick: undefined,
      invite: "acorn-yoga@relay.example",
    });

    // The relay comes from the invite. Accepting a flag as well would give two
    // answers to one question.
    expect(() => parseArgs(["join", "acorn@relay.example", "--relay", "wss://elsewhere"])).toThrow(
      /unknown option: --relay/,
    );
  });

  it("requires an invite on join", () => {
    expect(() => parseArgs(["join"])).toThrow(UsageError);
    expect(() => parseArgs(["join", "--nick", "alice"])).toThrow(/requires an invite/);
  });

  it("rejects --channel as an unknown flag rather than ignoring it", () => {
    // It is gone: the handle is derived from the secret alone, so a channel
    // name would be a second thing to agree out of band that buys nothing.
    expect(() => parseArgs(["new", "--relay", "wss://relay.example", "--channel", "demo"])).toThrow(
      /unknown option: --channel/,
    );
    expect(() => parseArgs(["join", "acorn@relay.example", "--channel", "demo"])).toThrow(
      /unknown option: --channel/,
    );
  });

  it("rejects anything that is not one of the three subcommands", () => {
    expect(() => parseArgs(["chat"])).toThrow(/expected new, join or serve/);
    expect(() => parseArgs([])).toThrow(/expected new, join or serve/);
  });

  it("serves on a port", () => {
    expect(parseArgs(["serve", "--port", "9001"])).toEqual({ mode: "serve", port: 9001 });
  });

  it("answers --help before anything else", () => {
    expect(parseArgs(["--help"])).toEqual({ mode: "help" });
    expect(parseArgs(["new", "--help"])).toEqual({ mode: "help" });
  });
});

describe("the invite an invite-shaped argument has to be", () => {
  it("is what `new` prints and `join` reads", () => {
    // The two halves of the CLI meet here: whatever `new` puts on stdout has
    // to be a token `parseInvite` accepts, or the pair of commands does not
    // make a conversation.
    const relay = asNew(["new", "--relay", "wss://relay.example:8787"]).relay;
    const invite = formatInvite(generatePsk(), relay);

    expect(parseInvite(invite).relay).toBe("wss://relay.example:8787/");
    expect(asJoin(["join", invite]).invite).toBe(invite);
  });
});

describe("the relay an invite is dialled on", () => {
  it("dials a remote host over wss", () => {
    // The token carries no scheme, so this is the only safe reading of one.
    expect(inviteRelayUrl("wss://relay.example:8787/")).toBe("wss://relay.example:8787/");
  });

  it("dials a loopback host over ws, which is the only thing there is to dial", () => {
    // Nothing issues a certificate for localhost, so reading a loopback invite
    // as wss:// would make `new --relay ws://localhost:8787` mint an invite
    // that cannot be redeemed on the machine that minted it.
    expect(inviteRelayUrl("wss://localhost:8787/")).toBe("ws://localhost:8787/");
    expect(inviteRelayUrl("wss://127.0.0.1:8787/")).toBe("ws://127.0.0.1:8787/");
    expect(inviteRelayUrl("wss://[::1]:8787/")).toBe("ws://[::1]:8787/");
  });

  it("is what `new` and `join` agree on for a localhost relay", () => {
    // The whole loop, which is the one a person runs first: a relay on
    // localhost, an invite minted against it, and the URL the far side dials.
    const relay = asNew(["new", "--relay", "ws://localhost:8787"]).relay;
    const invite = formatInvite(generatePsk(), relay);

    expect(inviteRelayUrl(parseInvite(invite).relay)).toBe("ws://localhost:8787/");
  });
});

describe("relay url", () => {
  const relayOf = (argv: string[]) => asNew(["new", ...argv]).relay;

  it("a bare host gains wss://", () => {
    expect(relayOf(["--relay", "relay.example.com:8787"])).toBe("wss://relay.example.com:8787");
  });

  it("accepts wss:// to any host", () => {
    expect(relayOf(["--relay", "wss://relay.example.com"])).toBe("wss://relay.example.com");
  });

  it("accepts ws:// to localhost, 127.0.0.1 and [::1]", () => {
    // The development path: there is no network between the two ends for
    // anyone to sit on.
    expect(relayOf(["--relay", "ws://localhost:8787"])).toBe("ws://localhost:8787");
    expect(relayOf(["--relay", "ws://127.0.0.1:8787"])).toBe("ws://127.0.0.1:8787");
    expect(relayOf(["--relay", "ws://[::1]:8787"])).toBe("ws://[::1]:8787");
  });

  it("refuses ws:// to a remote host, naming --insecure", () => {
    expect(() => relayOf(["--relay", "ws://relay.example.com:8787"])).toThrow(UsageError);
    expect(() => relayOf(["--relay", "ws://relay.example.com:8787"])).toThrow(/--insecure/);
  });

  it("accepts a remote ws:// under --insecure", () => {
    expect(relayOf(["--relay", "ws://relay.example.com:8787", "--insecure"])).toBe(
      "ws://relay.example.com:8787",
    );
    expect(relayOf(["--insecure", "--relay", "ws://relay.example.com:8787"])).toBe(
      "ws://relay.example.com:8787",
    );
  });

  it("refuses a scheme that is not ws or wss", () => {
    // Nothing is silently rewritten: a pasted http:// URL fails here, where the
    // message can say what is wrong, rather than as a connection that never
    // opens behind a full-screen interface.
    expect(() => relayOf(["--relay", "http://relay.example"])).toThrow(UsageError);
    expect(() => relayOf(["--relay", "http://relay.example"])).toThrow(/ws:\/\/ or wss:\/\//);
    expect(() => relayOf(["--relay", "https://relay.example"])).toThrow(UsageError);
  });
});

/**
 * `runNew` cannot be called in-process: it ends in a renderer that takes over
 * the terminal and never returns. Which stream each half of it goes to is the
 * whole point of requirement 18, and that is only observable from outside, so
 * this drives the real command and reads the two streams apart.
 */
describe("what `new` prints", () => {
  const MAIN = new URL("../src/main.ts", import.meta.url).pathname;

  async function firstLineOf(stream: ReadableStream<Uint8Array>): Promise<string> {
    const reader = stream.getReader();
    const decoder = new TextDecoder();
    let buffered = "";

    try {
      while (true) {
        const { value, done } = await reader.read();
        if (done) throw new Error(`the stream ended before a line: ${buffered}`);

        buffered += decoder.decode(value, { stream: true });
        const newline = buffered.indexOf("\n");
        if (newline >= 0) return buffered.slice(0, newline);
      }
    } finally {
      reader.releaseLock();
    }
  }

  it("puts the invite on stdout and the scrollback warning on stderr", async () => {
    // A relay that is not there: the invite is minted and printed before
    // anything is dialled, and nothing here is about connecting.
    const child = Bun.spawn(
      [process.execPath, "run", MAIN, "new", "--relay", "ws://localhost:1", "--nick", "alice"],
      { stdout: "pipe", stderr: "pipe", stdin: "ignore" },
    );

    try {
      const [invite, warning] = await Promise.all([
        firstLineOf(child.stdout),
        firstLineOf(child.stderr),
      ]);

      // Piped and pasted, the invite has to arrive on its own: a warning mixed
      // into stdout would travel with the thing it warns about.
      expect(parseInvite(invite).relay).toBe("wss://localhost:1/");
      expect(warning).toBe(SCROLLBACK_WARNING);
    } finally {
      // It is sitting in a chat screen by now, and would sit there forever.
      child.kill();
      await child.exited;
    }
  });
});

describe("nick", () => {
  // Written as an escape rather than the raw byte: a literal ESC in a source
  // file is invisible to every reader and one careless copy away from being
  // lost.
  const clearScreen = "al\u001B[2Jice";

  it("rejects a --nick containing a control character", () => {
    // StatusBar draws the local nickname unescaped, so an escape sequence in a
    // --nick from a launch script owns the reader's terminal before a single
    // message is sent.
    expect(() => parseArgs(["join", "acorn@relay.example", "--nick", clearScreen])).toThrow(
      UsageError,
    );
    expect(() => parseArgs(["join", "acorn@relay.example", "--nick", clearScreen])).toThrow(
      /U\+001B/,
    );
  });

  it("rejects a --nick longer than 32 bytes", () => {
    const long = "a".repeat(33);

    expect(() => parseArgs(["join", "acorn@relay.example", "--nick", long])).toThrow(
      /33 UTF-8 bytes, over the limit of 32/,
    );
  });

  // The flag is not the only way in. A nickname typed at the prompt reaches the
  // same status bar, so the same rule has to hold there.
  it("rejects a prompted nickname containing a control character", () => {
    expect(() => checkPromptedNick(clearScreen)).toThrow(UsageError);
    expect(() => checkPromptedNick(clearScreen)).toThrow(/U\+001B/);
  });

  it("rejects a prompted nickname longer than 32 bytes", () => {
    expect(() => checkPromptedNick("a".repeat(33))).toThrow(
      /33 UTF-8 bytes, over the limit of 32/,
    );
  });

  it("rejects an empty prompted nickname", () => {
    expect(() => checkPromptedNick("")).toThrow(/nickname is required/);
  });

  it("accepts an ordinary prompted nickname", () => {
    expect(() => checkPromptedNick("alice")).not.toThrow();
  });
});
