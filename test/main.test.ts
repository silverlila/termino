import { afterEach, describe, expect, it } from "bun:test";
import { type ClientCommand, DEFAULT_RELAY_URL, loadRenderer, parseArgs, UsageError } from "../src/main.ts";

/**
 * The CLI, at the seams a test can reach. `runClient` and `main` are not among
 * them: they prompt on stdin, spend ~850 ms in argon2id, write to the real
 * `~/.termino`, and end in a renderer that hangs without a TTY.
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

function client(argv: string[]): ClientCommand {
  const command = parseArgs(argv);
  if (command.mode !== "client") throw new Error(`expected a client command, got: ${command.mode}`);
  return command;
}

describe("relay url", () => {
  it("a bare host gains wss://", () => {
    expect(client(["--relay", "relay.example.com:8787"]).relay).toBe("wss://relay.example.com:8787");
  });

  it("accepts wss:// to any host", () => {
    expect(client(["--relay", "wss://relay.example.com"]).relay).toBe("wss://relay.example.com");
  });

  it("accepts ws:// to localhost", () => {
    // The development path, and the default: there is no network between the
    // two ends for anyone to sit on.
    expect(client(["--relay", "ws://localhost:8787"]).relay).toBe("ws://localhost:8787");
    expect(client([]).relay).toBe(DEFAULT_RELAY_URL);
  });

  it("accepts ws:// to 127.0.0.1 and [::1]", () => {
    expect(client(["--relay", "ws://127.0.0.1:8787"]).relay).toBe("ws://127.0.0.1:8787");
    expect(client(["--relay", "ws://[::1]:8787"]).relay).toBe("ws://[::1]:8787");
  });

  it("refuses ws:// to a remote host, naming --insecure", () => {
    expect(() => client(["--relay", "ws://relay.example.com:8787"])).toThrow(UsageError);
    expect(() => client(["--relay", "ws://relay.example.com:8787"])).toThrow(/--insecure/);
  });

  it("accepts a remote ws:// under --insecure", () => {
    expect(client(["--relay", "ws://relay.example.com:8787", "--insecure"]).relay).toBe(
      "ws://relay.example.com:8787",
    );
    expect(client(["--insecure", "--relay", "ws://relay.example.com:8787"]).relay).toBe(
      "ws://relay.example.com:8787",
    );
  });

  it("refuses a scheme that is not ws or wss", () => {
    // Nothing is silently rewritten: a pasted http:// URL fails here, where the
    // message can say what is wrong, rather than as a connection that never
    // opens behind a full-screen interface.
    expect(() => client(["--relay", "http://relay.example"])).toThrow(UsageError);
    expect(() => client(["--relay", "http://relay.example"])).toThrow(/ws:\/\/ or wss:\/\//);
    expect(() => client(["--relay", "https://relay.example"])).toThrow(UsageError);
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
    expect(() => client(["--nick", clearScreen])).toThrow(UsageError);
    expect(() => client(["--nick", clearScreen])).toThrow(/U\+001B/);
  });

  it("rejects a --nick longer than 32 bytes", () => {
    expect(() => client(["--nick", "a".repeat(33)])).toThrow(UsageError);
    expect(() => client(["--nick", "a".repeat(33)])).toThrow(/33 UTF-8 bytes, over the limit of 32/);
  });
});
