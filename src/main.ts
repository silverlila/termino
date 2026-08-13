import { stdin, stdout } from "node:process";
import * as readline from "node:readline/promises";
import { nickProblem } from "../shared/protocol/text.ts";
import type { SessionHandlers } from "./session.ts";

export const DEFAULT_RELAY_URL = "ws://localhost:8787";
export const DEFAULT_RELAY_PORT = 8787;

export const HELP = `termino — end-to-end encrypted terminal chat

Usage:
  termino [--channel <name>] [--nick <name>] [--relay <url>] [--insecure]
      Client. Prompts for the channel password on stdin without echoing it,
      derives keys, connects, then mounts the TUI. --channel and --nick are
      prompted for on stdin if omitted. Default --relay is ${DEFAULT_RELAY_URL}.

      A --relay with no scheme is read as wss://. Plain ws:// is refused for
      every host but localhost, 127.0.0.1 and [::1]: nothing authenticates a
      relay, so an unencrypted connection to a remote one can be dropped or
      delayed by anyone on the path. --insecure permits it anyway.

  termino serve [--port <n>]
      Relay. Default port ${DEFAULT_RELAY_PORT}, WebSocket path /.

  termino --help
      Show this message.

The channel password is never accepted as a flag — it would land in shell
history and in the output of \`ps\`.
`;

export class UsageError extends Error {}

export interface HelpCommand {
  mode: "help";
}

export interface ServeCommand {
  mode: "serve";
  port: number;
}

export interface ClientCommand {
  mode: "client";
  channel?: string;
  nick?: string;
  relay: string;
}

export type Command = HelpCommand | ServeCommand | ClientCommand;

export function parseArgs(argv: string[]): Command {
  if (argv.includes("--help") || argv.includes("-h")) return { mode: "help" };

  const [first, ...rest] = argv;
  if (first === "serve") return parseServeArgs(rest);

  return parseClientArgs(argv);
}

function parseServeArgs(argv: string[]): ServeCommand {
  const { values } = readFlags(argv, ["--port"]);
  const given = values.get("--port");
  if (given === undefined) return { mode: "serve", port: DEFAULT_RELAY_PORT };

  const port = Number(given);
  if (!Number.isInteger(port) || port < 0 || port > 65535)
    throw new UsageError(`--port must be an integer from 0 to 65535, got: ${given}`);

  return { mode: "serve", port };
}

function parseClientArgs(argv: string[]): ClientCommand {
  const { values, switches } = readFlags(argv, ["--channel", "--nick", "--relay"], ["--insecure"]);

  const nick = values.get("--nick");
  if (nick !== undefined) {
    // A nickname is drawn into the status bar and next to every line this
    // client sends, so the rule that protects the reader from a peer's
    // nickname has to protect them from their own too — a --nick can arrive
    // from a launch script or a pasted command nobody read.
    const problem = nickProblem(nick);
    if (problem !== null) throw new UsageError(`--nick is not usable: ${problem}`);
  }

  return {
    mode: "client",
    channel: values.get("--channel"),
    nick,
    relay: resolveRelayUrl(values.get("--relay") ?? DEFAULT_RELAY_URL, switches.has("--insecure")),
  };
}

/** Loopback carries no network an attacker can sit on. `URL.hostname` keeps
 * the brackets on an IPv6 literal, so `[::1]` is spelt that way here. */
const LOOPBACK_HOSTS = new Set(["localhost", "127.0.0.1", "[::1]"]);

const SCHEME_PATTERN = /^[a-z][a-z0-9+.-]*:\/\//i;

/**
 * The relay URL a client should dial, or a `UsageError` explaining why not.
 *
 * Message contents are encrypted whatever the transport, but nothing
 * authenticates the relay, so plain `ws://` over a real network lets an
 * attacker on the path drop or delay traffic silently. A mistyped scheme fails
 * here rather than inside the renderer, where the only symptom would be a
 * connection that never opens behind a full-screen interface.
 */
function resolveRelayUrl(given: string, insecure: boolean): string {
  const withScheme = SCHEME_PATTERN.test(given) ? given : `wss://${given}`;

  let parsed: URL;
  try {
    parsed = new URL(withScheme);
  } catch {
    throw new UsageError(`--relay is not a URL: ${given}`);
  }

  if (parsed.protocol === "wss:") return withScheme;

  if (parsed.protocol !== "ws:")
    throw new UsageError(`--relay must be ws:// or wss://, got ${parsed.protocol}// in: ${given}`);

  if (insecure || LOOPBACK_HOSTS.has(parsed.hostname)) return withScheme;

  throw new UsageError(
    `--relay ${given} is unencrypted ws:// to ${parsed.hostname}, which nothing authenticates; ` +
      `use wss://, or --insecure to accept that a network attacker can drop or delay your messages`,
  );
}

interface Flags {
  values: Map<string, string>;
  switches: Set<string>;
}

/** Flags are `--name value` pairs, except for the named value-less switches;
 * anything else is a usage error. */
function readFlags(
  argv: string[],
  allowed: readonly string[],
  switches: readonly string[] = [],
): Flags {
  const values = new Map<string, string>();
  const seen = new Set<string>();
  let index = 0;

  while (index < argv.length) {
    const token = argv[index]!;

    if (token === "--password" || token === "--pass")
      throw new UsageError("the channel password is never accepted as a flag; termino prompts for it");

    if (switches.includes(token)) {
      seen.add(token);
      index += 1;
      continue;
    }

    if (!allowed.includes(token))
      throw new UsageError(`unknown option: ${token}\n\n${HELP}`);

    const value = argv[index + 1];
    if (value === undefined || value.startsWith("-"))
      throw new UsageError(`option ${token} requires a value`);

    values.set(token, value);
    index += 2;
  }

  return { values, switches: seen };
}

async function promptLine(question: string): Promise<string> {
  const rl = readline.createInterface({ input: stdin, output: stdout });
  try {
    return (await rl.question(question)).trim();
  } finally {
    rl.close();
  }
}

/** Reads a line without echoing it, so the password never lands on screen. */
async function promptPassword(question: string): Promise<string> {
  if (!stdin.isTTY) return await promptLine(question);

  stdout.write(question);
  stdin.setRawMode(true);
  stdin.resume();
  stdin.setEncoding("utf8");

  const typed: string[] = [];

  return await new Promise<string>((resolve) => {
    const stop = () => {
      stdin.off("data", onData);
      stdin.setRawMode(false);
      stdin.pause();
      stdout.write("\n");
    };

    const onData = (chunk: string) => {
      for (const char of chunk) {
        if (char === "\r" || char === "\n") {
          stop();
          resolve(typed.join(""));
          return;
        }
        if (char === "\u0003") {
          stop();
          process.exit(130);
        }
        if (char === "\u007f" || char === "\b") {
          typed.pop();
          continue;
        }
        typed.push(char);
      }
    };

    stdin.on("data", onData);
  });
}

/**
 * Loads the React renderer with `DEV` cleared.
 *
 * `@opentui/react` imports `react-devtools-core` at module evaluation time
 * when `DEV=true`, and devtools serialises the whole element tree — props
 * included — to a WebSocket on localhost. The variable is cleared *before*
 * the import because the gate is read as the module evaluates; clearing it
 * afterwards would be too late.
 *
 * Exported so the clearing can be tested on its own: the caller below prompts
 * on stdin, spends ~850 ms in argon2id and ends in a renderer that hangs
 * without a TTY, none of which a test can drive.
 */
export async function loadRenderer(): Promise<typeof import("@opentui/react")> {
  delete process.env.DEV;
  return await import("@opentui/react");
}

async function runClient(command: ClientCommand): Promise<void> {
  const channel = command.channel ?? (await promptLine("Channel: "));
  const nick = command.nick ?? (await promptLine("Nickname: "));
  const password = await promptPassword("Password: ");

  if (channel === "" || nick === "" || password === "")
    throw new UsageError("channel, nickname and password are all required");

  // Everything up to and including derivation happens on the plain terminal,
  // before any renderer exists. argon2id blocks for ~850 ms; paying it with a
  // renderer already on screen would freeze a drawn interface instead of
  // pausing a printed prompt.
  const { loadOrCreateIdentity } = await import("../shared/crypto/identity.ts");
  const { deriveChannelKeys } = await import("../shared/crypto/derive.ts");
  const { fingerprint } = await import("../shared/crypto/fingerprint.ts");
  const { startSession } = await import("./session.ts");

  const identity = loadOrCreateIdentity();
  stdout.write("deriving channel keys…\n");
  const keys = deriveChannelKeys(channel, password);

  // The screen never holds the device key or the channel key. They are
  // captured here instead, where the only thing that crosses into React is a
  // function — and a function is not something devtools can serialise.
  const connect = (handlers: SessionHandlers) =>
    startSession({ keys, nick, identity, relayUrl: command.relay, handlers });

  // Imported here rather than at the top of the file so `--help` never loads
  // the renderer at all: constructing one without a TTY hangs. `App.tsx` comes
  // after `loadRenderer`, because its JSX pulls in `@opentui/react` too.
  const { createCliRenderer } = await import("@opentui/core");
  const { createElement, createRoot } = await loadRenderer();
  const { App } = await import("./tui/App.tsx");

  const renderer = await createCliRenderer();
  const root = createRoot(renderer);

  // `/exit` unwinds what this function built, in the order it was built, so
  // the terminal is handed back the way it was found.
  const onExit = () => {
    root.unmount();
    renderer.destroy();
    process.exit(0);
  };

  root.render(
    createElement(App, {
      channel,
      nick,
      fingerprint: fingerprint(identity.publicKey),
      connect,
      onExit,
    }),
  );
}

async function runServe(command: ServeCommand): Promise<void> {
  // Imported here rather than at the top of the file so that running the
  // client never loads relay code at all. The relay is a separate deployable;
  // the only thing the two share is the wire format.
  const { startRelay } = await import("../server/relay.ts");

  const server = startRelay({ port: command.port });
  stdout.write(`termino relay listening on ws://localhost:${server.port}\n`);
}

export async function main(argv: string[]): Promise<number> {
  // The whole body, not just `parseArgs`: the prompts in `runClient` raise
  // UsageError too, and that is the path most users reach it by.
  try {
    const command = parseArgs(argv);

    if (command.mode === "help") {
      stdout.write(HELP);
      return 0;
    }

    if (command.mode === "serve") {
      await runServe(command);
      return 0;
    }

    await runClient(command);
    return 0;
  } catch (error) {
    if (!(error instanceof UsageError)) throw error;
    process.stderr.write(`${error.message}\n`);
    return 2;
  }
}

if (import.meta.main) {
  process.exitCode = await main(process.argv.slice(2));
}
