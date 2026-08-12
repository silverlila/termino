import { stdin, stdout } from "node:process";
import * as readline from "node:readline/promises";

export const DEFAULT_RELAY_URL = "ws://localhost:8787";
export const DEFAULT_RELAY_PORT = 8787;

export const HELP = `termino — end-to-end encrypted terminal chat

Usage:
  termino [--channel <name>] [--nick <name>] [--relay <url>]
      Client. Prompts for the channel password on stdin without echoing it,
      derives keys, connects, then mounts the TUI. --channel and --nick are
      prompted for on stdin if omitted. Default --relay is ${DEFAULT_RELAY_URL}.

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
  const flags = readFlags(argv, ["--port"]);
  const given = flags.get("--port");
  if (given === undefined) return { mode: "serve", port: DEFAULT_RELAY_PORT };

  const port = Number(given);
  if (!Number.isInteger(port) || port < 0 || port > 65535)
    throw new UsageError(`--port must be an integer from 0 to 65535, got: ${given}`);

  return { mode: "serve", port };
}

function parseClientArgs(argv: string[]): ClientCommand {
  const flags = readFlags(argv, ["--channel", "--nick", "--relay"]);

  return {
    mode: "client",
    channel: flags.get("--channel"),
    nick: flags.get("--nick"),
    relay: flags.get("--relay") ?? DEFAULT_RELAY_URL,
  };
}

/** Flags are always `--name value` pairs; anything else is a usage error. */
function readFlags(argv: string[], allowed: readonly string[]): Map<string, string> {
  const flags = new Map<string, string>();

  for (let index = 0; index < argv.length; index += 2) {
    const token = argv[index];
    const value = argv[index + 1];
    if (token === undefined) break;

    if (token === "--password" || token === "--pass")
      throw new UsageError("the channel password is never accepted as a flag; termino prompts for it");
    if (!allowed.includes(token))
      throw new UsageError(`unknown option: ${token}\n\n${HELP}`);
    if (value === undefined || value.startsWith("-"))
      throw new UsageError(`option ${token} requires a value`);

    flags.set(token, value);
  }

  return flags;
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

async function runClient(command: ClientCommand): Promise<void> {
  const channel = command.channel ?? (await promptLine("Channel: "));
  const nick = command.nick ?? (await promptLine("Nickname: "));
  const password = await promptPassword("Password: ");

  if (channel === "" || nick === "" || password === "")
    throw new UsageError("channel, nickname and password are all required");

  // Stages 2–6 replace this: derive keys, connect to the relay, mount the TUI.
  // Key derivation must complete before the renderer starts, so the ~850 ms
  // argon2id stall never happens with a live renderer on screen.
  stdout.write(`termino: client not wired up yet — would join "${channel}" as "${nick}" via ${command.relay}\n`);
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
