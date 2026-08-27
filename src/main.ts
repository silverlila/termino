/**
 * The CLI: argument parsing, help, invite minting, relay URL resolution, and process
 * wiring for the TUI.
 *
 * A URL's hostname keeps the brackets on an IPv6 literal: loopback is "[::1]", never
 * "::1". No CA issues a certificate for localhost, so wss://localhost cannot be dialled
 * at all — a loopback relay is reached over ws://.
 *
 * @opentui/react reads DEV at module evaluation: on "true" it loads react-devtools-core,
 * which serialises the element tree to a WebSocket on localhost. DEV is cleared before
 * that import.
 */

import { stdin, stdout } from "node:process";
import * as readline from "node:readline/promises";
import { nickProblem } from "../shared/protocol/text.ts";
import type { SessionHandlers } from "./session.ts";

const DEFAULT_RELAY_PORT = 8787;

export const SCROLLBACK_WARNING =
  "this invite is now in your terminal scrollback — clear it once the other side has it";

const HELP = `termino — end-to-end encrypted terminal chat

Usage:
  termino new --relay <url> [--nick <name>]
      Generates a secret, prints an invite, and joins the channel it names.
      The invite is the whole secret: whoever holds it can talk to you, so
      carry it to the other person by a route you trust.

      A --relay with no scheme is read as wss://. Plain ws:// is refused for
      every host but localhost, 127.0.0.1 and [::1]: nothing authenticates a
      relay, so an unencrypted connection to a remote one can be dropped or
      delayed by anyone on the path. --insecure permits it anyway.

  termino join <invite> [--nick <name>]
      Joins the channel an invite names. The relay comes from the invite, so
      --relay is not accepted here. An invite carries a host and no scheme: it
      is dialled over wss://, or over ws:// when the host is localhost.

  termino serve [--port <n>]
      Relay. Default port ${DEFAULT_RELAY_PORT}, WebSocket path /.

  termino --help
      Show this message.

There is no password and no channel name. The secret is generated, never
typed: a secret a person chooses is one an attacker can guess offline.
`;

export class UsageError extends Error {}

export interface HelpCommand {
  mode: "help";
}

export interface ServeCommand {
  mode: "serve";
  port: number;
}

export interface NewCommand {
  mode: "new";
  nick?: string;
  relay: string;
}

export interface JoinCommand {
  mode: "join";
  nick?: string;
  invite: string;
}

export type Command = HelpCommand | ServeCommand | NewCommand | JoinCommand;

export function parseArgs(argv: string[]): Command {
  if (argv.includes("--help") || argv.includes("-h")) return { mode: "help" };

  const [first, ...rest] = argv;

  if (first === "serve") return parseServeArgs(rest);
  if (first === "new") return parseNewArgs(rest);
  if (first === "join") return parseJoinArgs(rest);

  throw new UsageError(`expected new, join or serve, got: ${first ?? "nothing"}\n\n${HELP}`);
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

function parseNewArgs(argv: string[]): NewCommand {
  const { values, switches } = readFlags(argv, ["--nick", "--relay"], ["--insecure"]);

  const relay = values.get("--relay");
  if (relay === undefined) throw new UsageError("new requires --relay <url>: an invite has to say where to meet");

  return {
    mode: "new",
    nick: readNickFlag(values.get("--nick")),
    relay: resolveRelayUrl(relay, switches.has("--insecure")),
  };
}

function parseJoinArgs(argv: string[]): JoinCommand {
  const [invite, ...rest] = argv;
  if (invite === undefined || invite.startsWith("-"))
    throw new UsageError(`join requires an invite: termino join <words>@<host>\n\n${HELP}`);

  const { values } = readFlags(rest, ["--nick"]);

  return { mode: "join", nick: readNickFlag(values.get("--nick")), invite };
}

function checkNick(nick: string, source: string): void {
  const problem = nickProblem(nick);
  if (problem !== null) throw new UsageError(`${source} is not usable: ${problem}`);
}

function readNickFlag(given: string | undefined): string | undefined {
  if (given === undefined) return undefined;

  checkNick(given, "--nick");
  return given;
}

export function checkPromptedNick(nick: string): void {
  if (nick === "") throw new UsageError("a nickname is required");
  checkNick(nick, "the nickname");
}

const LOOPBACK_HOSTS = new Set(["localhost", "127.0.0.1", "[::1]"]);

const SCHEME_PATTERN = /^[a-z][a-z0-9+.-]*:\/\//i;

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

export function inviteRelayUrl(fromInvite: string): string {
  const parsed = new URL(fromInvite);
  if (!LOOPBACK_HOSTS.has(parsed.hostname)) return fromInvite;

  parsed.protocol = "ws:";
  return parsed.toString();
}

interface Flags {
  values: Map<string, string>;
  switches: Set<string>;
}

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

export async function loadRenderer(): Promise<typeof import("@opentui/react")> {
  delete process.env.DEV;
  return await import("@opentui/react");
}

async function runNew(command: NewCommand): Promise<void> {
  const { generatePsk } = await import("../shared/crypto/psk.ts");
  const { formatInvite } = await import("../shared/protocol/invite.ts");

  const psk = generatePsk();

  stdout.write(`${formatInvite(psk, command.relay)}\n`);
  process.stderr.write(`${SCROLLBACK_WARNING}\n`);

  await runChat(psk, command.relay, command.nick);
}

async function runJoin(command: JoinCommand): Promise<void> {
  const { InvalidInviteError, parseInvite } = await import("../shared/protocol/invite.ts");

  try {
    const invite = parseInvite(command.invite);
    await runChat(invite.psk, inviteRelayUrl(invite.relay), command.nick);
  } catch (error) {
    if (error instanceof InvalidInviteError) throw new UsageError(error.message);
    throw error;
  }
}

async function runChat(psk: Uint8Array, relayUrl: string, given: string | undefined): Promise<void> {
  const nick = given ?? (await promptLine("Nickname: "));
  checkPromptedNick(nick);

  const { startSession } = await import("./session.ts");

  const connect = (handlers: SessionHandlers) =>
    startSession({ psk, nick, relayUrl, handlers });

  const { createCliRenderer } = await import("@opentui/core");
  const { createElement, createRoot } = await loadRenderer();
  const { App } = await import("./tui/App.tsx");

  const renderer = await createCliRenderer();
  const root = createRoot(renderer);

  const onExit = () => {
    root.unmount();
    renderer.destroy();
    process.exit(0);
  };

  root.render(createElement(App, { nick, connect, onExit }));
}

async function runServe(command: ServeCommand): Promise<void> {
  const { startRelay } = await import("../server/relay.ts");

  const server = startRelay({
    port: command.port,
    onError: () => process.stderr.write("termino relay: a connection failed\n"),
  });
  stdout.write(`termino relay listening on ws://localhost:${server.port}\n`);
}

export async function main(argv: string[]): Promise<number> {
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

    if (command.mode === "new") await runNew(command);
    else await runJoin(command);

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
