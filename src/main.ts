/**
 * @opentui/react reads DEV at module evaluation: on "true" it loads react-devtools-core,
 * which serialises the element tree to a WebSocket on localhost. DEV is cleared before
 * that import.
 */

import { stdin, stdout } from "node:process";
import * as readline from "node:readline/promises";
import { nickProblem, visible } from "../shared/protocol/text.ts";
import type { Chat } from "./launch.ts";
import { isLoopback } from "./relay-url.ts";

const DEFAULT_RELAY_PORT = 8787;

export const RELAY_ENV = "TERMINO_RELAY";

export const DEFAULT_RELAY_URL: string | undefined = undefined;

export const SCROLLBACK_WARNING =
  "this invite is now in your terminal scrollback — clear it once the other side has it";

const HELP = `termino — end-to-end encrypted terminal chat

Usage:
  termino [--relay <url>] [--nick <name>]
      Opens the start screen, where you pick a name and then start a new
      chat, join one with an invite somebody sent you, or meet in a room on a
      passphrase you both know. A passphrase room meets on the relay below,
      so both people need the same one.

  termino new [--relay <url>] [--nick <name>]
      Generates a secret, prints an invite, and joins the channel it names.
      The invite is the whole secret: whoever holds it can talk to you, so
      carry it to the other person by a route you trust.

  termino join <invite> [--nick <name>]
      Joins the channel an invite names. The relay comes from the invite, so
      --relay is not accepted here. An invite carries a host and no scheme: it
      is dialled over wss://, or over ws:// when the host is localhost.

  termino serve [--port <n>]
      Relay. Default port ${DEFAULT_RELAY_PORT}, WebSocket path /.

  termino --help
      Show this message.

The relay a new chat or passphrase room meets on is --relay if given, else $${RELAY_ENV}, else
the built-in default. A relay with no scheme is read as wss://. Plain ws:// is
refused for every host but localhost, 127.0.0.1 and [::1]: nothing
authenticates a relay, so an unencrypted connection to a remote one can be
dropped or delayed by anyone on the path. --insecure permits it anyway.

An invite's secret is generated, never typed, and is the strongest option.
A passphrase room uses a phrase people chose, through a password exchange
(CPace) that gives nobody a recording to guess against: each guess has to be
a live attempt, and a wrong one fails on the screen of whoever it was tried on.
`;

export class UsageError extends Error {}

export interface StartCommand {
  mode: "start";
  nick?: string;
  relay: string;
}

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

export type Command = StartCommand | HelpCommand | ServeCommand | NewCommand | JoinCommand;

export type Env = Record<string, string | undefined>;

export function parseArgs(argv: string[], env: Env = process.env): Command {
  if (argv.includes("--help") || argv.includes("-h")) return { mode: "help" };

  const [first, ...rest] = argv;

  if (first === undefined || first.startsWith("-")) return parseStartArgs(argv, env);
  if (first === "serve") return parseServeArgs(rest);
  if (first === "new") return parseNewArgs(rest, env);
  if (first === "join") return parseJoinArgs(rest);

  throw new UsageError(`expected new, join or serve, got: ${first}\n\n${HELP}`);
}

function parseStartArgs(argv: string[], env: Env): StartCommand {
  const { values, switches } = readFlags(argv, ["--nick", "--relay"], ["--insecure"]);

  return {
    mode: "start",
    nick: readNickFlag(values.get("--nick")),
    relay: chooseRelay(values.get("--relay"), env, switches.has("--insecure")),
  };
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

function parseNewArgs(argv: string[], env: Env): NewCommand {
  const { values, switches } = readFlags(argv, ["--nick", "--relay"], ["--insecure"]);

  return {
    mode: "new",
    nick: readNickFlag(values.get("--nick")),
    relay: chooseRelay(values.get("--relay"), env, switches.has("--insecure")),
  };
}

export function chooseRelay(
  flag: string | undefined,
  env: Env,
  insecure: boolean,
  fallback: string | undefined = DEFAULT_RELAY_URL,
): string {
  if (flag !== undefined) return resolveRelayUrl(flag, "--relay", insecure);

  const fromEnv = env[RELAY_ENV];
  if (fromEnv !== undefined && fromEnv !== "") return resolveRelayUrl(fromEnv, RELAY_ENV, insecure);

  if (fallback !== undefined) return fallback;

  throw new UsageError(`no relay to meet on: pass --relay <url> or set ${RELAY_ENV}`);
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

const SCHEME_PATTERN = /^[a-z][a-z0-9+.-]*:\/\//i;

function resolveRelayUrl(given: string, source: string, insecure: boolean): string {
  const withScheme = SCHEME_PATTERN.test(given) ? given : `wss://${given}`;

  let parsed: URL;
  try {
    parsed = new URL(withScheme);
  } catch {
    throw new UsageError(`${source} is not a URL: ${visible(given)}`);
  }

  // An invite keeps only the host, so anything after it would be dialled by the
  // person starting the chat and never by the person joining it.
  if (parsed.pathname !== "/" || parsed.search !== "" || parsed.hash !== "" || parsed.username !== "") {
    throw new UsageError(`${source} must be a relay's address alone, with no path or query: ${visible(given)}`);
  }

  const relay = `${parsed.protocol}//${parsed.host}`;

  if (parsed.protocol === "wss:") return relay;

  if (parsed.protocol !== "ws:")
    throw new UsageError(`${source} must be ws:// or wss://, got ${parsed.protocol}// in: ${relay}`);

  if (insecure || isLoopback(parsed.hostname)) return relay;

  throw new UsageError(
    `${source} ${relay} is unencrypted ws:// to ${parsed.hostname}, which nothing authenticates; ` +
      `use wss://, or --insecure to accept that a network attacker can drop or delay your messages`,
  );
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

async function runStart(command: StartCommand): Promise<void> {
  const { joinChat, newChat, passphraseChat } = await import("./launch.ts");
  const screen = await openScreen();
  const { Termino } = await import("./tui/Termino.tsx");

  screen.root.render(
    screen.createElement(Termino, {
      relay: command.relay,
      nick: command.nick,
      start: () => newChat(command.relay),
      join: joinChat,
      meet: (room: string, phrase: string) => passphraseChat(command.relay, room, phrase),
      onExit: screen.close,
    }),
  );
}

async function runNew(command: NewCommand): Promise<void> {
  const { newChat } = await import("./launch.ts");
  const chat = newChat(command.relay);

  stdout.write(`${chat.invite}\n`);
  process.stderr.write(`${SCROLLBACK_WARNING}\n`);

  await runChat(chat, command.nick);
}

async function runJoin(command: JoinCommand): Promise<void> {
  const { joinChat } = await import("./launch.ts");

  const joined = joinChat(command.invite);
  if (!joined.ok) throw new UsageError(joined.reason);

  await runChat(joined.chat, command.nick);
}

async function runChat(chat: Chat, given: string | undefined): Promise<void> {
  const nick = given ?? (await promptLine("Nickname: "));
  checkPromptedNick(nick);

  const screen = await openScreen();
  const { App } = await import("./tui/App.tsx");

  screen.root.render(
    screen.createElement(App, {
      nick,
      invite: chat.invite,
      connect: (handlers) => chat.connect(nick, handlers),
      onExit: screen.close,
    }),
  );
}

async function openScreen() {
  const { createCliRenderer } = await import("@opentui/core");
  const { createElement, createRoot } = await loadRenderer();

  const renderer = await createCliRenderer();
  const root = createRoot(renderer);

  const close = () => {
    root.unmount();
    renderer.destroy();
    process.exit(0);
  };

  return { createElement, root, close };
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

    if (command.mode === "start") await runStart(command);
    else if (command.mode === "new") await runNew(command);
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
