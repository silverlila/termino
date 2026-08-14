import { stdin, stdout } from "node:process";
import * as readline from "node:readline/promises";
import { nickProblem } from "../shared/protocol/text.ts";
import type { SessionHandlers } from "./session.ts";

export const DEFAULT_RELAY_PORT = 8787;

/** Printed to stderr, never to stdout: the invite itself is what gets piped or
 * copied, and a warning mixed into it would travel with it. */
export const SCROLLBACK_WARNING =
  "this invite is now in your terminal scrollback — clear it once the other side has it";

export const HELP = `termino — end-to-end encrypted terminal chat

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

/** Mints a secret and prints the invite for it. */
export interface NewCommand {
  mode: "new";
  /** Prompted for on stdin when the flag is absent, as in v1. */
  nick?: string;
  relay: string;
}

/** Joins a channel somebody else's invite names. */
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

/**
 * `--relay` is required rather than defaulted. A silent `ws://localhost:8787`
 * would mint invites that work on one machine and fail as silence everywhere
 * else, which is the failure mode the channel name was deleted to avoid.
 */
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

/** A nickname is drawn into the status bar and next to every line this client
 * sends, so the rule that protects the reader from a peer's nickname has to
 * protect them from their own too. It can arrive from a launch script, a
 * pasted command, or a prompt answered without reading it back. */
function checkNick(nick: string, source: string): void {
  const problem = nickProblem(nick);
  if (problem !== null) throw new UsageError(`${source} is not usable: ${problem}`);
}

function readNickFlag(given: string | undefined): string | undefined {
  if (given === undefined) return undefined;

  checkNick(given, "--nick");
  return given;
}

/** The other route in: a nickname typed at the prompt reaches the same status
 * bar, so it is held to the same rule. Exported because the caller that prompts
 * cannot be driven from a test — it reads stdin and ends in a renderer that
 * hangs without a TTY. */
export function checkPromptedNick(nick: string): void {
  if (nick === "") throw new UsageError("a nickname is required");
  checkNick(nick, "the nickname");
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
export function resolveRelayUrl(given: string, insecure: boolean): string {
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

/**
 * The URL an invite is dialled on.
 *
 * An invite carries a host and deliberately no scheme, so `parseInvite` hands
 * back `wss://` — the only answer that is safe over a network nobody controls.
 * Loopback is the one host where that answer is not cautious but wrong: nothing
 * issues a certificate for `localhost`, so `wss://localhost` cannot be dialled
 * at all, and an invite naming it can only have come from the same machine.
 *
 * This is the same exemption `resolveRelayUrl` makes for `--relay`, read from
 * the other direction, and it is made here rather than in `parseInvite` for the
 * same reason the scheme is not in the token: which schemes this client will
 * dial is the client's policy, not the invite's.
 *
 * The alternative was an `--insecure` flag on `join`. It was rejected: it would
 * put a security-waiving flag on the ordinary path of trying termino out on one
 * machine, which teaches the habit of typing it.
 */
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

/**
 * Loads the React renderer with `DEV` cleared.
 *
 * `@opentui/react` imports `react-devtools-core` at module evaluation time
 * when `DEV=true`, and devtools serialises the whole element tree — props
 * included — to a WebSocket on localhost. The variable is cleared *before*
 * the import because the gate is read as the module evaluates; clearing it
 * afterwards would be too late.
 *
 * Exported so the clearing can be tested on its own: the caller below ends in a
 * renderer that hangs without a TTY, which a test cannot drive.
 */
export async function loadRenderer(): Promise<typeof import("@opentui/react")> {
  delete process.env.DEV;
  return await import("@opentui/react");
}

/**
 * Mints a secret, says it out loud once, and joins the channel it names.
 *
 * The invite goes to stdout so it stays pipeable and copy-pasteable; the
 * warning goes to stderr so it never travels with the thing it warns about.
 */
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

  // The screen never holds the secret. It is captured here instead, where the
  // only thing that crosses into React is a function — and a function is not
  // something devtools can serialise.
  const connect = (handlers: SessionHandlers) =>
    startSession({ psk, nick, relayUrl, handlers });

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

  root.render(createElement(App, { nick, connect, onExit }));
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
  // The whole body, not just `parseArgs`: a malformed invite raises UsageError
  // from `runJoin` too, and that is the path most users reach it by.
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
