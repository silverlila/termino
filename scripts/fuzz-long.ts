/**
 * Fuzzes the two parsers that read fully attacker-controlled bytes.
 *
 * `decodeFrame` runs in the relay and in the client on anything a socket
 * delivers, and `parsePayload` runs on whatever a message turns out to contain
 * once it is decrypted. Nothing authenticates either input before it arrives, so
 * this is where the reachable bugs are; the AEAD and the ratchet only ever see
 * bytes that are already authenticated or locally generated.
 *
 * Neither parser may throw anything but its own declared error — `FrameError`,
 * `PayloadError` — and neither may take long enough on one input to look like a
 * hang. `openMessage` is deliberately not a target: it is documented to throw
 * `DecryptError` and `PaddingError` as well, so "only the parser's error
 * escapes" would fail there on correct behaviour.
 *
 * `test/shared/protocol/fuzz.test.ts` imports `fuzz` for a short budget inside
 * the suite; this file's command line runs a long one for somebody to leave
 * going. Both drive the same targets through the same generators.
 *
 *   bun run scripts/fuzz-long.ts --budget 60 [--seed 1234]
 */

import { decodeFrame, FrameError, toBase64 } from "../shared/protocol/frame.ts";
import { parsePayload, PayloadError } from "../shared/protocol/message.ts";

/**
 * No single input may spend longer than this in a parser. The bound is per
 * input rather than per run on purpose: a suite timeout cannot tell one input
 * that hangs from a thousand that are merely slow, and it is raised on a slow
 * machine anyway (`bun test --timeout 30000`), which would take the hang check
 * with it.
 */
export const MAX_PARSE_MS = 50;

/** Stops a run once it has this many findings. The point is to report the first
 * ones with their inputs, not to spend the rest of the budget on duplicates. */
const MAX_FINDINGS = 5;

export interface Target {
  readonly name: string;
  parse(input: string): void;
  /** True for the one error type this parser is allowed to throw. */
  declaresError(error: unknown): boolean;
}

const throwsOnlyFrameError = (error: unknown) => error instanceof FrameError;

export const frameTarget: Target = {
  name: "decodeFrame",
  parse: (input) => {
    decodeFrame(input);
  },
  declaresError: throwsOnlyFrameError,
};

/** The same parser through its other entry point: the relay hands `decodeFrame`
 * whatever the socket delivered, which is a `Uint8Array` for a binary message,
 * and the size limit is measured differently on that path. */
export const frameBytesTarget: Target = {
  name: "decodeFrame(bytes)",
  parse: (input) => {
    decodeFrame(new TextEncoder().encode(input));
  },
  declaresError: throwsOnlyFrameError,
};

export const payloadTarget: Target = {
  name: "parsePayload",
  parse: (input) => {
    parsePayload(input);
  },
  declaresError: (error) => error instanceof PayloadError,
};

export const TARGETS: readonly Target[] = [frameTarget, frameBytesTarget, payloadTarget];

export interface Finding {
  readonly target: string;
  /** The generator or corpus file the input came from. */
  readonly source: string;
  readonly input: string;
  readonly problem: string;
}

/**
 * Runs one input through one parser, and reports what it did wrong or `null`.
 *
 * A parse that is over the time bound is measured a second time before it is
 * reported: the first measurement can be a garbage collection pause that landed
 * inside the window, and a fuzz run that fails on a machine's mood teaches
 * nobody anything. A parser that genuinely hangs fails both measurements.
 */
export function check(target: Target, input: string, source: string): Finding | null {
  const attempt = attemptParse(target, input);
  const report = (problem: string): Finding => ({ target: target.name, source, input, problem });

  if (attempt.undeclared !== null) return report(attempt.undeclared);
  if (attempt.elapsed <= MAX_PARSE_MS) return null;

  const confirmed = attemptParse(target, input).elapsed;
  if (confirmed <= MAX_PARSE_MS) return null;

  return report(`took ${confirmed.toFixed(1)} ms, over the ${MAX_PARSE_MS} ms bound`);
}

interface Attempt {
  /** The error this input provoked that the parser does not declare, described,
   * or `null` for no error and for a declared one. */
  readonly undeclared: string | null;
  readonly elapsed: number;
}

function attemptParse(target: Target, input: string): Attempt {
  const started = performance.now();
  try {
    target.parse(input);
    return { undeclared: null, elapsed: performance.now() - started };
  } catch (error) {
    const elapsed = performance.now() - started;
    if (target.declaresError(error)) return { undeclared: null, elapsed };

    return { undeclared: `threw ${nameOf(error)}: ${messageOf(error)}`, elapsed };
  }
}

function nameOf(error: unknown): string {
  if (error instanceof Error) return error.constructor.name;
  return `a thrown ${error === null ? "null" : typeof error}`;
}

function messageOf(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

/** One line naming the parser, the problem and the input that caused it. The
 * input is truncated, because a finding may be a megabyte long. */
export function describeFinding(finding: Finding): string {
  const preview = JSON.stringify(finding.input.slice(0, 300));
  const rest = finding.input.length > 300 ? ` … (${finding.input.length} chars)` : "";

  return `${finding.target} ${finding.problem} — from ${finding.source}: ${preview}${rest}`;
}

// ---------------------------------------------------------------------------
// Generators
// ---------------------------------------------------------------------------

type Random = () => number;

interface Generator {
  readonly name: string;
  produce(random: Random): string;
}

/** Seeded rather than `Math.random`, so a finding can be reproduced from the
 * seed the run reports. */
export function randomFrom(seed: number): Random {
  let state = seed >>> 0;

  return () => {
    state = (state + 0x6d2b79f5) >>> 0;
    let mixed = state;
    mixed = Math.imul(mixed ^ (mixed >>> 15), mixed | 1);
    mixed ^= mixed + Math.imul(mixed ^ (mixed >>> 7), mixed | 61);
    return ((mixed ^ (mixed >>> 14)) >>> 0) / 4294967296;
  };
}

function pick<T>(random: Random, values: readonly T[]): T {
  return values[Math.floor(random() * values.length)]!;
}

function between(random: Random, low: number, high: number): number {
  return low + Math.floor(random() * (high - low + 1));
}

const HANDLE = "63402012e8d78d978a4ab491cf2e5ae9";
const PUBLIC_KEY = toBase64(new Uint8Array(32));
const CIPHERTEXT = toBase64(new Uint8Array(64));

/** Frames and payloads that parse today. Every structural generator starts from
 * one of these and breaks it, because a purely random string exercises nothing
 * past `JSON.parse`. */
const VALID: readonly Record<string, unknown>[] = [
  { v: 2, t: "sub", h: HANDLE },
  { v: 2, t: "hello", h: HANDLE, k: PUBLIC_KEY },
  { v: 2, t: "msg", h: HANDLE, i: 7, c: CIPHERTEXT },
  { v: 2, t: "err", code: "bad_frame" },
  { t: "text", nick: "alice", body: "hello" },
  { t: "ping", nick: "alice" },
  { t: "confirm", nick: "alice" },
];

/** What one field of an otherwise valid frame or payload gets replaced with:
 * values JSON can carry that the parser must refuse rather than believe. */
const HOSTILE_VALUES: readonly unknown[] = [
  null,
  true,
  false,
  0,
  -1,
  1.5,
  1e308,
  2 ** 53,
  4294967296,
  "",
  " ",
  "2",
  "null",
  "sub",
  "text",
  "\u0000",
  "\u202E",
  "\uFEFF",
  "\u{1D518}\u{1D52B}",
  [],
  {},
  [1, 2, 3],
  { t: "sub" },
  "63402012e8d78d978a4ab491cf2e5ae",
  "63402012E8D78D978A4AB491CF2E5AE9",
  "AA$A",
  "A===",
  "=",
  "A",
];

/** Characters that mean something to `JSON.parse`, to base64, or to a terminal.
 * Spread as code points, so no generated string carries a lone surrogate. */
const ALPHABET = [...'{}[]",:0123456789abcdefABCDEF+/=\\ \t\n\u0000\u202E\uFFFD\u{1D518}'];

const GENERATORS: readonly Generator[] = [
  { name: "random text", produce: randomText },
  { name: "field replaced", produce: fieldReplaced },
  { name: "field removed", produce: fieldRemoved },
  { name: "edited encoding", produce: editedEncoding },
  { name: "nested json", produce: nestedJson },
  { name: "oversized field", produce: oversizedField },
  { name: "corrupted base64", produce: corruptedBase64 },
];

function randomText(random: Random): string {
  const length = between(random, 0, 256);
  let text = "";
  for (let index = 0; index < length; index += 1) text += pick(random, ALPHABET);

  return text;
}

function fieldReplaced(random: Random): string {
  const original = pick(random, VALID);
  const mutated: Record<string, unknown> = { ...original };
  const field = pick(random, [...Object.keys(original), "n", "body", "nick", "extra"]);
  mutated[field] = pick(random, HOSTILE_VALUES);

  return JSON.stringify(mutated);
}

function fieldRemoved(random: Random): string {
  const original = pick(random, VALID);
  const mutated: Record<string, unknown> = { ...original };
  delete mutated[pick(random, Object.keys(original))];

  return JSON.stringify(mutated);
}

/** Byte-level damage to something that was well formed: what a relay that
 * rewrites frames, or a lossy path, actually produces. */
function editedEncoding(random: Random): string {
  let text = JSON.stringify(pick(random, VALID));
  const edits = between(random, 1, 4);
  for (let edit = 0; edit < edits; edit += 1) text = editOnce(random, text);

  return text;
}

function editOnce(random: Random, text: string): string {
  if (text.length === 0) return text;

  const at = between(random, 0, text.length - 1);
  switch (between(random, 0, 3)) {
    case 0:
      return text.slice(0, at);
    case 1:
      return text.slice(0, at) + text.slice(at + 1);
    case 2:
      return text.slice(0, at) + pick(random, ALPHABET) + text.slice(at + 1);
    default:
      return text.slice(0, at) + text.slice(at, at + 8) + text.slice(at);
  }
}

/**
 * Nesting far past anything the wire allows. `decodeFrame` caps its input at
 * `MAX_FRAME_BYTES`, but `parsePayload` is handed whatever a message decrypts
 * to, and building an error message by recursing over the value is a way to
 * overflow the stack while rejecting it. Depth is drawn log-uniformly, so most
 * cases stay cheap and a few go all the way.
 */
function nestedJson(random: Random): string {
  const depth = Math.max(1, Math.round(Math.exp(random() * Math.log(100_000))));
  const [open, close] = pick(random, [
    ["[", "]"],
    ['{"a":', "}"],
  ] as const);
  const nested = open.repeat(depth) + "0" + close.repeat(depth);

  return pick(random, [
    nested,
    `{"v":2,"t":${nested}}`,
    `{"t":${nested},"nick":"alice"}`,
    `{"v":2,"t":"msg","h":"${HANDLE}","i":0,"c":${nested}}`,
  ]);
}

function oversizedField(random: Random): string {
  const original = pick(random, VALID);
  const mutated: Record<string, unknown> = { ...original };
  mutated[pick(random, Object.keys(original))] = "A".repeat(between(random, 2000, 20_000));

  return JSON.stringify(mutated);
}

/** Base64 is the one place a parser can be fooled into accepting short bytes:
 * `Buffer.from(text, "base64")` drops characters outside the alphabet instead
 * of refusing them, which is why `fromBase64` checks the shape first. */
function corruptedBase64(random: Random): string {
  const base: Record<string, unknown> = pick(random, [
    { v: 2, t: "hello", h: HANDLE, k: PUBLIC_KEY },
    { v: 2, t: "msg", h: HANDLE, i: 0, c: CIPHERTEXT },
  ]);
  const field = "k" in base ? "k" : "c";
  const encoded = String(base[field]);
  const at = between(random, 0, encoded.length - 1);

  const corrupted = pick(random, [
    encoded.slice(0, at),
    `${encoded.slice(0, at)}$${encoded.slice(at + 1)}`,
    `${encoded.slice(0, at)}=${encoded.slice(at + 1)}`,
    `${encoded}===`,
    encoded.replace(/=/g, ""),
    `${encoded} `,
  ]);

  return JSON.stringify({ ...base, [field]: corrupted });
}

// ---------------------------------------------------------------------------
// The run
// ---------------------------------------------------------------------------

export interface FuzzOptions {
  readonly budgetMs: number;
  /** Omitted, a seed is drawn and reported, so a run explores rather than
   * replaying the same inputs the last one already cleared. */
  readonly seed?: number;
  readonly targets?: readonly Target[];
}

export interface FuzzReport {
  readonly seed: number;
  readonly cases: number;
  readonly findings: readonly Finding[];
}

/** Generates until the budget runs out, driving every case through every
 * target. Budgeted in time rather than iterations so a slow machine runs fewer
 * cases instead of taking longer. */
export function fuzz(options: FuzzOptions): FuzzReport {
  const seed = options.seed ?? Math.floor(Math.random() * 0xffffffff);
  const targets = options.targets ?? TARGETS;
  const random = randomFrom(seed);
  const findings: Finding[] = [];
  const deadline = performance.now() + options.budgetMs;
  let cases = 0;

  while (performance.now() < deadline && findings.length < MAX_FINDINGS) {
    const generator = GENERATORS[cases % GENERATORS.length]!;
    const input = generator.produce(random);
    cases += 1;

    for (const target of targets) {
      const finding = check(target, input, generator.name);
      if (finding !== null) findings.push(finding);
    }
  }

  return { seed, cases, findings };
}

const USAGE = "usage: bun run scripts/fuzz-long.ts --budget <seconds> [--seed <n>]";

/** The shell: the only part of this file that reads argv, prints or exits. */
export function runCli(argv: string[]): number {
  const budgetSeconds = readNumber(argv, "--budget");
  const seed = readNumber(argv, "--seed");

  if (budgetSeconds === null || !(budgetSeconds > 0)) {
    console.error(`${USAGE}\n--budget is required and must be a positive number of seconds`);
    return 1;
  }

  if (seed !== null && !Number.isInteger(seed)) {
    console.error(`${USAGE}\n--seed must be an integer`);
    return 1;
  }

  const report = fuzz({ budgetMs: budgetSeconds * 1000, seed: seed ?? undefined });
  const summary = `fuzz: ${report.cases} cases over ${budgetSeconds}s, seed ${report.seed}`;

  if (report.findings.length === 0) {
    console.log(`${summary} — no findings`);
    return 0;
  }

  console.error(`${summary} — ${report.findings.length} findings`);
  for (const finding of report.findings) console.error(describeFinding(finding));
  console.error("commit each input under test/corpus/ so it is replayed from now on");
  return 1;
}

/** `null` when the flag is absent, `NaN` when its value is not a number — the
 * caller rejects both rather than guessing a default for a run somebody asked
 * for explicitly. */
function readNumber(argv: string[], flag: string): number | null {
  const at = argv.indexOf(flag);
  if (at === -1) return null;

  return Number(argv[at + 1]);
}

if (import.meta.main) process.exitCode = runCli(Bun.argv.slice(2));
