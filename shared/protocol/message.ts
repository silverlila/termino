/**
 * The inner message: what travels encrypted, invisible to the relay.
 *
 * `JSON.stringify` recurses — roughly 200 ms at 22k nesting depth, and it throws
 * RangeError near 100k — so no error path here may stringify a value it is rejecting.
 * `describe()` names the shape instead.
 *
 * `payloadProblem` must be called before a counter is spent.
 */

import { pad, unpad } from "../crypto/pad.ts";
import type { MessageKey } from "../crypto/ratchet.ts";
import { open, seal } from "../crypto/seal.ts";
import { fromBase64, msgFrame, type MsgFrame } from "./frame.ts";
import { bodyProblem, nickProblem } from "./text.ts";

const utf8 = (text: string) => new TextEncoder().encode(text);

const PAYLOAD_TYPES = ["text", "ping", "confirm"] as const;
type PayloadType = (typeof PAYLOAD_TYPES)[number];

export interface TextPayload {
  t: "text";
  nick: string;
  body: string;
}

export interface PingPayload {
  t: "ping";
  nick: string;
}

export interface ConfirmPayload {
  t: "confirm";
  nick: string;
}

export type Payload = TextPayload | PingPayload | ConfirmPayload;

export class PayloadError extends Error {
  constructor(reason: string) {
    super(`invalid payload: ${reason}`);
  }
}

export function payloadProblem(payload: Payload): string | null {
  const problem = nickProblem(payload.nick);
  if (problem !== null) return problem;

  if (payload.t !== "text") return null;

  return bodyProblem(payload.body);
}

export async function sealMessage(
  messageKey: MessageKey,
  handle: string,
  counter: number,
  payload: Payload,
): Promise<MsgFrame> {
  const problem = payloadProblem(payload);
  if (problem !== null) throw new PayloadError(problem);

  const ciphertext = await seal(
    messageKey.key,
    messageKey.nonce,
    pad(utf8(JSON.stringify(payload))),
  );

  return msgFrame(handle, counter, ciphertext);
}

export async function openMessage(messageKey: MessageKey, frame: MsgFrame): Promise<Payload> {
  const plaintext = await open(messageKey.key, messageKey.nonce, fromBase64(frame.c));

  return parsePayload(new TextDecoder().decode(unpad(plaintext)));
}

export function parsePayload(text: string): Payload {
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new PayloadError("not JSON");
  }

  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    throw new PayloadError("not a JSON object");
  }

  const fields = parsed as Record<string, unknown>;
  const type = readType(fields.t);
  const nick = readText(fields.nick, "nick", nickProblem);

  if (type !== "text") {
    if ("body" in fields) throw new PayloadError(`a ${type} payload carries no body`);
    return { t: type, nick };
  }

  return { t: "text", nick, body: readText(fields.body, "body", bodyProblem) };
}

function readType(value: unknown): PayloadType {
  const known = PAYLOAD_TYPES.find((type) => type === value);
  if (known === undefined) throw new PayloadError(`unknown payload type ${describe(value)}`);
  return known;
}

function describe(value: unknown): string {
  if (typeof value === "object" && value !== null) {
    return Array.isArray(value) ? "an array" : "an object";
  }

  return JSON.stringify(value) ?? "undefined";
}

function readText(
  value: unknown,
  field: string,
  problemOf: (text: string) => string | null,
): string {
  if (typeof value !== "string") throw new PayloadError(`${field} is not a string`);

  const problem = problemOf(value);
  if (problem !== null) throw new PayloadError(problem);

  return value;
}
