import { pad, unpad } from "../crypto/pad.ts";
import type { MessageKey } from "../crypto/ratchet.ts";
import { open, seal } from "../crypto/seal.ts";
import { fromBase64, msgFrame, type MsgFrame } from "./frame.ts";
import { bodyProblem, nickProblem } from "./text.ts";

/**
 * The inner payload: what actually gets encrypted, and what the relay never
 * sees.
 *
 * There is no signature and no sender key. The session key is pairwise between
 * exactly two participants and each direction has its own chain, so a payload
 * that opens under the receiving chain was written by the one other party who
 * holds it — the AEAD tag is the authenticator. A per-message signature on top
 * would need a persistent identity, which is the thing this protocol does not
 * have.
 *
 * There is no timestamp either. Nothing trusted the sender's clock even when
 * one was carried; the receiver's arrival time is the only clock it can vouch
 * for.
 *
 * No error path here may `JSON.stringify` a value it is rejecting. `stringify`
 * recurses, so a deeply nested payload costs the receiver real time and then
 * throws `RangeError` — inside the code whose only job was to refuse it, and
 * out through a parser that promises to throw `PayloadError` and nothing else.
 * `describe` names the shape instead. The two nested-* files under test/corpus
 * hold that line.
 */

const utf8 = (text: string) => new TextEncoder().encode(text);

/** What a payload can be. An unrecognised type is rejected rather than
 * ignored, exactly as an unknown frame version is. */
const PAYLOAD_TYPES = ["text", "ping", "confirm"] as const;
type PayloadType = (typeof PAYLOAD_TYPES)[number];

/** Something a person said. */
export interface TextPayload {
  t: "text";
  nick: string;
  body: string;
}

/** Presence, asserted by the peer rather than by the relay: it opens under the
 * receiving chain, so only the other participant can have sent it. */
export interface PingPayload {
  t: "ping";
  nick: string;
}

/**
 * The first payload either side sends, at counter 0 of its own chain. It is
 * what proves the handshake reached the same keys on both ends — without it a
 * mismatched secret produces silence, and silence is indistinguishable from
 * nobody having typed anything yet. It is also where each side learns the
 * peer's nickname.
 */
export interface ConfirmPayload {
  t: "confirm";
  nick: string;
}

export type Payload = TextPayload | PingPayload | ConfirmPayload;

/** Thrown when a payload does not have the shape a payload must have. */
export class PayloadError extends Error {
  constructor(readonly reason: string) {
    super(`invalid payload: ${reason}`);
  }
}

/**
 * Why this payload cannot be sent, or `null` if it can.
 *
 * Separate from `sealMessage` because a sender must find out *before* it spends
 * a counter on the message: the counter cannot be handed back, and a burnt one
 * arrives at the far end as a gap in the conversation.
 */
export function payloadProblem(payload: Payload): string | null {
  const problem = nickProblem(payload.nick);
  if (problem !== null) return problem;

  if (payload.t !== "text") return null;

  return bodyProblem(payload.body);
}

/**
 * Pads, then encrypts, then wraps in the outer frame — in that order.
 *
 * The text rules are applied here as well as on arrival, so this client cannot
 * be the one sending a body that every honest recipient will refuse.
 *
 * Padding wraps the serialised payload rather than the body, because the body
 * is not what the relay measures — the sealed JSON is. `seal` itself stays
 * generic and knows nothing about any of this.
 */
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

/**
 * Decrypts and validates one inbound frame. Throws `DecryptError` if the
 * ciphertext does not authenticate, `PaddingError` if what it decrypts to is
 * not padded the way this protocol pads, and `PayloadError` if it decrypts to
 * something that is not a payload. Only a fully validated payload is returned.
 */
export async function openMessage(messageKey: MessageKey, frame: MsgFrame): Promise<Payload> {
  const plaintext = await open(messageKey.key, messageKey.nonce, fromBase64(frame.c));

  return parsePayload(new TextDecoder().decode(unpad(plaintext)));
}

/**
 * Exported for the fuzzer, which drives it directly: `openMessage` also throws
 * `DecryptError` and `PaddingError`, so "only `PayloadError` escapes" is a claim
 * that can only be made about this function. Nothing outside `openMessage`
 * should call it — a payload that has not been through the AEAD is not a
 * payload, whatever shape it has.
 */
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

  // Rebuilt field by field rather than spread from what arrived: anything the
  // sender added — a `from`, a `ts`, a field a later version invents — stops
  // here rather than travelling on into the client as if this layer had
  // checked it.
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

/**
 * The last point at which a hostile body can be stopped. Everything below this
 * treats what comes back as text; `text.ts` decides what text means.
 */
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
