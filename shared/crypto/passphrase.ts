/**
 * Passphrase mode: two people who share a phrase, rather than a generated invite, meet in
 * a named room. docs/security-design.md §10 explains why this cannot be v1 again.
 *
 * The room name is routing and nothing more. It is not secret — the relay sees the handle
 * derived from it, and a common name can be guessed — so the handle never touches the
 * passphrase: a handle derived from the passphrase is exactly v1's offline oracle.
 *
 * The passphrase enters only CPace's generator. Room and phrase are normalised the way a
 * person would expect two typings to agree: NFKC and trimmed, and the room — but not the
 * phrase — also has its runs of spaces collapsed and its case folded. Lowercasing alone is
 * not a fold for Greek: "Σ" lowers to "ς" or "σ" depending on its neighbours, so the
 * final form is folded to "σ" afterwards.
 */

import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex } from "@noble/hashes/utils.js";
import {
  calculateGenerator,
  intermediateSessionKey,
  lvCat,
  sampleScalar,
  scalarMult,
  scalarMultVerified,
} from "./cpace.ts";
import { deriveSessionKeys, HandshakeError, refuseReflection, type Exchange } from "./handshake.ts";

// Wire contract: two clients with different labels never meet, and fail as if nobody
// were there. Each differs from every invite-mode label, so the two modes cannot collide.
export const ROOM_HANDLE_LABEL = "termino/room/v2";
export const PASSPHRASE_CHANNEL_LABEL = "termino/passphrase/v2";
export const PASSPHRASE_SESSION_LABEL = "termino/session/passphrase/v2";

const HANDLE_BYTES = 16;

export const ASSOCIATED_DATA_BYTES = 16;

// No session id is agreed before the exchange, which the draft allows (§10, [BGHJ24]);
// uniqueness comes from each side's fresh share and associated data instead.
const SID = new Uint8Array(0);

const utf8 = (text: string) => new TextEncoder().encode(text);

export function normalizeRoom(room: string): string {
  return room.normalize("NFKC").trim().replace(/\s+/gu, " ").toLowerCase().replaceAll("ς", "σ");
}

export function normalizePassphrase(passphrase: string): string {
  return passphrase.normalize("NFKC").trim();
}

export function deriveRoomHandle(room: string): string {
  return bytesToHex(
    hkdf(sha256, utf8(normalizeRoom(room)), undefined, utf8(ROOM_HANDLE_LABEL), HANDLE_BYTES),
  );
}

/** The point both sides build their shares on: the phrase picks it, within the room. */
export function passphraseGenerator(room: string, passphrase: string): Uint8Array {
  return generatorFor(room, passphrase).toBytes();
}

function generatorFor(room: string, passphrase: string) {
  return calculateGenerator(
    utf8(normalizePassphrase(passphrase)),
    lvCat(utf8(PASSPHRASE_CHANNEL_LABEL), utf8(normalizeRoom(room))),
    SID,
  );
}

export function passphraseExchange(room: string, passphrase: string): Exchange {
  const generator = generatorFor(room, passphrase);
  const scalar = sampleScalar();
  const share = scalarMult(scalar, generator);
  const associatedData = crypto.getRandomValues(new Uint8Array(ASSOCIATED_DATA_BYTES));

  return {
    publicKey: share,
    associatedData,

    complete(theirShare, theirAssociatedData) {
      if (theirAssociatedData === null || theirAssociatedData.length !== ASSOCIATED_DATA_BYTES) {
        throw new HandshakeError("the other side did not answer as a passphrase room does");
      }
      refuseReflection(share, theirShare);

      const sharedPoint = scalarMultVerified(scalar, theirShare);
      const isk = intermediateSessionKey(
        SID,
        sharedPoint,
        { share, ad: associatedData },
        { share: theirShare, ad: theirAssociatedData },
      );
      sharedPoint.fill(0);

      const keys = deriveSessionKeys(isk, undefined, PASSPHRASE_SESSION_LABEL, share, theirShare);
      isk.fill(0);

      return keys;
    },
  };
}
