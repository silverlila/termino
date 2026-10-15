/**
 * Passphrase rooms: a room name and a phrase both people know, in place of a generated
 * invite.
 *
 * The room name is routing only: it is not secret, and the relay sees the handle derived
 * from it. The handle never touches the passphrase, because a handle derived from the
 * passphrase is v1's offline oracle (docs/security-design.md §10). The passphrase enters
 * only CPace's generator.
 *
 * CPace runs with an empty sid, which the draft allows (§10, [BGHJ24]); uniqueness comes
 * from each side's fresh share and associated data.
 *
 * `toLowerCase` does not fold Greek: "Σ" lowers to "ς" or "σ" depending on its
 * neighbours, so final sigma is mapped to "σ" afterwards.
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

export const ROOM_HANDLE_LABEL = "termino/room/v2";
export const PASSPHRASE_CHANNEL_LABEL = "termino/passphrase/v2";
export const PASSPHRASE_SESSION_LABEL = "termino/session/passphrase/v2";

const HANDLE_BYTES = 16;

export const ASSOCIATED_DATA_BYTES = 16;

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
