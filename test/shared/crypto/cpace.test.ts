import { describe, expect, it } from "bun:test";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import {
  calculateGenerator,
  CPaceError,
  intermediateSessionKey,
  lvCat,
  sampleScalar,
  scalarFromBytes,
  scalarMult,
  scalarMultVerified,
} from "../../../shared/crypto/cpace.ts";

const utf8 = (text: string) => new TextEncoder().encode(text);

const PRS = utf8("Password");
const CI = hexToBytes("0b415f696e69746961746f720b425f726573706f6e646572");
const SID = hexToBytes("7e4b4791d6a8ef019b936c79fb7f2c57");

const YA = scalarFromBytes(hexToBytes("da3d23700a9e5699258aef94dc060dfda5ebb61f02a5ea77fad53f4ff0976d08"));
const YB = scalarFromBytes(hexToBytes("d2316b454718c35362d83d69df6320f38578ed5984651435e2949762d900b80d"));

const SHARE_A = "d6bac480f2c386c394efc7c47adb9925dcd2630b64f240c50f8d0eec482b9157";
const SHARE_B = "3ea7e0b19560d7c0b0f5734f63b955286dfa8232b5ebe63324e2d9e7433f7258";
const SHARED_POINT = "80b69a8a76457ab6a4d7f887a4bf6b55a2f80ac19c333f917a05fc9887c8b40f";

describe("the length-value encoding", () => {
  it("prefixes each part with its LEB128 length (A.1.2)", () => {
    expect(bytesToHex(lvCat(new Uint8Array()))).toBe("00");
    expect(bytesToHex(lvCat(utf8("1234")))).toBe("0431323334");
    const range = (length: number) => Uint8Array.from({ length }, (_, index) => index);
    expect(lvCat(range(127)).length).toBe(128);
    expect(bytesToHex(lvCat(range(127))).slice(0, 6)).toBe("7f0001");
    expect(lvCat(range(128)).length).toBe(130);
    expect(bytesToHex(lvCat(range(128))).slice(0, 8)).toBe("80010001");
  });
});

describe("the generator", () => {
  it("matches B.3.1", () => {
    expect(bytesToHex(calculateGenerator(PRS, CI, SID).toBytes())).toBe(
      "222b6b195fe84b1652badb6f6a3ae3d24341e7306967f0b8115b40d5698c7e56",
    );
  });

  it("differs for a different password, which is the whole mechanism", () => {
    const other = calculateGenerator(utf8("Passwore"), CI, SID);
    expect(bytesToHex(other.toBytes())).not.toBe(
      "222b6b195fe84b1652badb6f6a3ae3d24341e7306967f0b8115b40d5698c7e56",
    );
  });
});

describe("the shares and the shared point", () => {
  const generator = calculateGenerator(PRS, CI, SID);

  it("matches B.3.2 and B.3.3", () => {
    expect(bytesToHex(scalarMult(YA, generator))).toBe(SHARE_A);
    expect(bytesToHex(scalarMult(YB, generator))).toBe(SHARE_B);
  });

  it("matches B.3.4 from either side", () => {
    expect(bytesToHex(scalarMultVerified(YA, hexToBytes(SHARE_B)))).toBe(SHARED_POINT);
    expect(bytesToHex(scalarMultVerified(YB, hexToBytes(SHARE_A)))).toBe(SHARED_POINT);
  });

  it("matches B.3.10 for an arbitrary valid point", () => {
    const scalar = scalarFromBytes(
      hexToBytes("7cd0e075fa7955ba52c02759a6c90dbbfc10e6d40aea8d283e407d88cf538a05"),
    );
    const point = hexToBytes("2c3c6b8c4f3800e7aef6864025b4ed79bd599117e427c41bd47d93d654b4a51c");

    expect(bytesToHex(scalarMultVerified(scalar, point))).toBe(
      "7c13645fe790a468f62c39beb7388e541d8405d1ade69d1778c5fe3e7f6b600e",
    );
  });
});

describe("a share that must abort the exchange (B.3.11)", () => {
  const scalar = scalarFromBytes(
    hexToBytes("7cd0e075fa7955ba52c02759a6c90dbbfc10e6d40aea8d283e407d88cf538a05"),
  );

  it("refuses an encoding that is not a point", () => {
    const notAPoint = hexToBytes("2b3c6b8c4f3800e7aef6864025b4ed79bd599117e427c41bd47d93d654b4a51c");
    expect(() => scalarMultVerified(scalar, notAPoint)).toThrow(CPaceError);
  });

  it("refuses the identity", () => {
    expect(() => scalarMultVerified(scalar, new Uint8Array(32))).toThrow(/identity/);
  });
});

describe("the intermediate session key", () => {
  it("matches B.3.6, the transcript for two sides with no fixed roles", () => {
    const a = { share: hexToBytes(SHARE_A), ad: utf8("ADa") };
    const b = { share: hexToBytes(SHARE_B), ad: utf8("ADb") };
    const expected =
      "544199d71f62f8d9a1fee55727e24fe4a45844593c2b6013c4fa3969d0e5debb" +
      "2244675c0b43397cbb68d342b01fc0f98fc961469a25134de9f0f813c1a57476";

    expect(bytesToHex(intermediateSessionKey(SID, hexToBytes(SHARED_POINT), a, b))).toBe(expected);
    expect(bytesToHex(intermediateSessionKey(SID, hexToBytes(SHARED_POINT), b, a))).toBe(expected);
  });
});

describe("a fresh scalar", () => {
  it("is never zero, never at or above the group order, and never repeats", () => {
    const seen = new Set<bigint>();
    for (let drawn = 0; drawn < 64; drawn++) {
      const scalar = sampleScalar();
      expect(scalar > 0n).toBe(true);
      expect(scalar < 2n ** 253n).toBe(true);
      seen.add(scalar);
    }
    expect(seen.size).toBe(64);
  });
});
