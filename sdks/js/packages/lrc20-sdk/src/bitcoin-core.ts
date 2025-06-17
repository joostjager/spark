import { initEccLib } from "bitcoinjs-lib";
import * as ecc from "@bitcoinerlab/secp256k1";
import { secp256k1, schnorr } from "@noble/curves/secp256k1";
import type { Network } from "bitcoinjs-lib";
import { bytesToHex as b2h } from "@noble/hashes/utils";

initEccLib(ecc);

/** Buffer ∣ Uint8Array → Uint8Array (zero-copy when possible) */
const toU8 = (b: Buffer | Uint8Array): Uint8Array => (b instanceof Uint8Array ? b : new Uint8Array(b));

/** Uint8Array → bigint */
const bn = (b: Buffer | Uint8Array): bigint => BigInt("0x" + b2h(toU8(b)));

/** bigint → 32-byte Buffer (big-endian, zero-padded) */
const bnToBuf = (n: bigint): Buffer => Buffer.from(n.toString(16).padStart(64, "0"), "hex");

export type KeyPair = {
  publicKey: Buffer;
  privateKey?: Buffer;
  network?: Network;
  compressed: true;
  sign(hash: Buffer): Buffer;
  signSchnorr(hash: Buffer): Buffer;
  verify(hash: Buffer, sig: Buffer): boolean;
  verifySchnorr(hash: Buffer, sig: Buffer): boolean;
};

function makeKeyPair(priv?: Buffer, pub?: Buffer, network?: Network): KeyPair {
  if (!priv && !pub) {
    throw new Error("Either priv or pub must be supplied");
  }

  // Derive compressed SEC public key if we possess the private half.
  const publicKey = pub ?? Buffer.from(secp256k1.getPublicKey(toU8(priv!), true));

  const sign = (hash: Buffer): Buffer => {
    if (!priv) throw new Error("Private key required for signing");
    const sigObj = secp256k1.sign(toU8(hash), toU8(priv));
    return Buffer.from(sigObj.toCompactRawBytes());
  };

  const signSchnorr = (hash: Buffer): Buffer => {
    if (!priv) throw new Error("Private key required for Schnorr signing");
    return Buffer.from(schnorr.sign(toU8(hash), toU8(priv)));
  };

  const verify = (hash: Buffer, signature: Buffer): boolean => {
    try {
      const sig = secp256k1.Signature.fromDER(toU8(signature));
      return secp256k1.verify(sig, toU8(hash), toU8(publicKey));
    } catch {
      return false;
    }
  };

  const verifySchnorr = (hash: Buffer, signature: Buffer): boolean =>
    schnorr.verify(toU8(signature), toU8(hash), toU8(publicKey));

  return {
    publicKey,
    privateKey: priv,
    network,
    compressed: true,
    sign,
    signSchnorr,
    verify,
    verifySchnorr,
  };
}

/** Create a full key-pair from a 32-byte secret. */
export const fromPrivateKey = (privKey: Buffer, opts: { network?: Network } = {}): KeyPair =>
  makeKeyPair(privKey, undefined, opts.network);

/** Create a watch-only key from a compressed SEC public key. */
export const fromPublicKey = (pubKey: Buffer, opts: { network?: Network } = {}): KeyPair =>
  makeKeyPair(undefined, pubKey, opts.network);
