import { BigNumber } from "bignumber.js";
import * as bitcoin from "bitcoinjs-lib";
import { fromPrivateKey, fromPublicKey } from "./bitcoin-core.ts";

export const toXOnly = (pubKey: Buffer) => (pubKey.length === 32 ? pubKey : pubKey.slice(1, 33));

function tapTweakHash(pubKey: Buffer, h: Buffer | undefined): Buffer {
  return bitcoin.crypto.taggedHash("TapTweak", Buffer.concat(h ? [pubKey, h] : [pubKey]));
}

/**
 * ECDSA signature validator
 */
export const validator = (pubkey: Buffer, msghash: Buffer, signature: Buffer): boolean =>
  fromPublicKey(pubkey).verify(msghash, signature);

/**
 * Schnorr signature validator
 */
export const schnorrValidator = (pubkey: Buffer, msghash: Buffer, signature: Buffer): boolean => {
  return fromPublicKey(pubkey).verifySchnorr(msghash, signature);
};

/**
 * Transform satoshis to btc format
 */
export function satoshisToAmount(val: number) {
  const num = new BigNumber(val);
  return num.dividedBy(100000000).toFixed(8);
}

/**
 * Transform btc format to satoshis
 */
export function amountToSaothis(val: any) {
  const num = new BigNumber(val);
  return num.multipliedBy(100000000).toNumber();
}
