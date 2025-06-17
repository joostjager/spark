import { schnorr, secp256k1 } from "@noble/curves/secp256k1";
import { bytesToHex, hexToBytes } from "@noble/curves/abstract/utils";
import { HDKey } from "@scure/bip32";
import { Psbt } from "bitcoinjs-lib";
import { Receipt } from "../types/receipt.ts";
import { PARITY } from "../utils/index.ts";
import { privateNegate, privateAdd } from "@bitcoinerlab/secp256k1";
import * as bitcoin from "bitcoinjs-lib";
import { fromPrivateKey } from "../../bitcoin-core.ts";
import { generateMnemonic } from "@scure/bip39";
import { wordlist } from "@scure/bip39/wordlists/english";
import * as bip39 from "@scure/bip39";

export enum Network {
  MAINNET,
  TESTNET,
  SIGNET,
  REGTEST,
  LOCAL,
}

interface TokenSigner {
  getIdentityPublicKey(): Promise<Uint8Array>;

  signMessageWithIdentityKey(message: Uint8Array, compact?: boolean): Promise<Uint8Array>;

  signSchnorrWithIdentityKey(message: Uint8Array, compact?: boolean): Promise<Uint8Array>;

  generateMnemonic(): Promise<string>;

  createSparkWalletFromSeed(seed: Uint8Array | string, network: Network): Promise<string>;

  mnemonicToSeed(mnemonic: string): Promise<Uint8Array>;

  signPsbt(psbt: Psbt, input: number, sighashTypes?: number[], receipt?: Receipt): Promise<Psbt>;
}

class DefaultTokenSigner implements TokenSigner {
  private identityKey: HDKey | null = null;

  async getIdentityPublicKey(): Promise<Uint8Array> {
    if (!this.identityKey?.publicKey) {
      throw new Error("Private key is not set");
    }

    return this.identityKey.publicKey;
  }

  async generateMnemonic(): Promise<string> {
    return generateMnemonic(wordlist);
  }

  async createSparkWalletFromSeed(seed: Uint8Array | string, network: Network): Promise<string> {
    if (typeof seed === "string") {
      seed = hexToBytes(seed);
    }

    this.identityKey = HDKey.fromMasterSeed(seed);

    if (!this.identityKey.privateKey || !this.identityKey.publicKey) {
      throw new Error("Failed to derive keys from seed");
    }

    return bytesToHex(this.identityKey.publicKey);
  }

  async mnemonicToSeed(mnemonic: string): Promise<Uint8Array> {
    return await bip39.mnemonicToSeed(mnemonic);
  }

  async signMessageWithIdentityKey(message: Uint8Array, compact?: boolean): Promise<Uint8Array> {
    if (!this.identityKey?.privateKey) {
      throw new Error("Private key is not set");
    }

    const signature = secp256k1.sign(message, this.identityKey.privateKey);

    if (compact) {
      return signature.toCompactRawBytes();
    }

    return signature.toDERRawBytes();
  }

  async signSchnorrWithIdentityKey(message: Uint8Array): Promise<Uint8Array> {
    if (!this.identityKey?.privateKey) {
      throw new Error("Identity key not initialized");
    }

    const signature = schnorr.sign(message, this.identityKey.privateKey);
    return signature;
  }

  async signPsbt(psbt: Psbt, input: number, sighashTypes?: number[], receipt?: Receipt): Promise<Psbt> {
    if (!this.identityKey?.privateKey) {
      throw new Error("Identity key not initialized");
    }

    if (receipt) {
      const receiptPrivateKey = this.getReceiptPrivateKey(receipt);
      const tweakedKeyPair = fromPrivateKey(Buffer.from(receiptPrivateKey));
      psbt.signInput(input, tweakedKeyPair, sighashTypes);
      return psbt;
    }
    const keypair = fromPrivateKey(Buffer.from(this.identityKey!.privateKey));
    psbt.signInput(input, keypair, sighashTypes);
    return psbt;
  }

  private getReceiptPrivateKey(receipt: Receipt): Uint8Array {
    const pxh = Receipt.receiptHash(receipt);
    let innerKey = this.identityKey.publicKey!;
    let privateKey = this.identityKey.privateKey!;

    if (innerKey[0] === 3) {
      innerKey = Buffer.concat([PARITY, innerKey.slice(1)]);
      privateKey = Buffer.from(privateNegate(privateKey));
    }

    const pxhPubkey = bitcoin.crypto.sha256(Buffer.concat([pxh, innerKey]));

    const receiptProof = privateAdd(privateKey, pxhPubkey)!;
    return Buffer.from(receiptProof);
  }
}

export { DefaultTokenSigner, type TokenSigner };
