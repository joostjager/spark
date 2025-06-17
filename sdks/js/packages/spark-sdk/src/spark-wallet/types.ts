import type { Transaction } from "@scure/btc-signer";
import { ConfigOptions } from "../services/wallet-config.js";
import type { SparkSigner } from "../signer/signer.js";

export type CreateLightningInvoiceParams = {
  amountSats: number;
  memo?: string;
  expirySeconds?: number;
  includeSparkAddress?: boolean;
  receiverIdentityPubkey?: string;
  descriptionHash?: string;
};

export type PayLightningInvoiceParams = {
  invoice: string;
  maxFeeSats: number;
  preferSpark?: boolean;
};

export type TransferParams = {
  amountSats: number;
  receiverSparkAddress: string;
};

export type DepositParams = {
  signingPubKey: Uint8Array;
  verifyingKey: Uint8Array;
  depositTx: Transaction;
  vout: number;
};

export type TokenInfo = {
  tokenPublicKey: string;
  tokenName: string;
  tokenSymbol: string;
  tokenDecimals: number;
  maxSupply: bigint;
};

export type InitWalletResponse = {
  mnemonic?: string | undefined;
};
export interface SparkWalletProps {
  mnemonicOrSeed?: Uint8Array | string;
  accountNumber?: number;
  signer?: SparkSigner;
  options?: ConfigOptions;
}

export interface SparkWalletEvents {
  /** Emitted when an incoming transfer is successfully claimed. Includes the transfer ID and new total balance. */
  "transfer:claimed": (transferId: string, updatedBalance: number) => void;
  /** Emitted when a deposit is marked as available. Includes the deposit ID and new total balance. */
  "deposit:confirmed": (depositId: string, updatedBalance: number) => void;
  /** Emitted when the stream is connected */
  "stream:connected": () => void;
  /** Emitted when the stream disconnects and fails to reconnect after max attempts */
  "stream:disconnected": (reason: string) => void;
  /** Emitted when attempting to reconnect the stream */
  "stream:reconnecting": (
    attempt: number,
    maxAttempts: number,
    delayMs: number,
    error: string,
  ) => void;
}
