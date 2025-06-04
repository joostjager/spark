export type TokenActivityResponse = {
  transactions: Transaction[];
  nextCursor?: ListAllTokenTransactionsCursor | undefined;
};

export interface Transaction {
  transaction?:
    | {
        $case: "onChain";
        onChain: OnChainTransaction;
      }
    | {
        $case: "spark";
        spark: SparkTransaction;
      }
    | undefined;
}

export interface TokenPubKeyInfoResponse {
  announcement: {
    tokenPubkey: {
      pubkey: string;
    };
    name: string;
    symbol: string;
    decimal: number;
    maxSupply: bigint;
    isFreezable: boolean;
  } | null;
  totalSupply: bigint;
}

export interface OnChainTokenOutput {
  rawTx: string;
  vout: number;
  amountSats: number;
  tokenPublicKey?: string | undefined;
  tokenAmount?: string | undefined;
}
export interface OnChainTransaction {
  operationType: string;
  transactionHash: string;
  rawtx: string;
  status: string;
  inputs: OnChainTokenOutput[];
  outputs: OnChainTokenOutput[];
  broadcastedAt: Date | undefined;
  confirmedAt: Date | undefined;
}
export interface SparkTransaction {
  operationType: string;
  transactionHash: string;
  status: string;
  confirmedAt: Date | undefined;
  leavesToCreate: SparkLeaf[];
  leavesToSpend: SparkLeaf[];
  sparkOperatorIdentityPublicKeys: string[];
}
export interface SparkLeaf {
  tokenPublicKey: string;
  id: string;
  ownerPublicKey: string;
  revocationPublicKey: string;
  withdrawalBondSats: number;
  withdrawalLocktime: number;
  tokenAmount: string;
  createTxHash: string;
  createTxVoutIndex: number;
  spendTxHash?: string | undefined;
  spendTxVoutIndex?: number | undefined;
  isFrozen?: boolean | undefined;
}

export interface ListAllTokenTransactionsCursor {
  lastTransactionHash: string;
  layer: string;
}

export interface TokenDistribution {
  totalCirculatingSupply: bigint;
  totalIssued: bigint;
  totalBurned: bigint;
  numHoldingAddress: number;
  numConfirmedTransactions: bigint;
}
