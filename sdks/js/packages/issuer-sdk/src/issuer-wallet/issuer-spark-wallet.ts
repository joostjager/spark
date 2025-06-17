import { TokenPubkey, TokenPubkeyAnnouncement } from "@buildonspark/lrc20-sdk";
import {
  NetworkError,
  SparkWallet,
  SparkWalletProps,
  ValidationError,
} from "@buildonspark/spark-sdk";
import { isNode } from "@lightsparkdev/core";
import {
  decodeSparkAddress,
  encodeSparkAddress,
} from "@buildonspark/spark-sdk/address";
import {
  OutputWithPreviousTransactionData,
  TokenTransaction as TokenTransactionV0,
} from "@buildonspark/spark-sdk/proto/spark";
import { TokenTransaction } from "@buildonspark/spark-sdk/proto/spark_token";
import { ConfigOptions } from "@buildonspark/spark-sdk/services/wallet-config";
import {
  bytesToHex,
  bytesToNumberBE,
  hexToBytes,
} from "@noble/curves/abstract/utils";
import { TokenFreezeService } from "../services/freeze.js";
import { IssuerTokenTransactionService } from "../services/token-transactions.js";
import { TokenActivityResponse, TokenDistribution } from "../types.js";
import { convertToTokenActivity } from "../utils/type-mappers.js";
import { NotImplementedError } from "@buildonspark/spark-sdk";
import {
  Layer,
  ListAllTokenTransactionsCursor,
  OperationType,
} from "@buildonspark/spark-sdk/proto/lrc20";
import { SparkSigner } from "@buildonspark/spark-sdk/signer";

const BURN_ADDRESS = "02".repeat(33);

export type IssuerTokenInfo = {
  tokenPublicKey: string;
  tokenName: string;
  tokenSymbol: string;
  tokenDecimals: number;
  maxSupply: bigint;
  isFreezable: boolean;
  totalSupply: bigint;
};

/**
 * Represents a Spark wallet with minting capabilities.
 * This class extends the base SparkWallet with additional functionality for token minting,
 * burning, and freezing operations.
 */
export class IssuerSparkWallet extends SparkWallet {
  private issuerTokenTransactionService: IssuerTokenTransactionService;
  private tokenFreezeService: TokenFreezeService;
  protected tracerId = "issuer-sdk";

  /**
   * Initializes a new IssuerSparkWallet instance.
   * @param options - Configuration options for the wallet
   * @returns An object containing the initialized wallet and initialization response
   */
  public static async initialize({
    mnemonicOrSeed,
    accountNumber,
    signer,
    options,
  }: SparkWalletProps) {
    const wallet = new IssuerSparkWallet(options, signer);

    const initResponse = await wallet.initWallet(mnemonicOrSeed, accountNumber);

    if (isNode) {
      wallet.wrapIssuerSparkWalletWithTracing();
    }

    return {
      wallet,
      ...initResponse,
    };
  }

  private wrapIssuerSparkWalletWithTracing() {
    this.getIssuerTokenBalance = this.wrapWithOtelSpan(
      "SparkIssuerWallet.getIssuerTokenBalance",
      this.getIssuerTokenBalance.bind(this),
    );
    this.getIssuerTokenInfo = this.wrapWithOtelSpan(
      "SparkIssuerWallet.getIssuerTokenInfo",
      this.getIssuerTokenInfo.bind(this),
    );
    this.mintTokens = this.wrapWithOtelSpan(
      "SparkIssuerWallet.mintTokens",
      this.mintTokens.bind(this),
    );
    this.burnTokens = this.wrapWithOtelSpan(
      "SparkIssuerWallet.burnTokens",
      this.burnTokens.bind(this),
    );
    this.freezeTokens = this.wrapWithOtelSpan(
      "SparkIssuerWallet.freezeTokens",
      this.freezeTokens.bind(this),
    );
    this.unfreezeTokens = this.wrapWithOtelSpan(
      "SparkIssuerWallet.unfreezeTokens",
      this.unfreezeTokens.bind(this),
    );
    this.getIssuerTokenActivity = this.wrapWithOtelSpan(
      "SparkIssuerWallet.getIssuerTokenActivity",
      this.getIssuerTokenActivity.bind(this),
    );
    this.getIssuerTokenDistribution = this.wrapWithOtelSpan(
      "SparkIssuerWallet.getIssuerTokenDistribution",
      this.getIssuerTokenDistribution.bind(this),
    );
    this.announceTokenL1 = this.wrapWithOtelSpan(
      "SparkIssuerWallet.announceTokenL1",
      this.announceTokenL1.bind(this),
    );
  }

  protected constructor(configOptions?: ConfigOptions, signer?: SparkSigner) {
    super(configOptions, signer);
    this.issuerTokenTransactionService = new IssuerTokenTransactionService(
      this.config,
      this.connectionManager,
    );
    this.tokenFreezeService = new TokenFreezeService(
      this.config,
      this.connectionManager,
    );
  }

  /**
   * Gets the token balance for the issuer's token.
   * @returns An object containing the token balance as a bigint
   */
  public async getIssuerTokenBalance(): Promise<{
    balance: bigint;
  }> {
    const publicKey = await super.getIdentityPublicKey();
    const balanceObj = await this.getBalance();

    if (!balanceObj.tokenBalances || !balanceObj.tokenBalances.has(publicKey)) {
      return {
        balance: 0n,
      };
    }
    return {
      balance: balanceObj.tokenBalances.get(publicKey)!.balance,
    };
  }

  /**
   * Retrieves information about the issuer's token.
   * @returns An object containing token information including public key, name, symbol, decimals, max supply, and freeze status
   * @throws {NetworkError} If the token info cannot be retrieved
   */
  public async getIssuerTokenInfo(): Promise<IssuerTokenInfo | null> {
    const lrc20Client = await this.lrc20ConnectionManager.createLrc20Client();

    try {
      const tokenInfo = await lrc20Client.getTokenPubkeyInfo({
        publicKeys: [hexToBytes(await super.getIdentityPublicKey())],
      });

      const info = tokenInfo.tokenPubkeyInfos[0];
      return {
        tokenPublicKey: bytesToHex(info.announcement!.publicKey!.publicKey),
        tokenName: info.announcement!.name,
        tokenSymbol: info.announcement!.symbol,
        tokenDecimals: Number(bytesToNumberBE(info.announcement!.decimal)),
        isFreezable: info.announcement!.isFreezable,
        maxSupply: bytesToNumberBE(info.announcement!.maxSupply),
        totalSupply: bytesToNumberBE(info.totalSupply),
      };
    } catch (error) {
      throw new NetworkError("Failed to get token info", {
        operation: "getIssuerTokenInfo",
        errorCount: 1,
        errors: error instanceof Error ? error.message : String(error),
      });
    }
  }

  /**
   * Mints new tokens
   * @param tokenAmount - The amount of tokens to mint
   * @returns The transaction ID of the mint operation
   */
  public async mintTokens(tokenAmount: bigint): Promise<string> {
    const tokenPublicKey = await super.getIdentityPublicKey();
    let tokenTransaction: TokenTransactionV0 | TokenTransaction;

    if (this.config.getTokenTransactionVersion() === "V0") {
      tokenTransaction =
        await this.issuerTokenTransactionService.constructMintTokenTransactionV0(
          hexToBytes(tokenPublicKey),
          tokenAmount,
        );
    } else {
      tokenTransaction =
        await this.issuerTokenTransactionService.constructMintTokenTransaction(
          hexToBytes(tokenPublicKey),
          tokenAmount,
        );
    }

    return await this.issuerTokenTransactionService.broadcastTokenTransaction(
      tokenTransaction,
    );
  }

  /**
   * Burns issuer's tokens
   * @param tokenAmount - The amount of tokens to burn
   * @param selectedOutputs - Optional array of outputs to use for the burn operation
   * @returns The transaction ID of the burn operation
   */
  public async burnTokens(
    tokenAmount: bigint,
    selectedOutputs?: OutputWithPreviousTransactionData[],
  ): Promise<string> {
    const burnAddress = encodeSparkAddress({
      identityPublicKey: BURN_ADDRESS,
      network: this.config.getNetworkType(),
    });
    return await this.transferTokens({
      tokenPublicKey: await super.getIdentityPublicKey(),
      tokenAmount,
      receiverSparkAddress: burnAddress,
      selectedOutputs,
    });
  }

  /**
   * Freezes tokens associated with a specific Spark address.
   * @param sparkAddress - The Spark address whose tokens should be frozen
   * @returns An object containing the IDs of impacted outputs and the total amount of frozen tokens
   */
  public async freezeTokens(
    sparkAddress: string,
  ): Promise<{ impactedOutputIds: string[]; impactedTokenAmount: bigint }> {
    await this.syncTokenOutputs();
    const tokenPublicKey = await super.getIdentityPublicKey();
    const decodedOwnerPubkey = decodeSparkAddress(
      sparkAddress,
      this.config.getNetworkType(),
    );
    const response = await this.tokenFreezeService!.freezeTokens(
      hexToBytes(decodedOwnerPubkey.identityPublicKey),
      hexToBytes(tokenPublicKey),
    );

    // Convert the Uint8Array to a bigint
    const tokenAmount = bytesToNumberBE(response.impactedTokenAmount);

    return {
      impactedOutputIds: response.impactedOutputIds,
      impactedTokenAmount: tokenAmount,
    };
  }

  /**
   * Unfreezes previously frozen tokens associated with a specific Spark address.
   * @param sparkAddress - The Spark address whose tokens should be unfrozen
   * @returns An object containing the IDs of impacted outputs and the total amount of unfrozen tokens
   */
  public async unfreezeTokens(
    sparkAddress: string,
  ): Promise<{ impactedOutputIds: string[]; impactedTokenAmount: bigint }> {
    await this.syncTokenOutputs();
    const tokenPublicKey = await super.getIdentityPublicKey();
    const decodedOwnerPubkey = decodeSparkAddress(
      sparkAddress,
      this.config.getNetworkType(),
    );
    const response = await this.tokenFreezeService!.unfreezeTokens(
      hexToBytes(decodedOwnerPubkey.identityPublicKey),
      hexToBytes(tokenPublicKey),
    );
    const tokenAmount = bytesToNumberBE(response.impactedTokenAmount);

    return {
      impactedOutputIds: response.impactedOutputIds,
      impactedTokenAmount: tokenAmount,
    };
  }

  /**
   * Retrieves the activity history for the issuer's token.
   * @param pageSize - The number of transactions to return per page (default: 100)
   * @param cursor - Optional cursor for pagination
   * @param operationTypes - Optional array of operation types to filter by
   * @param beforeTimestamp - Optional timestamp to filter transactions before
   * @param afterTimestamp - Optional timestamp to filter transactions after
   * @returns An object containing the token activity data
   * @throws {ValidationError} If pageSize is not a safe integer
   * @throws {NetworkError} If the activity data cannot be retrieved
   */
  public async getIssuerTokenActivity(
    pageSize: number = 100,
    cursor?: {
      lastTransactionHash: string | Uint8Array;
      layer: string | Layer;
    },
    operationTypes?: string[] | OperationType[],
    beforeTimestamp?: Date,
    afterTimestamp?: Date,
  ): Promise<TokenActivityResponse> {
    if (!Number.isSafeInteger(pageSize)) {
      throw new ValidationError("pageSize must be less than 2^53", {
        field: "pageSize",
        value: pageSize,
        expected: "smaller or equal to " + Number.MAX_SAFE_INTEGER,
      });
    }

    const lrc20Client = await this.lrc20ConnectionManager.createLrc20Client();

    // Convert cursor to proper ListAllTokenTransactionsCursor format
    let convertedCursor: ListAllTokenTransactionsCursor | undefined;
    if (cursor) {
      const lastTransactionHash =
        typeof cursor.lastTransactionHash === "string"
          ? hexToBytes(cursor.lastTransactionHash)
          : cursor.lastTransactionHash;

      let layer: Layer;
      if (typeof cursor.layer === "string") {
        switch (cursor.layer.toUpperCase()) {
          case "L1":
            layer = Layer.L1;
            break;
          case "Spark":
            layer = Layer.SPARK;
            break;
          default:
            layer = Layer.UNRECOGNIZED;
        }
      } else {
        layer = cursor.layer;
      }

      convertedCursor = {
        lastTransactionHash,
        layer,
      };
    }

    // Convert operationTypes to proper OperationType[] format
    let convertedOperationTypes: OperationType[] | undefined;
    if (operationTypes) {
      if (typeof operationTypes[0] === "string") {
        convertedOperationTypes = (operationTypes as string[]).map((opType) => {
          switch (opType.toUpperCase()) {
            case "USER_TRANSFER":
              return OperationType.USER_TRANSFER;
            case "USER_BURN":
              return OperationType.USER_BURN;
            case "ISSUER_ANNOUNCE":
              return OperationType.ISSUER_ANNOUNCE;
            case "ISSUER_MINT":
              return OperationType.ISSUER_MINT;
            case "ISSUER_TRANSFER":
              return OperationType.ISSUER_TRANSFER;
            case "ISSUER_FREEZE":
              return OperationType.ISSUER_FREEZE;
            case "ISSUER_UNFREEZE":
              return OperationType.ISSUER_UNFREEZE;
            case "ISSUER_BURN":
              return OperationType.ISSUER_BURN;
            default:
              return OperationType.UNRECOGNIZED;
          }
        });
      } else {
        convertedOperationTypes = operationTypes as OperationType[];
      }
    }

    try {
      const transactions = await lrc20Client.listTransactions({
        tokenPublicKey: hexToBytes(await super.getIdentityPublicKey()),
        cursor: convertedCursor,
        pageSize,
        beforeTimestamp,
        afterTimestamp,
        operationTypes: convertedOperationTypes,
      });

      return convertToTokenActivity(transactions);
    } catch (error) {
      throw new NetworkError("Failed to get token activity", {
        operation: "listTransactions",
        errorCount: 1,
        errors: error instanceof Error ? error.message : String(error),
      });
    }
  }

  /**
   * Retrieves the distribution information for the issuer's token.
   * @throws {NotImplementedError} This feature is not yet supported
   */
  public async getIssuerTokenDistribution(): Promise<TokenDistribution> {
    throw new NotImplementedError("Token distribution is not yet supported");
  }

  /**
   * Announces a new token on the L1 (Bitcoin) network.
   * @param tokenName - The name of the token
   * @param tokenTicker - The ticker symbol for the token
   * @param decimals - The number of decimal places for the token
   * @param maxSupply - The maximum supply of the token
   * @param isFreezable - Whether the token can be frozen
   * @param feeRateSatsPerVb - The fee rate in satoshis per virtual byte (default: 4.0)
   * @returns The transaction ID of the announcement
   * @throws {ValidationError} If decimals is not a safe integer
   * @throws {NetworkError} If the announcement transaction cannot be broadcast
   */
  public async announceTokenL1(
    tokenName: string,
    tokenTicker: string,
    decimals: number,
    maxSupply: bigint,
    isFreezable: boolean,
    feeRateSatsPerVb: number = 4.0,
  ): Promise<string> {
    if (!Number.isSafeInteger(decimals)) {
      throw new ValidationError("Decimals must be less than 2^53", {
        field: "decimals",
        value: decimals,
        expected: "smaller or equal to " + Number.MAX_SAFE_INTEGER,
      });
    }

    await this.lrc20Wallet!.syncWallet();

    const tokenPublicKey = new TokenPubkey(this.lrc20Wallet!.pubkey);

    const announcement = new TokenPubkeyAnnouncement(
      tokenPublicKey,
      tokenName,
      tokenTicker,
      decimals,
      maxSupply,
      isFreezable,
    );

    try {
      const tx = await this.lrc20Wallet!.prepareAnnouncement(
        announcement,
        feeRateSatsPerVb,
      );

      const txId = await this.lrc20Wallet!.broadcastRawBtcTransaction(
        tx.bitcoin_tx.toHex(),
      );

      return txId;
    } catch (error) {
      throw new NetworkError(
        "Failed to broadcast announcement transaction on L1",
        {
          operation: "broadcastRawBtcTransaction",
          errorCount: 1,
          errors: error instanceof Error ? error.message : String(error),
        },
      );
    }
  }
}
