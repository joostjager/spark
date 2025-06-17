import { isNode, mapCurrencyAmount } from "@lightsparkdev/core";
import {
  bytesToHex,
  bytesToNumberBE,
  equalBytes,
  hexToBytes,
  numberToVarBytesBE,
} from "@noble/curves/abstract/utils";
import { secp256k1 } from "@noble/curves/secp256k1";
import { validateMnemonic } from "@scure/bip39";
import { wordlist } from "@scure/bip39/wordlists/english";
import { Address, OutScript, Transaction } from "@scure/btc-signer";
import { TransactionInput } from "@scure/btc-signer/psbt";
import { Mutex } from "async-mutex";
import { uuidv7obj, uuidv7 } from "uuidv7";
import {
  ConfigurationError,
  NetworkError,
  RPCError,
  ValidationError,
} from "../errors/types.js";
import SspClient from "../graphql/client.js";
import {
  BitcoinNetwork,
  ClaimStaticDepositOutput,
  CoopExitFeeEstimatesOutput,
  CoopExitRequest,
  ExitSpeed,
  LeavesSwapFeeEstimateOutput,
  LeavesSwapRequest,
  LightningReceiveRequest,
  LightningSendFeeEstimateInput,
  LightningSendRequest,
  StaticDepositQuoteOutput,
  SwapLeaf,
  UserLeafInput,
} from "../graphql/objects/index.js";
import {
  DepositAddressQueryResult,
  OutputWithPreviousTransactionData,
  QueryNodesRequest,
  QueryNodesResponse,
  SigningJob,
  SubscribeToEventsResponse,
  TokenTransactionWithStatus,
  Transfer,
  TransferStatus,
  TransferType,
  TreeNode,
  UtxoSwapRequestType,
} from "../proto/spark.js";
import { WalletConfigService } from "../services/config.js";
import { ConnectionManager } from "../services/connection.js";
import { CoopExitService } from "../services/coop-exit.js";
import { DepositService } from "../services/deposit.js";
import { LightningService } from "../services/lightning.js";
import { Lrc20ConnectionManager } from "../services/lrc-connection.js";
import { TokenTransactionService } from "../services/token-transactions.js";
import type { LeafKeyTweak } from "../services/transfer.js";
import { TransferService } from "../services/transfer.js";
import {
  DepositAddressTree,
  TreeCreationService,
} from "../services/tree-creation.js";
import {
  ConfigOptions,
  ELECTRS_CREDENTIALS,
} from "../services/wallet-config.js";
import {
  applyAdaptorToSignature,
  generateAdaptorFromSignature,
  generateSignatureFromExistingAdaptor,
} from "../utils/adaptor-signature.js";
import {
  computeTaprootKeyNoScript,
  getP2TRScriptFromPublicKey,
  getP2WPKHAddressFromPublicKey,
  getSigHashFromTx,
  getTxFromRawTxBytes,
  getTxFromRawTxHex,
  getTxId,
} from "../utils/bitcoin.js";
import {
  getNetwork,
  LRC_WALLET_NETWORK,
  LRC_WALLET_NETWORK_TYPE,
  Network,
  NetworkToProto,
  NetworkType,
} from "../utils/network.js";
import { calculateAvailableTokenAmount } from "../utils/token-transactions.js";
import { getNextTransactionSequence } from "../utils/transaction.js";

import { LRCWallet } from "@buildonspark/lrc20-sdk";
import { sha256 } from "@noble/hashes/sha2";
import { EventEmitter } from "eventemitter3";
import {
  decodeSparkAddress,
  encodeSparkAddress,
  isValidPublicKey,
  SparkAddressFormat,
} from "../address/index.js";
import { isReactNative } from "../constants.js";
import { networkToJSON } from "../proto/spark.js";
import {
  decodeInvoice,
  getNetworkFromInvoice,
  isValidSparkFallback,
} from "../services/bolt11-spark.js";
import { SigningService } from "../services/signing.js";
import { SparkSigner } from "../signer/signer.js";
import { BitcoinFaucet } from "../tests/utils/test-faucet.js";
import {
  mapTransferToWalletTransfer,
  mapTreeNodeToWalletLeaf,
  WalletLeaf,
  WalletTransfer,
} from "../types/sdk-types.js";
import { chunkArray } from "../utils/chunkArray.js";
import { addPublicKeys } from "../utils/keys.js";
import type {
  CreateLightningInvoiceParams,
  DepositParams,
  InitWalletResponse,
  PayLightningInvoiceParams,
  SparkWalletProps,
  TokenInfo,
  TransferParams,
} from "./types.js";

/**
 * The SparkWallet class is the primary interface for interacting with the Spark network.
 * It provides methods for creating and managing wallets, handling deposits, executing transfers,
 * and interacting with the Lightning Network.
 */
export class SparkWallet extends EventEmitter {
  protected config: WalletConfigService;

  protected connectionManager: ConnectionManager;
  protected lrc20ConnectionManager: Lrc20ConnectionManager;
  protected lrc20Wallet: LRCWallet | undefined;
  protected transferService: TransferService;
  protected tracerId = "spark-sdk";

  private depositService: DepositService;
  private treeCreationService: TreeCreationService;
  private lightningService: LightningService;
  private coopExitService: CoopExitService;
  private signingService: SigningService;
  private tokenTransactionService: TokenTransactionService;

  private claimTransferMutex = new Mutex();
  private leavesMutex = new Mutex();
  private optimizationInProgress = false;
  private sspClient: SspClient | null = null;

  private mutexes: Map<string, Mutex> = new Map();

  private pendingWithdrawnOutputIds: string[] = [];

  private sparkAddress: SparkAddressFormat | undefined;

  private streamController: AbortController | null = null;

  protected leaves: TreeNode[] = [];
  protected tokenOutputs: Map<string, OutputWithPreviousTransactionData[]> =
    new Map();

  // Add this property near the top of the class with other private properties
  private claimTransfersInterval: NodeJS.Timeout | null = null;

  protected wrapWithOtelSpan<T>(
    name: string,
    fn: (...args: any[]) => Promise<T>,
  ): (...args: any[]) => Promise<T> {
    return async (...args: any[]): Promise<T> => {
      return await fn(...args);
    };
  }

  protected constructor(options?: ConfigOptions, signer?: SparkSigner) {
    super();

    this.config = new WalletConfigService(options, signer);
    this.connectionManager = new ConnectionManager(this.config);
    this.signingService = new SigningService(this.config);
    this.lrc20ConnectionManager = new Lrc20ConnectionManager(this.config);
    this.depositService = new DepositService(
      this.config,
      this.connectionManager,
    );
    this.transferService = new TransferService(
      this.config,
      this.connectionManager,
      this.signingService,
    );
    this.treeCreationService = new TreeCreationService(
      this.config,
      this.connectionManager,
    );
    this.tokenTransactionService = new TokenTransactionService(
      this.config,
      this.connectionManager,
    );
    this.lightningService = new LightningService(
      this.config,
      this.connectionManager,
      this.signingService,
    );
    this.coopExitService = new CoopExitService(
      this.config,
      this.connectionManager,
      this.signingService,
    );
  }

  public static async initialize({
    mnemonicOrSeed,
    accountNumber,
    signer,
    options,
  }: SparkWalletProps) {
    const wallet = new SparkWallet(options, signer);
    const initResponse = await wallet.initWallet(mnemonicOrSeed, accountNumber);

    return {
      wallet,
      ...initResponse,
    };
  }

  private async initializeWallet() {
    this.sspClient = new SspClient(this.config);
    await this.connectionManager.createClients();

    if (isReactNative) {
      this.startPeriodicClaimTransfers();
    } else {
      this.setupBackgroundStream();
    }

    await this.syncWallet();
  }

  private getSspClient() {
    if (!this.sspClient) {
      throw new ConfigurationError("SSP client not initialized", {
        configKey: "sspClient",
      });
    }
    return this.sspClient;
  }

  private async handleStreamEvent({ event }: SubscribeToEventsResponse) {
    try {
      if (
        event?.$case === "transfer" &&
        event.transfer.transfer &&
        event.transfer.transfer.type !== TransferType.COUNTER_SWAP
      ) {
        const { senderIdentityPublicKey, receiverIdentityPublicKey } =
          event.transfer.transfer;

        // Don't claim if this is a self transfer, that's handled elsewhere
        if (
          event.transfer.transfer &&
          !equalBytes(senderIdentityPublicKey, receiverIdentityPublicKey)
        ) {
          await this.claimTransfer({
            transfer: event.transfer.transfer,
            emit: true,
            optimize: true,
          });
        }
      } else if (event?.$case === "deposit" && event.deposit.deposit) {
        const deposit = event.deposit.deposit;
        const signingKey = await this.config.signer.generatePublicKey(
          sha256(deposit.id),
        );

        const newLeaf = await this.transferService.extendTimelock(
          deposit,
          signingKey,
        );
        await this.transferLeavesToSelf(newLeaf.nodes, signingKey);
        this.emit(
          "deposit:confirmed",
          deposit.id,
          (await this.getBalance()).balance,
        );
      }
    } catch (error) {
      console.error("Error processing event", error);
    }
  }

  protected async setupBackgroundStream() {
    const MAX_RETRIES = 10;
    const INITIAL_DELAY = 1000;
    const MAX_DELAY = 60000;

    this.streamController = new AbortController();

    const delay = (ms: number, signal?: AbortSignal): Promise<boolean> => {
      return new Promise((resolve) => {
        const timer = setTimeout(() => {
          if (signal) {
            signal.removeEventListener("abort", onAbort);
          }
          resolve(true);
        }, ms);

        function onAbort() {
          clearTimeout(timer);
          resolve(false);
          signal?.removeEventListener("abort", onAbort);
        }

        if (signal) {
          signal.addEventListener("abort", onAbort);
        }
      });
    };

    let retryCount = 0;
    while (retryCount <= MAX_RETRIES) {
      try {
        const address = this.config.getCoordinatorAddress();

        const sparkClient =
          await this.connectionManager.createSparkStreamClient(address);
        const channel = await this.connectionManager.getStreamChannel(address);

        const stream = sparkClient.subscribe_to_events(
          {
            identityPublicKey: await this.config.signer.getIdentityPublicKey(),
          },
          {
            signal: this.streamController?.signal,
          },
        );

        // In Node.js, long-lived gRPC streams keep the underlying socket "ref'd",
        // which prevents the process from exiting. To avoid that (e.g. in CLI tools),
        // we manually unref the socket so Node can shut down when nothing else is active.
        //
        // The gRPC client doesn't expose the socket directly, so we dig through
        // internal fields to find it. This is a bit of a hack and may break if the
        // internals change.
        //
        // Since the socket isn't always immediately available, we retry with setTimeout
        // until it shows up.
        const maybeUnref = () => {
          const internalChannel = (channel as any).internalChannel;
          if (
            internalChannel?.currentPicker?.subchannel?.child?.transport
              ?.session?.socket
          ) {
            internalChannel.currentPicker.subchannel.child.transport.session.socket.unref();
          } else {
            setTimeout(maybeUnref, 100);
          }
        };

        // Only need to unref in Node environments.
        // In the browser and React Native, the runtime handles shutdown when the tab/app closes.
        if (isNode) {
          maybeUnref();
        }

        const claimedTransfersIds = await this.claimTransfers();

        try {
          for await (const data of stream) {
            if (this.streamController?.signal.aborted) {
              break;
            }

            if (data.event?.$case === "connected") {
              this.emit("stream:connected");
              retryCount = 0;
            }

            if (
              data.event?.$case === "transfer" &&
              data.event.transfer.transfer &&
              claimedTransfersIds.includes(data.event.transfer.transfer.id)
            ) {
              continue;
            }
            await this.handleStreamEvent(data);
          }
        } catch (error) {
          throw error;
        }
      } catch (error) {
        if (this.streamController?.signal.aborted) {
          break;
        }

        const backoffDelay = Math.min(
          INITIAL_DELAY * Math.pow(2, retryCount),
          MAX_DELAY,
        );

        if (retryCount < MAX_RETRIES) {
          retryCount++;
          this.emit(
            "stream:reconnecting",
            retryCount,
            MAX_RETRIES,
            backoffDelay,
            error instanceof Error ? error.message : String(error),
          );
          try {
            const completed = await delay(
              backoffDelay,
              this.streamController?.signal,
            );
            if (!completed) {
              break;
            }
          } catch (error) {
            if (this.streamController?.signal.aborted) {
              break;
            }
          }
        } else {
          this.emit("stream:disconnected", "Max reconnection attempts reached");
          break;
        }
      }
    }
  }

  public async getLeaves(isBalanceCheck: boolean = false): Promise<TreeNode[]> {
    const leaves = await this.queryNodes({
      source: {
        $case: "ownerIdentityPubkey",
        ownerIdentityPubkey: await this.config.signer.getIdentityPublicKey(),
      },
      includeParents: false,
      network: NetworkToProto[this.config.getNetwork()],
    });

    const leavesToIgnore: Set<string> = new Set();
    // Query the leaf states from other operators.
    // We'll ignore the leaves that are out of sync for now.
    // Still include the leaves that are out of sync for balance check.
    if (!isBalanceCheck) {
      for (const [id, operator] of Object.entries(
        this.config.getSigningOperators(),
      )) {
        if (id !== this.config.getCoordinatorIdentifier()) {
          const operatorLeaves = await this.queryNodes(
            {
              source: {
                $case: "ownerIdentityPubkey",
                ownerIdentityPubkey:
                  await this.config.signer.getIdentityPublicKey(),
              },
              includeParents: false,
              network: NetworkToProto[this.config.getNetwork()],
            },
            operator.address,
          );

          // Loop over leaves returned by coordinator.
          // If the leaf is not present in the operator's leaves, we'll ignore it.
          // If the leaf is present, we'll check if the leaf is in sync with the operator's leaf.
          // If the leaf is not in sync, we'll ignore it.
          for (const [nodeId, leaf] of Object.entries(leaves.nodes)) {
            const operatorLeaf = operatorLeaves.nodes[nodeId];

            if (!operatorLeaf) {
              leavesToIgnore.add(nodeId);
              continue;
            }

            if (
              leaf.status !== operatorLeaf.status ||
              !leaf.signingKeyshare ||
              !operatorLeaf.signingKeyshare ||
              !equalBytes(
                leaf.signingKeyshare.publicKey,
                operatorLeaf.signingKeyshare.publicKey,
              ) ||
              !equalBytes(leaf.nodeTx, operatorLeaf.nodeTx) ||
              !equalBytes(leaf.refundTx, operatorLeaf.refundTx)
            ) {
              leavesToIgnore.add(nodeId);
            }
          }
        }
      }
    }

    const verifyKey = (
      pubkey1: Uint8Array,
      pubkey2: Uint8Array,
      verifyingKey: Uint8Array,
    ) => {
      return equalBytes(addPublicKeys(pubkey1, pubkey2), verifyingKey);
    };

    for (const [id, leaf] of Object.entries(leaves.nodes)) {
      if (
        !verifyKey(
          await this.config.signer.generatePublicKey(sha256(leaf.id)),
          leaf.signingKeyshare?.publicKey ?? new Uint8Array(),
          leaf.verifyingPublicKey,
        )
      ) {
        leavesToIgnore.add(id);
      }
    }

    return Object.entries(leaves.nodes)
      .filter(
        ([_, node]) =>
          node.status === "AVAILABLE" && !leavesToIgnore.has(node.id),
      )
      .map(([_, node]) => node);
  }

  private async selectLeaves(targetAmount: number): Promise<TreeNode[]> {
    if (targetAmount <= 0) {
      throw new ValidationError("Target amount must be positive", {
        field: "targetAmount",
        value: targetAmount,
      });
    }

    const leaves = await this.getLeaves();
    if (leaves.length === 0) {
      throw new ValidationError("No owned leaves found", {
        field: "leaves",
      });
    }

    leaves.sort((a, b) => b.value - a.value);

    let amount = 0;
    let nodes: TreeNode[] = [];
    for (const leaf of leaves) {
      if (targetAmount - amount >= leaf.value) {
        amount += leaf.value;
        nodes.push(leaf);
      }
    }

    if (amount !== targetAmount) {
      await this.requestLeavesSwap({ targetAmount });

      amount = 0;
      nodes = [];
      const newLeaves = await this.getLeaves();
      newLeaves.sort((a, b) => b.value - a.value);
      for (const leaf of newLeaves) {
        if (targetAmount - amount >= leaf.value) {
          amount += leaf.value;
          nodes.push(leaf);
        }
      }
    }

    if (nodes.reduce((acc, leaf) => acc + leaf.value, 0) !== targetAmount) {
      throw new Error(
        `Failed to select leaves for target amount ${targetAmount}`,
      );
    }

    return nodes;
  }

  private async selectLeavesForSwap(targetAmount: number) {
    if (targetAmount == 0) {
      throw new Error("Target amount needs to > 0");
    }
    const leaves = await this.getLeaves();
    leaves.sort((a, b) => a.value - b.value);

    let amount = 0;
    const nodes: TreeNode[] = [];
    for (const leaf of leaves) {
      if (amount < targetAmount) {
        amount += leaf.value;
        nodes.push(leaf);
      }
    }

    if (amount < targetAmount) {
      throw new Error("Not enough leaves to swap for the target amount");
    }

    return nodes;
  }

  private areLeavesInefficient() {
    const totalAmount = this.getInternalBalance();

    if (this.leaves.length <= 1) {
      return false;
    }

    const nextLowerPowerOfTwo = 31 - Math.clz32(totalAmount);

    let remainingAmount = totalAmount;
    let optimalLeavesLength = 0;

    for (let i = nextLowerPowerOfTwo; i >= 0; i--) {
      const denomination = 2 ** i;
      while (remainingAmount >= denomination) {
        remainingAmount -= denomination;
        optimalLeavesLength++;
      }
    }

    return this.leaves.length > optimalLeavesLength * 5;
  }

  private async optimizeLeaves() {
    if (this.optimizationInProgress || !this.areLeavesInefficient()) {
      return;
    }

    await this.withLeaves(async () => {
      this.optimizationInProgress = true;
      try {
        if (this.leaves.length > 0) {
          await this.requestLeavesSwap({ leaves: this.leaves });
        }
        this.leaves = await this.getLeaves();
      } finally {
        this.optimizationInProgress = false;
      }
    });
  }

  private async syncWallet() {
    await this.syncTokenOutputs();

    let leaves = await this.getLeaves();
    await this.config.signer.restoreSigningKeysFromLeafs(leaves);

    leaves = await this.checkRefreshTimelockNodes(leaves);
    leaves = await this.checkExtendTimeLockNodes(leaves);

    this.leaves = leaves;
    this.optimizeLeaves().catch((e) => {
      console.error("Failed to optimize leaves", e);
    });
  }

  private async withLeaves<T>(operation: () => Promise<T>): Promise<T> {
    const release = await this.leavesMutex.acquire();
    try {
      return await operation();
    } finally {
      release();
    }
  }

  /**
   * Gets the identity public key of the wallet.
   *
   * @returns {Promise<string>} The identity public key as a hex string.
   */
  public async getIdentityPublicKey(): Promise<string> {
    return bytesToHex(await this.config.signer.getIdentityPublicKey());
  }

  /**
   * Gets the Spark address of the wallet.
   *
   * @returns {Promise<string>} The Spark address as a hex string.
   */
  public async getSparkAddress(): Promise<SparkAddressFormat> {
    if (!this.sparkAddress) {
      this.sparkAddress = encodeSparkAddress({
        identityPublicKey: bytesToHex(
          await this.config.signer.getIdentityPublicKey(),
        ),
        network: this.config.getNetworkType(),
      });
    }

    return this.sparkAddress;
  }

  public async createSparkPaymentIntent(
    assetIdentifier?: string,
    assetAmount: bigint = BigInt(0),
    memo?: string,
  ): Promise<SparkAddressFormat> {
    const MAX_UINT128 = BigInt("340282366920938463463374607431768211455");
    if (assetAmount < 0 || assetAmount > MAX_UINT128) {
      throw new ValidationError(
        "Asset amount must be between 0 and MAX_UINT128",
        {
          field: "assetAmount",
          value: assetAmount,
        },
      );
    }
    if (memo) {
      const encoder = new TextEncoder();
      const memoBytes = encoder.encode(memo);
      if (memoBytes.length > 120) {
        throw new ValidationError(
          "Memo exceeds the maximum allowed byte length of 120.",
          {
            field: "memo",
            value: memo,
            expected: "less than 120 bytes",
          },
        );
      }
    }
    if (assetIdentifier) {
      isValidPublicKey(assetIdentifier);
    }
    const paymentRequest = encodeSparkAddress({
      identityPublicKey: bytesToHex(
        await this.config.signer.getIdentityPublicKey(),
      ),
      network: this.config.getNetworkType(),
      paymentIntentFields: {
        id: uuidv7obj().bytes,
        assetIdentifier: assetIdentifier
          ? hexToBytes(assetIdentifier)
          : undefined,
        assetAmount: numberToVarBytesBE(assetAmount),
        memo: memo,
      },
    });

    return paymentRequest;
  }

  /**
   * Initializes the wallet using either a mnemonic phrase or a raw seed.
   * initWallet will also claim any pending incoming lightning payment, spark transfer,
   * or bitcoin deposit.
   *
   * @param {Uint8Array | string} [mnemonicOrSeed] - (Optional) Either:
   *   - A BIP-39 mnemonic phrase as string
   *   - A raw seed as Uint8Array or hex string
   *   If not provided, generates a new mnemonic and uses it to create a new wallet
   *
   * @param {number} [accountNumber] - (Optional) The account number to use for the wallet. Defaults to 1 to maintain backwards compatability for legacy mainnet wallets.
   *
   * @returns {Promise<Object>} Object containing:
   *   - mnemonic: The mnemonic if one was generated (undefined for raw seed)
   *   - balance: The wallet's initial balance in satoshis
   *   - tokenBalance: Map of token balances
   * @private
   */
  protected async initWallet(
    mnemonicOrSeed?: Uint8Array | string,
    accountNumber?: number,
  ): Promise<InitWalletResponse | undefined> {
    if (accountNumber === undefined) {
      if (this.config.getNetwork() === Network.REGTEST) {
        accountNumber = 0;
      } else {
        accountNumber = 1;
      }
    }
    let mnemonic: string | undefined;
    if (!mnemonicOrSeed) {
      mnemonic = await this.config.signer.generateMnemonic();
      mnemonicOrSeed = mnemonic;
    }

    let seed: Uint8Array;
    if (typeof mnemonicOrSeed !== "string") {
      seed = mnemonicOrSeed;
    } else {
      if (validateMnemonic(mnemonicOrSeed, wordlist)) {
        mnemonic = mnemonicOrSeed;
        seed = await this.config.signer.mnemonicToSeed(mnemonicOrSeed);
      } else {
        seed = hexToBytes(mnemonicOrSeed);
      }
    }

    await this.initWalletFromSeed(seed, accountNumber);
    const network = this.config.getNetwork();

    this.lrc20Wallet = await LRCWallet.create(
      LRC_WALLET_NETWORK[network],
      LRC_WALLET_NETWORK_TYPE[network],
      this.config.lrc20ApiConfig,
      this.config.signer,
    );

    return {
      mnemonic,
    };
  }

  /**
   * Initializes a wallet from a seed.
   *
   * @param {Uint8Array | string} seed - The seed to initialize the wallet from
   * @returns {Promise<string>} The identity public key
   * @private
   */
  private async initWalletFromSeed(
    seed: Uint8Array | string,
    accountNumber?: number,
  ) {
    const identityPublicKey =
      await this.config.signer.createSparkWalletFromSeed(seed, accountNumber);
    await this.initializeWallet();

    this.sparkAddress = encodeSparkAddress({
      identityPublicKey: identityPublicKey,
      network: this.config.getNetworkType(),
    });

    return this.sparkAddress;
  }

  /**
   * Gets the estimated fee for a swap of leaves.
   *
   * @param amountSats - The amount of sats to swap
   *  @returns {Promise<LeavesSwapFeeEstimateOutput>}  The estimated fee for the swap
   */
  public async getSwapFeeEstimate(
    amountSats: number,
  ): Promise<LeavesSwapFeeEstimateOutput> {
    const sspClient = this.getSspClient();

    const feeEstimate = await sspClient.getSwapFeeEstimate(amountSats);
    if (!feeEstimate) {
      throw new Error("Failed to get swap fee estimate");
    }

    return feeEstimate;
  }

  /**
   * Requests a swap of leaves to optimize wallet structure.
   *
   * @param {Object} params - Parameters for the leaves swap
   * @param {number} [params.targetAmount] - Target amount for the swap
   * @param {TreeNode[]} [params.leaves] - Specific leaves to swap
   * @returns {Promise<Object>} The completed swap response
   * @private
   */
  private async requestLeavesSwap({
    targetAmount,
    leaves,
  }: {
    targetAmount?: number;
    leaves?: TreeNode[];
  }) {
    if (targetAmount && targetAmount <= 0) {
      throw new Error("targetAmount must be positive");
    }

    if (targetAmount && !Number.isSafeInteger(targetAmount)) {
      throw new ValidationError("targetAmount must be less than 2^53", {
        field: "targetAmount",
        value: targetAmount,
        expected: "smaller or equal to " + Number.MAX_SAFE_INTEGER,
      });
    }

    let leavesToSwap: TreeNode[];
    if (targetAmount && leaves && leaves.length > 0) {
      if (targetAmount < leaves.reduce((acc, leaf) => acc + leaf.value, 0)) {
        throw new Error("targetAmount is less than the sum of leaves");
      }
      leavesToSwap = leaves;
    } else if (targetAmount) {
      leavesToSwap = await this.selectLeavesForSwap(targetAmount);
    } else if (leaves && leaves.length > 0) {
      leavesToSwap = leaves;
    } else {
      throw new Error("targetAmount or leaves must be provided");
    }

    leavesToSwap.sort((a, b) => a.value - b.value);

    const batches = chunkArray(leavesToSwap, 100);

    const results: SwapLeaf[] = [];
    for (const batch of batches) {
      const result = await this.processSwapBatch(batch, targetAmount);
      results.push(...result.swapLeaves);
    }

    return results;
  }

  /**
   * Processes a single batch of leaves for swapping.
   */
  private async processSwapBatch(
    leavesBatch: TreeNode[],
    targetAmount?: number,
  ): Promise<LeavesSwapRequest> {
    const leafKeyTweaks = await Promise.all(
      leavesBatch.map(async (leaf) => ({
        leaf,
        signingPubKey: await this.config.signer.generatePublicKey(
          sha256(leaf.id),
        ),
        newSigningPubKey: await this.config.signer.generatePublicKey(),
      })),
    );

    const { transfer, signatureMap } =
      await this.transferService.startSwapSignRefund(
        leafKeyTweaks,
        hexToBytes(this.config.getSspIdentityPublicKey()),
        new Date(Date.now() + 2 * 60 * 1000),
      );
    try {
      if (!transfer.leaves[0]?.leaf) {
        throw new Error("Failed to get leaf");
      }

      const refundSignature = signatureMap.get(transfer.leaves[0].leaf.id);
      if (!refundSignature) {
        throw new Error("Failed to get refund signature");
      }

      const { adaptorPrivateKey, adaptorSignature } =
        generateAdaptorFromSignature(refundSignature);

      if (!transfer.leaves[0].leaf) {
        throw new Error("Failed to get leaf");
      }

      const userLeaves: UserLeafInput[] = [];
      userLeaves.push({
        leaf_id: transfer.leaves[0].leaf.id,
        raw_unsigned_refund_transaction: bytesToHex(
          transfer.leaves[0].intermediateRefundTx,
        ),
        adaptor_added_signature: bytesToHex(adaptorSignature),
      });

      for (let i = 1; i < transfer.leaves.length; i++) {
        const leaf = transfer.leaves[i];
        if (!leaf?.leaf) {
          throw new Error("Failed to get leaf");
        }

        const refundSignature = signatureMap.get(leaf.leaf.id);
        if (!refundSignature) {
          throw new Error("Failed to get refund signature");
        }

        const signature = generateSignatureFromExistingAdaptor(
          refundSignature,
          adaptorPrivateKey,
        );

        userLeaves.push({
          leaf_id: leaf.leaf.id,
          raw_unsigned_refund_transaction: bytesToHex(
            leaf.intermediateRefundTx,
          ),
          adaptor_added_signature: bytesToHex(signature),
        });
      }

      const sspClient = this.getSspClient();
      const adaptorPubkey = bytesToHex(
        secp256k1.getPublicKey(adaptorPrivateKey),
      );
      let request: LeavesSwapRequest | null | undefined = null;
      request = await sspClient.requestLeaveSwap({
        userLeaves,
        adaptorPubkey,
        targetAmountSats:
          targetAmount ||
          leavesBatch.reduce((acc, leaf) => acc + leaf.value, 0),
        totalAmountSats: leavesBatch.reduce((acc, leaf) => acc + leaf.value, 0),
        // TODO: Request fee from SSP
        feeSats: 0,
        idempotencyKey: uuidv7(),
      });

      if (!request) {
        throw new Error("Failed to request leaves swap. No response returned.");
      }

      const nodes = await this.queryNodes({
        source: {
          $case: "nodeIds",
          nodeIds: {
            nodeIds: request.swapLeaves.map((leaf) => leaf.leafId),
          },
        },
        includeParents: false,
        network: NetworkToProto[this.config.getNetwork()],
      });

      if (Object.values(nodes.nodes).length !== request.swapLeaves.length) {
        throw new Error("Expected same number of nodes as swapLeaves");
      }

      for (const [nodeId, node] of Object.entries(nodes.nodes)) {
        if (!node.nodeTx) {
          throw new Error(`Node tx not found for leaf ${nodeId}`);
        }

        if (!node.verifyingPublicKey) {
          throw new Error(`Node public key not found for leaf ${nodeId}`);
        }

        const leaf = request.swapLeaves.find((leaf) => leaf.leafId === nodeId);
        if (!leaf) {
          throw new Error(`Leaf not found for node ${nodeId}`);
        }

        const nodeTx = getTxFromRawTxBytes(node.nodeTx);
        const refundTxBytes = hexToBytes(leaf.rawUnsignedRefundTransaction);
        const refundTx = getTxFromRawTxBytes(refundTxBytes);
        const sighash = getSigHashFromTx(refundTx, 0, nodeTx.getOutput(0));

        const nodePublicKey = node.verifyingPublicKey;

        const taprootKey = computeTaprootKeyNoScript(nodePublicKey.slice(1));
        const adaptorSignatureBytes = hexToBytes(leaf.adaptorSignedSignature);
        applyAdaptorToSignature(
          taprootKey.slice(1),
          sighash,
          adaptorSignatureBytes,
          adaptorPrivateKey,
        );
      }

      await this.transferService.deliverTransferPackage(
        transfer,
        leafKeyTweaks,
        signatureMap,
      );

      const completeResponse = await sspClient.completeLeaveSwap({
        adaptorSecretKey: bytesToHex(adaptorPrivateKey),
        userOutboundTransferExternalId: transfer.id,
        leavesSwapRequestId: request.id,
      });

      if (!completeResponse) {
        throw new Error("Failed to complete leaves swap");
      }

      await this.claimTransfers(TransferType.COUNTER_SWAP);

      return completeResponse;
    } catch (e) {
      await this.cancelAllSenderInitiatedTransfers();
      throw new Error(`Failed to request leaves swap: ${e}`);
    }
  }

  /**
   * Gets all transfers for the wallet.
   *
   * @param {number} [limit=20] - Maximum number of transfers to return
   * @param {number} [offset=0] - Offset for pagination
   * @returns {Promise<QueryTransfersResponse>} Response containing the list of transfers
   */
  public async getTransfers(
    limit: number = 20,
    offset: number = 0,
  ): Promise<{
    transfers: WalletTransfer[];
    offset: number;
  }> {
    const transfers = await this.transferService.queryAllTransfers(
      limit,
      offset,
    );
    const identityPublicKey = bytesToHex(
      await this.config.signer.getIdentityPublicKey(),
    );
    return {
      transfers: transfers.transfers.map((transfer) =>
        mapTransferToWalletTransfer(transfer, identityPublicKey),
      ),
      offset: transfers.offset,
    };
  }

  /**
   * Gets the held token info for the wallet.
   *
   * @deprecated The information is returned in getBalance
   */
  public async getTokenInfo(): Promise<TokenInfo[]> {
    console.warn("getTokenInfo is deprecated. Use getBalance instead.");

    await this.syncTokenOutputs();

    const lrc20Client = await this.lrc20ConnectionManager.createLrc20Client();
    const { balance, tokenBalances } = await this.getBalance();

    const tokenInfo = await lrc20Client.getTokenPubkeyInfo({
      publicKeys: Array.from(tokenBalances.keys()).map(hexToBytes),
    });

    return tokenInfo.tokenPubkeyInfos.map((info) => ({
      tokenPublicKey: bytesToHex(info.announcement!.publicKey!.publicKey),
      tokenName: info.announcement!.name,
      tokenSymbol: info.announcement!.symbol,
      tokenDecimals: Number(bytesToNumberBE(info.announcement!.decimal)),
      maxSupply: bytesToNumberBE(info.announcement!.maxSupply),
    }));
  }

  /**
   * Gets the current balance of the wallet.
   * You can use the forceRefetch option to synchronize your wallet and claim any
   * pending incoming lightning payment, spark transfer, or bitcoin deposit before returning the balance.
   *
   * @returns {Promise<Object>} Object containing:
   *   - balance: The wallet's current balance in satoshis
   *   - tokenBalances: Map of token public keys to token balances and token info
   */
  public async getBalance(): Promise<{
    balance: bigint;
    tokenBalances: Map<string, { balance: bigint; tokenInfo: TokenInfo }>;
  }> {
    const leaves = await this.getLeaves(true);
    await this.syncTokenOutputs();

    let tokenBalances: Map<string, { balance: bigint; tokenInfo: TokenInfo }>;

    if (this.tokenOutputs.size !== 0) {
      tokenBalances = await this.getTokenBalance();
    } else {
      tokenBalances = new Map<
        string,
        { balance: bigint; tokenInfo: TokenInfo }
      >();
    }

    return {
      balance: BigInt(leaves.reduce((acc, leaf) => acc + leaf.value, 0)),
      tokenBalances,
    };
  }

  private async getTokenBalance(): Promise<
    Map<string, { balance: bigint; tokenInfo: TokenInfo }>
  > {
    const lrc20Client = await this.lrc20ConnectionManager.createLrc20Client();

    // Get token info for all tokens
    const tokenInfo = await lrc20Client.getTokenPubkeyInfo({
      publicKeys: Array.from(this.tokenOutputs.keys()).map(hexToBytes),
    });

    const result = new Map<string, { balance: bigint; tokenInfo: TokenInfo }>();

    for (const info of tokenInfo.tokenPubkeyInfos) {
      const tokenPublicKey = bytesToHex(
        info.announcement!.publicKey!.publicKey,
      );
      const leaves = this.tokenOutputs.get(tokenPublicKey);

      result.set(tokenPublicKey, {
        balance: leaves ? calculateAvailableTokenAmount(leaves) : BigInt(0),
        tokenInfo: {
          tokenPublicKey,
          tokenName: info.announcement!.name,
          tokenSymbol: info.announcement!.symbol,
          tokenDecimals: Number(bytesToNumberBE(info.announcement!.decimal)),
          maxSupply: bytesToNumberBE(info.announcement!.maxSupply),
        },
      });
    }

    return result;
  }

  private getInternalBalance(): number {
    return this.leaves.reduce((acc, leaf) => acc + leaf.value, 0);
  }

  // ***** Deposit Flow *****

  /**
   * Generates a new deposit address for receiving bitcoin funds.
   * Note that this function returns a bitcoin address, not a spark address, and this address is single use.
   * Once you deposit funds to this address, it cannot be used again.
   * For Layer 1 Bitcoin deposits, Spark generates Pay to Taproot (P2TR) addresses.
   * These addresses start with "bc1p" and can be used to receive Bitcoin from any wallet.
   *
   * @returns {Promise<string>} A Bitcoin address for depositing funds
   */
  public async getSingleUseDepositAddress(): Promise<string> {
    return await this.generateDepositAddress(false);
  }

  /**
   * Generates a new static deposit address for receiving bitcoin funds.
   * This address is permanent and can be used multiple times.
   *
   * @returns {Promise<string>} A Bitcoin address for depositing funds
   */
  public async getStaticDepositAddress(): Promise<string> {
    try {
      return await this.generateDepositAddress(true);
    } catch (error: any) {
      if (error.message?.includes("static deposit address already exists")) {
        // Query instead of checking error message in case error message changes.
        const existingAddresses = await this.queryStaticDepositAddresses();
        if (existingAddresses.length > 0 && existingAddresses[0]) {
          return existingAddresses[0];
        } else {
          throw error;
        }
      } else {
        throw error;
      }
    }
  }

  /**
   * Generates a deposit address for receiving funds.
   *
   * @param {boolean} static - Whether the address is static or single use
   * @returns {Promise<string>} A deposit address
   * @private
   */
  private async generateDepositAddress(isStatic?: boolean): Promise<string> {
    const leafId = uuidv7();
    let signingPubkey: Uint8Array;
    if (isStatic) {
      // TODO: Add support for multiple static deposit addresses
      signingPubkey = await this.config.signer.generateStaticDepositKey(0);
    } else {
      signingPubkey = await this.config.signer.generatePublicKey(
        sha256(leafId),
      );
    }

    const address = await this.depositService!.generateDepositAddress({
      signingPubkey,
      leafId,
      isStatic,
    });
    if (!address.depositAddress) {
      throw new RPCError("Failed to generate deposit address", {
        method: "generateDepositAddress",
        params: { signingPubkey, leafId },
      });
    }
    return address.depositAddress.address;
  }

  public async queryStaticDepositAddresses(): Promise<string[]> {
    const sparkClient = await this.connectionManager.createSparkClient(
      this.config.getCoordinatorAddress(),
    );
    return (
      await sparkClient.query_static_deposit_addresses({
        identityPublicKey: await this.config.signer.getIdentityPublicKey(),
        network: NetworkToProto[this.config.getNetwork()],
      })
    ).depositAddresses.map((addr) => addr.depositAddress);
  }

  /**
   * Get a quote on how much credit you can claim for a deposit from the SSP.
   *
   * @param {string} transactionId - The ID of the transaction
   * @param {number} [outputIndex] - The index of the output
   * @returns {Promise<StaticDepositQuoteOutput>} Quote for claiming a deposit to a static deposit address
   */
  public async getClaimStaticDepositQuote(
    transactionId: string,
    outputIndex?: number,
  ): Promise<StaticDepositQuoteOutput> {
    const sspClient = this.getSspClient();
    let network = this.config.getSspNetwork();

    if (network === BitcoinNetwork.FUTURE_VALUE) {
      network = BitcoinNetwork.REGTEST;
    }

    if (outputIndex === undefined) {
      outputIndex = await this.getDepositTransactionVout(transactionId);
    }

    const quote = await sspClient.getClaimDepositQuote({
      transactionId,
      outputIndex,
      network,
    });

    if (!quote) {
      throw new Error("Failed to get claim deposit quote");
    }

    return quote;
  }

  /**
   * Claims a deposit to a static deposit address.
   *
   * @param {string} transactionId - The ID of the transaction
   * @param {number} creditAmountSats - The amount of credit to claim
   * @param {string} sspSignature - The SSP signature for the deposit
   * @param {number} [outputIndex] - The index of the output
   * @returns {Promise<RequestClaimDepositQuoteOutput | null>} Quote for claiming a deposit to a static deposit address
   */
  public async claimStaticDeposit({
    transactionId,
    creditAmountSats,
    sspSignature,
    outputIndex,
  }: {
    transactionId: string;
    creditAmountSats: number;
    sspSignature: string;
    outputIndex?: number;
  }): Promise<ClaimStaticDepositOutput | null> {
    if (!this.sspClient) {
      throw new Error("SSP client not initialized");
    }

    if (outputIndex === undefined) {
      outputIndex = await this.getDepositTransactionVout(transactionId);
    }

    let network = this.config.getSspNetwork();

    if (network === BitcoinNetwork.FUTURE_VALUE) {
      network = BitcoinNetwork.REGTEST;
    }

    // const network =  BitcoinNetwork.REGTEST;
    const depositSecretKey = bytesToHex(
      await this.config.signer.getStaticDepositSecretKey(0),
    );

    const message = await this.getStaticDepositSigningPayload(
      transactionId,
      outputIndex,
      network.toLowerCase(),
      UtxoSwapRequestType.Fixed,
      creditAmountSats,
      sspSignature,
    );

    const hashBuffer = sha256(message);
    const signatureBytes =
      await this.config.signer.signMessageWithIdentityKey(hashBuffer);
    const signature = bytesToHex(signatureBytes);

    const response = await this.sspClient.claimStaticDeposit({
      transactionId,
      outputIndex,
      network,
      creditAmountSats,
      depositSecretKey,
      signature,
      sspSignature,
    });

    if (!response) {
      throw new Error("Failed to claim static deposit");
    }

    return response;
  }

  /**
   * Refunds a static deposit to a destination address.
   *
   * @param {string} depositTransactionId - The ID of the transaction
   * @param {number} [outputIndex] - The index of the output
   * @param {string} destinationAddress - The destination address
   * @param {number} fee - The fee to refund
   * @returns {Promise<string>} The hex of the refund transaction
   */
  public async refundStaticDeposit({
    depositTransactionId,
    outputIndex,
    destinationAddress,
    fee,
  }: {
    depositTransactionId: string;
    outputIndex?: number;
    destinationAddress: string;
    fee: number;
  }): Promise<string> {
    if (fee <= 300) {
      throw new ValidationError("Fee must be greater than 300", {
        field: "fee",
        value: fee,
      });
    }

    let network = this.config.getNetwork();
    let networkType = this.config.getNetworkProto();
    const networkJSON = networkToJSON(networkType);

    const depositTx = await this.getDepositTransaction(depositTransactionId);

    if (outputIndex === undefined) {
      outputIndex = await this.getDepositTransactionVout(depositTransactionId);
    }

    const totalAmount = depositTx.getOutput(outputIndex).amount;
    const creditAmountSats = Number(totalAmount) - fee;

    if (creditAmountSats <= 0) {
      throw new ValidationError(
        "Fee too large. Credit amount must be greater than 0",
        {
          field: "creditAmountSats",
          value: creditAmountSats,
        },
      );
    }

    const tx = new Transaction();

    tx.addInput({
      txid: depositTransactionId,
      index: outputIndex,
      witnessScript: new Uint8Array(),
    });

    // Decode the address and create output script
    const addressDecoded = Address(getNetwork(network)).decode(
      destinationAddress,
    );
    const outputScript = OutScript.encode(addressDecoded);

    // Add the output to the transaction
    tx.addOutput({
      script: outputScript,
      amount: BigInt(creditAmountSats),
    });

    const spendTxSighash = getSigHashFromTx(
      tx,
      0,
      depositTx.getOutput(outputIndex),
    );

    // Used in the signing job and frost.
    const signingNonceCommitment =
      await this.config.signer.getRandomSigningCommitment();

    const signingJob: SigningJob = {
      rawTx: tx.toBytes(),
      signingPublicKey: await this.config.signer.getStaticDepositSigningKey(0),
      signingNonceCommitment: signingNonceCommitment,
    };

    const message = await this.getStaticDepositSigningPayload(
      depositTransactionId,
      outputIndex,
      networkJSON.toLowerCase(),
      UtxoSwapRequestType.Refund,
      creditAmountSats,
      bytesToHex(spendTxSighash),
    );
    const hashBuffer = sha256(message);
    const swapResponseUserSignature =
      await this.config.signer.signMessageWithIdentityKey(hashBuffer);

    const sparkClient = await this.connectionManager.createSparkClient(
      this.config.getCoordinatorAddress(),
    );

    const transferId = uuidv7();

    // Initiate Utxo Swap
    const swapResponse = await sparkClient.initiate_utxo_swap({
      onChainUtxo: {
        txid: hexToBytes(depositTransactionId),
        vout: outputIndex,
        network: networkType,
      },
      requestType: UtxoSwapRequestType.Refund,
      amount: {
        creditAmountSats: 0,
        $case: "creditAmountSats",
      },
      userSignature: swapResponseUserSignature,
      sspSignature: new Uint8Array(),
      transfer: {
        transferId: transferId,
        ownerIdentityPublicKey: await this.config.signer.getIdentityPublicKey(),
        receiverIdentityPublicKey:
          await this.config.signer.getIdentityPublicKey(),
      },
      spendTxSigningJob: signingJob,
    });

    if (!swapResponse) {
      throw new Error("Failed to initiate utxo swap");
    }

    // Sign the spend tx
    const userSignature = await this.config.signer.signFrost({
      message: spendTxSighash,
      publicKey: swapResponse.depositAddress!.verifyingPublicKey,
      privateAsPubKey: await this.config.signer.getStaticDepositSigningKey(0),
      selfCommitment: signingNonceCommitment,
      statechainCommitments:
        swapResponse.spendTxSigningResult!.signingNonceCommitments,
      verifyingKey: swapResponse.depositAddress!.verifyingPublicKey,
    });

    const signatureResult = await this.config.signer.aggregateFrost({
      message: spendTxSighash,
      statechainSignatures: swapResponse.spendTxSigningResult!.signatureShares,
      statechainPublicKeys: swapResponse.spendTxSigningResult!.publicKeys,
      verifyingKey: swapResponse.depositAddress!.verifyingPublicKey,
      statechainCommitments:
        swapResponse.spendTxSigningResult!.signingNonceCommitments,
      selfCommitment: signingNonceCommitment,
      publicKey: await this.config.signer.getStaticDepositSigningKey(0),
      selfSignature: userSignature,
    });

    // Update the input with the signature
    tx.updateInput(0, {
      finalScriptWitness: [signatureResult],
    });

    return tx.hex;
  }

  private async getStaticDepositSigningPayload(
    transactionID: string,
    outputIndex: number,
    network: string,
    requestType: UtxoSwapRequestType,
    creditAmountSats: number,
    sspSignature: string,
  ): Promise<Uint8Array> {
    const encoder = new TextEncoder();
    // Create arrays to hold all the data parts
    const parts: Uint8Array[] = [];

    // Add action name as UTF-8 bytes
    parts.push(encoder.encode("claim_static_deposit"));

    // Add network value as UTF-8 bytes
    parts.push(encoder.encode(network));

    // Add transaction ID as UTF-8 bytes
    parts.push(encoder.encode(transactionID));

    // Add output index as 4-byte unsigned integer (little-endian)
    const outputIndexBuffer = new ArrayBuffer(4);
    new DataView(outputIndexBuffer).setUint32(0, outputIndex, true); // true for little-endian
    parts.push(new Uint8Array(outputIndexBuffer));

    let requestTypeInt: number;
    switch (requestType) {
      case UtxoSwapRequestType.Fixed:
        requestTypeInt = 0;
        break;
      case UtxoSwapRequestType.MaxFee:
        requestTypeInt = 1;
        break;
      case UtxoSwapRequestType.Refund:
        requestTypeInt = 2;
        break;
      default:
        requestTypeInt = 0;
    }
    const requestTypeBuffer = new ArrayBuffer(1);
    new DataView(requestTypeBuffer).setUint8(0, requestTypeInt);
    parts.push(new Uint8Array(requestTypeBuffer));

    // Add credit amount as 8-byte unsigned integer (little-endian)
    const creditAmountBuffer = new ArrayBuffer(8);
    const creditAmountView = new DataView(creditAmountBuffer);

    // Split the number into low and high 32-bit parts
    const lowerHalf = creditAmountSats >>> 0; // Get the lower 32 bits
    const upperHalf = Math.floor(creditAmountSats / 0x100000000); // Get the upper 32 bits

    creditAmountView.setUint32(0, lowerHalf, true); // Lower 32 bits
    creditAmountView.setUint32(4, upperHalf, true); // Upper 32 bits

    parts.push(new Uint8Array(creditAmountBuffer));

    // Add SSP signature as bytes
    parts.push(hexToBytes(sspSignature));

    // Combine all parts into a single buffer
    const totalLength = parts.reduce((sum, part) => sum + part.length, 0);
    const payload = new Uint8Array(totalLength);

    let offset = 0;
    for (const part of parts) {
      payload.set(part, offset);
      offset += part.length;
    }
    return payload;
  }

  private async getDepositTransactionVout(txid: string): Promise<number> {
    const depositTx = await this.getDepositTransaction(txid);

    const staticDepositAddresses = new Set(
      await this.queryStaticDepositAddresses(),
    );

    let vout = -1;

    for (let i = 0; i < depositTx.outputsLength; i++) {
      const output = depositTx.getOutput(i);
      if (!output) {
        continue;
      }
      const parsedScript = OutScript.decode(output.script!);
      const address = Address(getNetwork(this.config.getNetwork())).encode(
        parsedScript,
      );
      if (staticDepositAddresses.has(address)) {
        vout = i;
        break;
      }
    }

    if (vout === -1) {
      throw new Error("No static deposit address found");
    }

    return vout;
  }

  private async getDepositTransaction(txid: string): Promise<Transaction> {
    if (!txid) {
      throw new ValidationError("Transaction ID cannot be empty", {
        field: "txid",
      });
    }

    const baseUrl = this.config.getElectrsUrl();
    const headers: Record<string, string> = {};

    let txHex: string | undefined;

    if (this.config.getNetwork() === Network.LOCAL) {
      const localFaucet = BitcoinFaucet.getInstance();
      const response = await localFaucet.getRawTransaction(txid);
      txHex = response.hex;
    } else {
      if (this.config.getNetwork() === Network.REGTEST) {
        const auth = btoa(
          `${ELECTRS_CREDENTIALS.username}:${ELECTRS_CREDENTIALS.password}`,
        );
        headers["Authorization"] = `Basic ${auth}`;
      }

      const response = await fetch(`${baseUrl}/tx/${txid}/hex`, {
        headers,
      });

      txHex = await response.text();
    }

    if (!txHex) {
      throw new Error("Transaction not found");
    }

    if (!/^[0-9A-Fa-f]+$/.test(txHex)) {
      throw new ValidationError("Invalid transaction hex", {
        field: "txHex",
        value: txHex,
      });
    }
    const depositTx = getTxFromRawTxHex(txHex);

    return depositTx;
  }

  /**
   * Finalizes a deposit to the wallet.
   *
   * @param {DepositParams} params - Parameters for finalizing the deposit
   * @returns {Promise<void>} The nodes created from the deposit
   * @private
   */
  private async finalizeDeposit({
    signingPubKey,
    verifyingKey,
    depositTx,
    vout,
  }: DepositParams) {
    if (!Number.isSafeInteger(vout)) {
      throw new ValidationError("vout must be less than 2^53", {
        field: "vout",
        value: vout,
        expected: "smaller or equal to " + Number.MAX_SAFE_INTEGER,
      });
    }

    const res = await this.depositService!.createTreeRoot({
      signingPubKey,
      verifyingKey,
      depositTx,
      vout,
    });

    const resultingNodes: TreeNode[] = [];
    for (const node of res.nodes) {
      if (node.status === "AVAILABLE") {
        const { nodes } = await this.transferService.extendTimelock(
          node,
          signingPubKey,
        );

        for (const n of nodes) {
          if (n.status === "AVAILABLE") {
            const transfer = await this.transferLeavesToSelf(
              [n],
              signingPubKey,
            );
            resultingNodes.push(...transfer);
          } else {
            resultingNodes.push(n);
          }
        }
      } else {
        resultingNodes.push(node);
      }
    }

    return resultingNodes;
  }

  /**
   * Gets all unused deposit addresses for the wallet.
   *
   * @returns {Promise<string[]>} The unused deposit addresses
   */
  public async getUnusedDepositAddresses(): Promise<string[]> {
    const sparkClient = await this.connectionManager.createSparkClient(
      this.config.getCoordinatorAddress(),
    );
    return (
      await sparkClient.query_unused_deposit_addresses({
        identityPublicKey: await this.config.signer.getIdentityPublicKey(),
        network: NetworkToProto[this.config.getNetwork()],
      })
    ).depositAddresses.map((addr) => addr.depositAddress);
  }
  /**
   * Claims a deposit to the wallet.
   * Note that if you used advancedDeposit, you don't need to call this function.
   * @param {string} txid - The transaction ID of the deposit
   * @returns {Promise<WalletLeaf[] | undefined>} The nodes resulting from the deposit
   */
  public async claimDeposit(txid: string): Promise<WalletLeaf[]> {
    if (!txid) {
      throw new ValidationError("Transaction ID cannot be empty", {
        field: "txid",
      });
    }

    let mutex = this.mutexes.get(txid);
    if (!mutex) {
      mutex = new Mutex();
      this.mutexes.set(txid, mutex);
    }

    const nodes = await mutex.runExclusive(async () => {
      const baseUrl = this.config.getElectrsUrl();
      const headers: Record<string, string> = {};

      let txHex: string | undefined;

      if (this.config.getNetwork() === Network.LOCAL) {
        const localFaucet = BitcoinFaucet.getInstance();
        const response = await localFaucet.getRawTransaction(txid);
        txHex = response.hex;
      } else {
        if (this.config.getNetwork() === Network.REGTEST) {
          const auth = btoa(
            `${ELECTRS_CREDENTIALS.username}:${ELECTRS_CREDENTIALS.password}`,
          );
          headers["Authorization"] = `Basic ${auth}`;
        }

        const response = await fetch(`${baseUrl}/tx/${txid}/hex`, {
          headers,
        });

        txHex = await response.text();
      }

      if (!txHex) {
        throw new Error("Transaction not found");
      }

      if (!/^[0-9A-Fa-f]+$/.test(txHex)) {
        throw new ValidationError("Invalid transaction hex", {
          field: "txHex",
          value: txHex,
        });
      }
      const depositTx = getTxFromRawTxHex(txHex);

      const sparkClient = await this.connectionManager.createSparkClient(
        this.config.getCoordinatorAddress(),
      );

      const unusedDepositAddresses: Map<string, DepositAddressQueryResult> =
        new Map(
          (
            await sparkClient.query_unused_deposit_addresses({
              identityPublicKey:
                await this.config.signer.getIdentityPublicKey(),
              network: NetworkToProto[this.config.getNetwork()],
            })
          ).depositAddresses.map((addr) => [addr.depositAddress, addr]),
        );
      let depositAddress: DepositAddressQueryResult | undefined;
      let vout = 0;
      for (let i = 0; i < depositTx.outputsLength; i++) {
        const output = depositTx.getOutput(i);
        if (!output) {
          continue;
        }
        const parsedScript = OutScript.decode(output.script!);
        const address = Address(getNetwork(this.config.getNetwork())).encode(
          parsedScript,
        );
        if (unusedDepositAddresses.has(address)) {
          vout = i;
          depositAddress = unusedDepositAddresses.get(address);
          break;
        }
      }
      if (!depositAddress) {
        throw new ValidationError("Deposit address has already been used", {
          field: "depositAddress",
          value: depositAddress,
        });
      }

      let signingPubKey: Uint8Array;
      if (!depositAddress.leafId) {
        signingPubKey = depositAddress.userSigningPublicKey;
      } else {
        signingPubKey = await this.config.signer.generatePublicKey(
          sha256(depositAddress.leafId),
        );
      }

      const nodes = await this.finalizeDeposit({
        signingPubKey,
        verifyingKey: depositAddress.verifyingPublicKey,
        depositTx,
        vout,
      });

      return nodes;
    });

    this.mutexes.delete(txid);

    return nodes.map(mapTreeNodeToWalletLeaf);
  }

  /**
   * Non-trusty flow for depositing funds to the wallet.
   * Construct the tx spending from an L1 wallet to the Spark address.
   * After calling this function, you must sign and broadcast the tx.
   *
   * @param {string} txHex - The hex string of the transaction to deposit
   * @returns {Promise<TreeNode[] | undefined>} The nodes resulting from the deposit
   */
  public async advancedDeposit(txHex: string) {
    const depositTx = getTxFromRawTxHex(txHex);
    const sparkClient = await this.connectionManager.createSparkClient(
      this.config.getCoordinatorAddress(),
    );
    const unusedDepositAddresses: Map<string, DepositAddressQueryResult> =
      new Map(
        (
          await sparkClient.query_unused_deposit_addresses({
            identityPublicKey: await this.config.signer.getIdentityPublicKey(),
            network: NetworkToProto[this.config.getNetwork()],
          })
        ).depositAddresses.map((addr) => [addr.depositAddress, addr]),
      );

    let vout = 0;
    const responses: TreeNode[] = [];
    for (let i = 0; i < depositTx.outputsLength; i++) {
      const output = depositTx.getOutput(i);
      if (!output) {
        continue;
      }
      const parsedScript = OutScript.decode(output.script!);
      const address = Address(getNetwork(this.config.getNetwork())).encode(
        parsedScript,
      );
      const unusedDepositAddress = unusedDepositAddresses.get(address);
      if (unusedDepositAddress) {
        vout = i;
        const response = await this.depositService!.createTreeRoot({
          signingPubKey: unusedDepositAddress.userSigningPublicKey,
          verifyingKey: unusedDepositAddress.verifyingPublicKey,
          depositTx,
          vout,
        });
        responses.push(...response.nodes);
      }
    }
    if (responses.length === 0) {
      throw new Error(
        `No unused deposit address found for tx: ${getTxId(depositTx)}`,
      );
    }

    return responses;
  }

  /**
   * Transfers deposit to self to claim ownership.
   *
   * @param {TreeNode[]} leaves - The leaves to transfer
   * @param {Uint8Array} signingPubKey - The signing public key
   * @returns {Promise<TreeNode[] | undefined>} The nodes resulting from the transfer
   * @private
   */
  private async transferLeavesToSelf(
    leaves: TreeNode[],
    signingPubKey: Uint8Array,
  ): Promise<TreeNode[]> {
    const leafKeyTweaks = await Promise.all(
      leaves.map(async (leaf) => ({
        leaf,
        signingPubKey,
        newSigningPubKey: await this.config.signer.generatePublicKey(),
      })),
    );

    const transfer = await this.transferService.sendTransferWithKeyTweaks(
      leafKeyTweaks,
      await this.config.signer.getIdentityPublicKey(),
    );

    const pendingTransfer = await this.transferService.queryTransfer(
      transfer.id,
    );

    const resultNodes = !pendingTransfer
      ? []
      : await this.claimTransfer({ transfer: pendingTransfer });

    const leavesToRemove = new Set(leaves.map((leaf) => leaf.id));
    this.leaves = [
      ...this.leaves.filter((leaf) => !leavesToRemove.has(leaf.id)),
      ...resultNodes,
    ];

    return resultNodes;
  }
  // ***** Transfer Flow *****

  /**
   * Sends a transfer to another Spark user.
   *
   * @param {TransferParams} params - Parameters for the transfer
   * @param {string} params.receiverSparkAddress - The recipient's Spark address
   * @param {number} params.amountSats - Amount to send in satoshis
   * @returns {Promise<WalletTransfer>} The completed transfer details
   */
  public async transfer({
    amountSats,
    receiverSparkAddress,
  }: TransferParams): Promise<WalletTransfer> {
    if (!receiverSparkAddress) {
      throw new ValidationError("Receiver Spark address cannot be empty", {
        field: "receiverSparkAddress",
      });
    }

    if (!Number.isSafeInteger(amountSats)) {
      throw new ValidationError("Sats amount must be less than 2^53", {
        field: "amountSats",
        value: amountSats,
        expected: "smaller or equal to " + Number.MAX_SAFE_INTEGER,
      });
    }

    if (amountSats <= 0) {
      throw new ValidationError("Amount must be greater than 0", {
        field: "amountSats",
        value: amountSats,
      });
    }

    const receiverAddress = decodeSparkAddress(
      receiverSparkAddress,
      this.config.getNetworkType(),
    );

    const signerIdentityPublicKey =
      await this.config.signer.getIdentityPublicKey();

    const isSelfTransfer = equalBytes(
      signerIdentityPublicKey,
      hexToBytes(receiverAddress.identityPublicKey),
    );

    return await this.withLeaves(async () => {
      let leavesToSend = await this.selectLeaves(amountSats);

      leavesToSend = await this.checkRefreshTimelockNodes(leavesToSend);
      leavesToSend = await this.checkExtendTimeLockNodes(leavesToSend);

      const leafKeyTweaks = await Promise.all(
        leavesToSend.map(async (leaf) => ({
          leaf,
          signingPubKey: await this.config.signer.generatePublicKey(
            sha256(leaf.id),
          ),
          newSigningPubKey: await this.config.signer.generatePublicKey(),
        })),
      );

      const transfer = await this.transferService.sendTransferWithKeyTweaks(
        leafKeyTweaks,
        hexToBytes(receiverAddress.identityPublicKey),
      );

      const leavesToRemove = new Set(leavesToSend.map((leaf) => leaf.id));
      this.leaves = this.leaves.filter((leaf) => !leavesToRemove.has(leaf.id));

      // If this is a self-transfer, lets claim it immediately
      if (isSelfTransfer) {
        const transactionId = transfer.id;
        const pendingTransfer =
          await this.transferService.queryTransfer(transactionId);
        if (pendingTransfer) {
          await this.claimTransfer({
            transfer: pendingTransfer,
            optimize: true,
          });
        }
      }

      return mapTransferToWalletTransfer(
        transfer,
        bytesToHex(await this.config.signer.getIdentityPublicKey()),
      );
    });
  }

  private async checkExtendTimeLockNodes(
    nodes: TreeNode[],
  ): Promise<TreeNode[]> {
    const nodesToExtend: TreeNode[] = [];
    const nodeIds: string[] = [];
    const validNodes: TreeNode[] = [];

    for (const node of nodes) {
      const nodeTx = getTxFromRawTxBytes(node.nodeTx);
      const { needRefresh } = getNextTransactionSequence(
        nodeTx.getInput(0).sequence,
      );
      if (needRefresh) {
        nodesToExtend.push(node);
        nodeIds.push(node.id);
      } else {
        validNodes.push(node);
      }
    }

    if (nodesToExtend.length === 0) {
      return validNodes;
    }

    const nodesToAdd: TreeNode[] = [];
    for (const node of nodesToExtend) {
      const signingPubKey = await this.config.signer.generatePublicKey(
        sha256(node.id),
      );
      const { nodes } = await this.transferService.extendTimelock(
        node,
        signingPubKey,
      );
      this.leaves = this.leaves.filter((leaf) => leaf.id !== node.id);
      const newNodes = await this.transferLeavesToSelf(nodes, signingPubKey);
      nodesToAdd.push(...newNodes);
    }

    this.updateLeaves(nodeIds, nodesToAdd);
    validNodes.push(...nodesToAdd);

    return validNodes;
  }

  /**
   * Internal method to refresh timelock nodes.
   *
   * @param {string} nodeId - The optional ID of the node to refresh. If not provided, all nodes will be checked.
   * @returns {Promise<void>}
   * @private
   */
  private async checkRefreshTimelockNodes(
    nodes: TreeNode[],
  ): Promise<TreeNode[]> {
    const nodesToRefresh: TreeNode[] = [];
    const nodeIds: string[] = [];
    const validNodes: TreeNode[] = [];

    for (const node of nodes) {
      const refundTx = getTxFromRawTxBytes(node.refundTx);
      const { needRefresh } = getNextTransactionSequence(
        refundTx.getInput(0).sequence,
        true,
      );
      if (needRefresh) {
        nodesToRefresh.push(node);
        nodeIds.push(node.id);
      } else {
        validNodes.push(node);
      }
    }

    if (nodesToRefresh.length === 0) {
      return validNodes;
    }

    const nodesResp = await this.queryNodes({
      source: {
        $case: "nodeIds",
        nodeIds: {
          nodeIds,
        },
      },
      includeParents: true,
      network: NetworkToProto[this.config.getNetwork()],
    });

    const nodesMap = new Map<string, TreeNode>();
    for (const node of Object.values(nodesResp.nodes)) {
      nodesMap.set(node.id, node);
    }

    const nodesToAdd: TreeNode[] = [];
    for (const node of nodesToRefresh) {
      if (!node.parentNodeId) {
        throw new Error(`node ${node.id} has no parent`);
      }

      const parentNode = nodesMap.get(node.parentNodeId);
      if (!parentNode) {
        throw new Error(`parent node ${node.parentNodeId} not found`);
      }

      const { nodes } = await this.transferService.refreshTimelockNodes(
        [node],
        parentNode,
        await this.config.signer.generatePublicKey(sha256(node.id)),
      );

      if (nodes.length !== 1) {
        throw new Error(`expected 1 node, got ${nodes.length}`);
      }

      const newNode = nodes[0];
      if (!newNode) {
        throw new Error("Failed to refresh timelock node");
      }

      nodesToAdd.push(newNode);
    }

    this.updateLeaves(nodeIds, nodesToAdd);
    validNodes.push(...nodesToAdd);

    return validNodes;
  }

  /**
   * Claims a specific transfer.
   *
   * @param {Transfer} transfer - The transfer to claim
   * @returns {Promise<Object>} The claim result
   */
  private async claimTransfer({
    transfer,
    emit,
    retryCount,
    optimize,
  }: {
    transfer: Transfer;
    emit?: boolean;
    retryCount?: number;
    optimize?: boolean;
  }) {
    const MAX_RETRIES = 5;
    const BASE_DELAY_MS = 1000;
    const MAX_DELAY_MS = 10000;

    if (retryCount && retryCount > 0) {
      const delayMs = Math.min(
        BASE_DELAY_MS * Math.pow(2, retryCount - 1),
        MAX_DELAY_MS,
      );
      await new Promise((resolve) => setTimeout(resolve, delayMs));
    }
    try {
      let result = await this.claimTransferMutex.runExclusive(async () => {
        const leafPubKeyMap =
          await this.transferService.verifyPendingTransfer(transfer);

        let leavesToClaim: LeafKeyTweak[] = [];

        for (const leaf of transfer.leaves) {
          if (leaf.leaf) {
            const leafPubKey = leafPubKeyMap.get(leaf.leaf.id);
            if (leafPubKey) {
              leavesToClaim.push({
                leaf: {
                  ...leaf.leaf,
                  refundTx: leaf.intermediateRefundTx,
                },
                signingPubKey: leafPubKey,
                newSigningPubKey: await this.config.signer.generatePublicKey(
                  sha256(leaf.leaf.id),
                ),
              });
            }
          }
        }

        const response = await this.transferService.claimTransfer(
          transfer,
          leavesToClaim,
        );

        if (emit) {
          this.emit(
            "transfer:claimed",
            transfer.id,
            (await this.getBalance()).balance,
          );
        }

        return response.nodes;
      });

      result = await this.checkRefreshTimelockNodes(result);
      result = await this.checkExtendTimeLockNodes(result);

      const existingIds = new Set(this.leaves.map((leaf) => leaf.id));
      const uniqueResults = result.filter((node) => !existingIds.has(node.id));
      this.leaves.push(...uniqueResults);

      if (optimize && transfer.type !== TransferType.COUNTER_SWAP) {
        await this.optimizeLeaves();
      }

      return result;
    } catch (error) {
      if (retryCount && retryCount < MAX_RETRIES) {
        this.claimTransfer({
          transfer,
          emit,
          retryCount: retryCount + 1,
          optimize,
        });
        return [];
      } else if (retryCount) {
        console.warn(
          "Failed to claim transfer. Please try reinitializing your wallet in a few minutes. Transfer ID: " +
            transfer.id,
          error,
        );
        return [];
      } else {
        throw new NetworkError(
          "Failed to claim transfer",
          {
            operation: "claimTransfer",
            errors: error instanceof Error ? error.message : String(error),
          },
          error instanceof Error ? error : undefined,
        );
      }
    }
  }

  /**
   * Claims all pending transfers.
   *
   * @returns {Promise<string[]>} Array of successfully claimed transfer IDs
   * @private
   */
  private async claimTransfers(
    type?: TransferType,
    emit?: boolean,
  ): Promise<string[]> {
    const transfers = await this.transferService.queryPendingTransfers();
    const promises: Promise<string | null>[] = [];
    for (const transfer of transfers.transfers) {
      if (type && transfer.type !== type) {
        continue;
      }

      if (
        transfer.status !== TransferStatus.TRANSFER_STATUS_SENDER_KEY_TWEAKED &&
        transfer.status !==
          TransferStatus.TRANSFER_STATUS_RECEIVER_KEY_TWEAKED &&
        transfer.status !==
          TransferStatus.TRANSFER_STATUSR_RECEIVER_REFUND_SIGNED &&
        transfer.status !==
          TransferStatus.TRANSFER_STATUS_RECEIVER_KEY_TWEAK_APPLIED
      ) {
        continue;
      }
      promises.push(
        this.claimTransfer({ transfer, emit, optimize: true })
          .then(() => transfer.id)
          .catch((error) => {
            console.warn(`Failed to claim transfer ${transfer.id}:`, error);
            return null;
          }),
      );
    }
    const results = await Promise.allSettled(promises);
    return results
      .filter(
        (result) => result.status === "fulfilled" && result.value !== null,
      )
      .map((result) => (result as PromiseFulfilledResult<string>).value);
  }

  /**
   * Cancels all sender-initiated transfers.
   *
   * @returns {Promise<void>}
   * @private
   */
  private async cancelAllSenderInitiatedTransfers() {
    for (const operator of Object.values(this.config.getSigningOperators())) {
      const transfers =
        await this.transferService.queryPendingTransfersBySender(
          operator.address,
        );

      for (const transfer of transfers.transfers) {
        if (
          transfer.status === TransferStatus.TRANSFER_STATUS_SENDER_INITIATED
        ) {
          await this.transferService.cancelTransfer(transfer, operator.address);
        }
      }
    }
  }

  // ***** Lightning Flow *****

  /**
   * Creates a Lightning invoice for receiving payments.
   *
   * @param {Object} params - Parameters for the lightning invoice
   * @param {number} params.amountSats - Amount in satoshis
   * @param {string} [params.memo] - Description for the invoice. Should not be provided if the descriptionHash is provided.
   * @param {number} [params.expirySeconds] - Optional expiry time in seconds
   * @param {boolean} [params.includeSparkAddress] - Optional boolean signalling whether or not to include the spark address in the invoice
   * @param {string} [params.receiverIdentityPubkey] - Optional public key of the wallet receiving the lightning invoice. If not present, the receiver will be the creator of this request.
   * @param {string} [params.descriptionHash] - Optional h tag of the invoice. This is the hash of a longer description to include in the lightning invoice. It is used in LNURL and UMA as the hash of the metadata. This field is mutually exclusive with the memo field. Only one or the other should be provided.
   * @returns {Promise<LightningReceiveRequest>} BOLT11 encoded invoice
   */
  public async createLightningInvoice({
    amountSats,
    memo,
    expirySeconds = 60 * 60 * 24 * 30,
    includeSparkAddress = false,
    receiverIdentityPubkey,
    descriptionHash,
  }: CreateLightningInvoiceParams): Promise<LightningReceiveRequest> {
    const sspClient = this.getSspClient();

    if (isNaN(amountSats) || amountSats < 0) {
      throw new ValidationError("Invalid amount", {
        field: "amountSats",
        value: amountSats,
        expected: "non-negative number",
      });
    }

    if (!Number.isSafeInteger(amountSats)) {
      throw new ValidationError("Sats amount must be less than 2^53", {
        field: "amountSats",
        value: amountSats,
        expected: "smaller or equal to " + Number.MAX_SAFE_INTEGER,
      });
    }

    if (!Number.isSafeInteger(expirySeconds)) {
      throw new ValidationError("Expiration time must be less than 2^53", {
        field: "expirySeconds",
        value: expirySeconds,
        expected: "smaller or equal to " + Number.MAX_SAFE_INTEGER,
      });
    }

    if (expirySeconds < 0) {
      throw new ValidationError("Invalid expiration time", {
        field: "expirySeconds",
        value: expirySeconds,
        expected: "Non-negative expiration time",
      });
    }

    if (memo && memo.length > 639) {
      throw new ValidationError("Invalid memo size", {
        field: "memo",
        value: memo,
        expected: "Memo size within limits",
      });
    }

    if (memo && descriptionHash) {
      throw new ValidationError(
        "Memo and descriptionHash cannot be provided together. Please provide only one.",
        {
          field: "memo",
          value: memo,
          expected: "Memo or descriptionHash",
        },
      );
    }

    const requestLightningInvoice = async (
      amountSats: number,
      paymentHash: Uint8Array,
      memo?: string,
      receiverIdentityPubkey?: string,
      descriptionHash?: string,
    ) => {
      const network = this.config.getNetwork();
      let bitcoinNetwork: BitcoinNetwork = BitcoinNetwork.REGTEST;
      if (network === Network.MAINNET) {
        bitcoinNetwork = BitcoinNetwork.MAINNET;
      } else if (network === Network.REGTEST) {
        bitcoinNetwork = BitcoinNetwork.REGTEST;
      }

      const invoice = await sspClient.requestLightningReceive({
        amountSats,
        network: bitcoinNetwork,
        paymentHash: bytesToHex(paymentHash),
        expirySecs: expirySeconds,
        memo,
        includeSparkAddress: includeSparkAddress,
        receiverIdentityPubkey,
        descriptionHash,
      });

      if (!invoice) {
        throw new Error("Failed to create lightning invoice");
      }

      // Validate the spark address embedded in the lightning invoice
      if (includeSparkAddress) {
        const sparkFallbackAddress = decodeInvoice(
          invoice.invoice.encodedInvoice,
        ).fallbackAddress;

        if (
          sparkFallbackAddress &&
          isValidSparkFallback(hexToBytes(sparkFallbackAddress))
        ) {
          const invoiceIdentityPubkey = sparkFallbackAddress.slice(6); // remove the 3 byte header
          const expectedIdentityPubkey =
            receiverIdentityPubkey ?? (await this.getIdentityPublicKey());

          if (invoiceIdentityPubkey !== expectedIdentityPubkey) {
            throw new ValidationError(
              "Mismatch between spark identity embedded in lightning invoice and designated recipient spark identity",
              {
                field: "sparkFallbackAddress",
                value: invoiceIdentityPubkey,
                expected: expectedIdentityPubkey,
              },
            );
          }
        } else {
          throw new ValidationError(
            "No valid spark fallback address found in lightning invoice",
            {
              field: "sparkFallbackAddress",
              value: sparkFallbackAddress,
              expected: "Valid spark fallback address",
            },
          );
        }
      }

      return invoice;
    };

    const invoice = await this.lightningService!.createLightningInvoice({
      amountSats,
      memo,
      invoiceCreator: requestLightningInvoice,
      receiverIdentityPubkey,
      descriptionHash,
    });

    return invoice;
  }

  /**
   * Pays a Lightning invoice.
   *
   * @param {Object} params - Parameters for paying the invoice
   * @param {string} params.invoice - The BOLT11-encoded Lightning invoice to pay
   * @param {boolean} [params.preferSpark] - Whether to prefer a spark transfer over lightning for the payment
   * @returns {Promise<LightningSendRequest>} The Lightning payment request details
   */
  public async payLightningInvoice({
    invoice,
    maxFeeSats,
    preferSpark = false,
  }: PayLightningInvoiceParams) {
    const invoiceNetwork = getNetworkFromInvoice(invoice);
    const walletNetwork = this.config.getNetwork();
    if (invoiceNetwork !== walletNetwork) {
      throw new ValidationError(
        `Invoice network: ${invoiceNetwork} does not match wallet network: ${walletNetwork}`,
        {
          field: "invoice",
          value: invoiceNetwork,
          expected: walletNetwork,
        },
      );
    }

    const decodedInvoice = decodeInvoice(invoice);
    const amountSats =
      decodedInvoice.amountMSats !== null
        ? Number(decodedInvoice.amountMSats / 1000n)
        : 0;
    const sparkFallbackAddress = decodedInvoice.fallbackAddress;
    const paymentHash = decodedInvoice.paymentHash;

    // Pay over Spark
    if (preferSpark) {
      if (
        sparkFallbackAddress === undefined ||
        isValidSparkFallback(hexToBytes(sparkFallbackAddress)) === false
      ) {
        console.warn(
          "No valid spark address found in invoice. Defaulting to lightning.",
        );
      } else {
        const identityPublicKey = sparkFallbackAddress.slice(6); // remove the 3 byte header
        const receiverSparkAddress = encodeSparkAddress({
          identityPublicKey,
          network: Network[invoiceNetwork] as NetworkType,
        });
        return await this.transfer({
          amountSats,
          receiverSparkAddress,
        });
      }
    }

    // Pay over Lightning
    return await this.withLeaves(async () => {
      const sspClient = this.getSspClient();

      if (isNaN(amountSats) || amountSats <= 0) {
        throw new ValidationError("Invalid amount", {
          field: "amountSats",
          value: amountSats,
          expected: "positive number",
        });
      }

      const feeEstimate = await this.getLightningSendFeeEstimate({
        encodedInvoice: invoice,
      });

      if (maxFeeSats < feeEstimate) {
        throw new ValidationError("maxFeeSats does not cover fee estimate", {
          field: "maxFeeSats",
          value: maxFeeSats,
          expected: `${feeEstimate} sats`,
        });
      }

      const totalAmount = amountSats + feeEstimate;

      const internalBalance = this.getInternalBalance();
      if (totalAmount > internalBalance) {
        throw new ValidationError("Insufficient balance", {
          field: "balance",
          value: internalBalance,
          expected: `${totalAmount} sats`,
        });
      }

      let leaves = await this.selectLeaves(totalAmount);

      leaves = await this.checkRefreshTimelockNodes(leaves);
      leaves = await this.checkExtendTimeLockNodes(leaves);

      const leavesToSend = await Promise.all(
        leaves.map(async (leaf) => ({
          leaf,
          signingPubKey: await this.config.signer.generatePublicKey(
            sha256(leaf.id),
          ),
          newSigningPubKey: await this.config.signer.generatePublicKey(),
        })),
      );

      const swapResponse = await this.lightningService.swapNodesForPreimage({
        leaves: leavesToSend,
        receiverIdentityPubkey: hexToBytes(
          this.config.getSspIdentityPublicKey(),
        ),
        paymentHash: hexToBytes(paymentHash),
        isInboundPayment: false,
        invoiceString: invoice,
        feeSats: feeEstimate,
      });

      if (!swapResponse.transfer) {
        throw new Error("Failed to swap nodes for preimage");
      }

      const transfer = await this.transferService.sendTransferTweakKey(
        swapResponse.transfer,
        leavesToSend,
        new Map(),
      );

      const sspResponse = await sspClient.requestLightningSend({
        encodedInvoice: invoice,
        idempotencyKey: paymentHash,
      });

      if (!sspResponse) {
        throw new Error("Failed to contact SSP");
      }
      // test
      const leavesToRemove = new Set(leavesToSend.map((leaf) => leaf.leaf.id));
      this.leaves = this.leaves.filter((leaf) => !leavesToRemove.has(leaf.id));

      return sspResponse;
    });
  }

  /**
   * Gets fee estimate for sending Lightning payments.
   *
   * @param {LightningSendFeeEstimateInput} params - Input parameters for fee estimation
   * @returns {Promise<number>} Fee estimate for sending Lightning payments
   */
  public async getLightningSendFeeEstimate({
    encodedInvoice,
  }: LightningSendFeeEstimateInput): Promise<number> {
    const sspClient = this.getSspClient();

    const feeEstimate =
      await sspClient.getLightningSendFeeEstimate(encodedInvoice);

    if (!feeEstimate) {
      throw new Error("Failed to get lightning send fee estimate");
    }
    const satsFeeEstimate = mapCurrencyAmount(feeEstimate.feeEstimate);
    return Math.ceil(satsFeeEstimate.sats);
  }

  // ***** Tree Creation Flow *****

  /**
   * Generates a deposit address for a tree.
   *
   * @param {number} vout - The vout index
   * @param {Uint8Array} parentSigningPubKey - The parent signing public key
   * @param {Transaction} [parentTx] - Optional parent transaction
   * @param {TreeNode} [parentNode] - Optional parent node
   * @returns {Promise<Object>} Deposit address information
   * @private
   */
  private async generateDepositAddressForTree(
    vout: number,
    parentSigningPubKey: Uint8Array,
    parentTx?: Transaction,
    parentNode?: TreeNode,
  ) {
    return await this.treeCreationService!.generateDepositAddressForTree(
      vout,
      parentSigningPubKey,
      parentTx,
      parentNode,
    );
  }

  /**
   * Creates a tree structure.
   *
   * @param {number} vout - The vout index
   * @param {DepositAddressTree} root - The root of the tree
   * @param {boolean} createLeaves - Whether to create leaves
   * @param {Transaction} [parentTx] - Optional parent transaction
   * @param {TreeNode} [parentNode] - Optional parent node
   * @returns {Promise<Object>} The created tree
   * @private
   */
  private async createTree(
    vout: number,
    root: DepositAddressTree,
    createLeaves: boolean,
    parentTx?: Transaction,
    parentNode?: TreeNode,
  ) {
    return await this.treeCreationService!.createTree(
      vout,
      root,
      createLeaves,
      parentTx,
      parentNode,
    );
  }

  // ***** Cooperative Exit Flow *****

  /**
   * Initiates a withdrawal to move funds from the Spark network to an on-chain Bitcoin address.
   *
   * @param {Object} params - Parameters for the withdrawal
   * @param {string} params.onchainAddress - The Bitcoin address where the funds should be sent
   * @param {number} [params.amountSats] - The amount in satoshis to withdraw. If not specified, attempts to withdraw all available funds
   * @returns {Promise<CoopExitRequest | null | undefined>} The withdrawal request details, or null/undefined if the request cannot be completed
   */
  public async withdraw({
    onchainAddress,
    exitSpeed,
    amountSats,
  }: {
    onchainAddress: string;
    exitSpeed: ExitSpeed;
    amountSats?: number;
  }) {
    if (!Number.isSafeInteger(amountSats)) {
      throw new ValidationError("Sats amount must be less than 2^53", {
        field: "amountSats",
        value: amountSats,
        expected: "smaller or equal to " + Number.MAX_SAFE_INTEGER,
      });
    }
    return await this.withLeaves(async () => {
      return await this.coopExit(onchainAddress, exitSpeed, amountSats);
    });
  }

  /**
   * Internal method to perform a cooperative exit (withdrawal).
   *
   * @param {string} onchainAddress - The Bitcoin address where the funds should be sent
   * @param {number} [targetAmountSats] - The amount in satoshis to withdraw
   * @returns {Promise<Object | null | undefined>} The exit request details
   * @private
   */
  private async coopExit(
    onchainAddress: string,
    exitSpeed: ExitSpeed,
    targetAmountSats?: number,
  ) {
    if (!Number.isSafeInteger(targetAmountSats)) {
      throw new ValidationError("Sats amount must be less than 2^53", {
        field: "targetAmountSats",
        value: targetAmountSats,
        expected: "smaller or equal to " + Number.MAX_SAFE_INTEGER,
      });
    }

    let leavesToSend: TreeNode[] = [];
    if (targetAmountSats) {
      leavesToSend = await this.selectLeaves(targetAmountSats);
    } else {
      leavesToSend = this.leaves.map((leaf) => ({
        ...leaf,
      }));
    }

    const sspClient = this.getSspClient();
    const feeEstimate = await sspClient.getCoopExitFeeEstimate({
      leafExternalIds: leavesToSend.map((leaf) => leaf.id),
      withdrawalAddress: onchainAddress,
    });

    if (feeEstimate) {
      let fee: number | undefined;
      switch (exitSpeed) {
        case ExitSpeed.FAST:
          fee =
            (feeEstimate.speedFast?.l1BroadcastFee.originalValue || 0) +
            (feeEstimate.speedFast?.userFee.originalValue || 0);
          break;
        case ExitSpeed.MEDIUM:
          fee =
            (feeEstimate.speedMedium?.l1BroadcastFee.originalValue || 0) +
            (feeEstimate.speedMedium?.userFee.originalValue || 0);
          break;
        case ExitSpeed.SLOW:
          fee =
            (feeEstimate.speedSlow?.l1BroadcastFee.originalValue || 0) +
            (feeEstimate.speedSlow?.userFee.originalValue || 0);
          break;
        default:
          throw new ValidationError("Invalid exit speed", {
            field: "exitSpeed",
            value: exitSpeed,
            expected: "FAST, MEDIUM, or SLOW",
          });
      }

      if (
        fee !== undefined &&
        fee > leavesToSend.reduce((acc, leaf) => acc + leaf.value, 0)
      ) {
        throw new ValidationError(
          "The fee for the withdrawal is greater than the target amount",
          {
            field: "fee",
            value: fee,
            expected: "less than or equal to the target amount",
          },
        );
      }
    }
    leavesToSend = await this.checkRefreshTimelockNodes(leavesToSend);
    leavesToSend = await this.checkExtendTimeLockNodes(leavesToSend);

    const leafKeyTweaks = await Promise.all(
      leavesToSend.map(async (leaf) => ({
        leaf,
        signingPubKey: await this.config.signer.generatePublicKey(
          sha256(leaf.id),
        ),
        newSigningPubKey: await this.config.signer.generatePublicKey(),
      })),
    );

    const coopExitRequest = await sspClient.requestCoopExit({
      leafExternalIds: leavesToSend.map((leaf) => leaf.id),
      withdrawalAddress: onchainAddress,
      idempotencyKey: uuidv7(),
      exitSpeed,
      withdrawAll: true,
    });

    if (!coopExitRequest?.rawConnectorTransaction) {
      throw new Error("Failed to request coop exit");
    }

    const connectorTx = getTxFromRawTxHex(
      coopExitRequest.rawConnectorTransaction,
    );

    const coopExitTxId = connectorTx.getInput(0).txid;
    const connectorTxId = getTxId(connectorTx);

    if (!coopExitTxId) {
      throw new Error("Failed to get coop exit tx id");
    }

    const connectorOutputs: TransactionInput[] = [];
    for (let i = 0; i < connectorTx.outputsLength - 1; i++) {
      connectorOutputs.push({
        txid: hexToBytes(connectorTxId),
        index: i,
      });
    }

    const sspPubIdentityKey = hexToBytes(this.config.getSspIdentityPublicKey());
    const transfer = await this.coopExitService.getConnectorRefundSignatures({
      leaves: leafKeyTweaks,
      exitTxId: coopExitTxId,
      connectorOutputs,
      receiverPubKey: sspPubIdentityKey,
    });

    const completeResponse = await sspClient.completeCoopExit({
      userOutboundTransferExternalId: transfer.transfer.id,
      coopExitRequestId: coopExitRequest.id,
    });

    return completeResponse;
  }

  /**
   * Gets fee estimate for cooperative exit (on-chain withdrawal).
   *
   * @param {Object} params - Input parameters for fee estimation
   * @param {number} params.amountSats - The amount in satoshis to withdraw
   * @param {string} params.withdrawalAddress - The Bitcoin address where the funds should be sent
   * @returns {Promise<CoopExitFeeEstimatesOutput | null>} Fee estimate for the withdrawal
   */
  public async getWithdrawalFeeEstimate({
    amountSats,
    withdrawalAddress,
  }: {
    amountSats: number;
    withdrawalAddress: string;
  }): Promise<CoopExitFeeEstimatesOutput | null> {
    const sspClient = this.getSspClient();

    if (!Number.isSafeInteger(amountSats)) {
      throw new ValidationError("Sats amount must be less than 2^53", {
        field: "amountSats",
        value: amountSats,
        expected: "smaller or equal to " + Number.MAX_SAFE_INTEGER,
      });
    }

    let leaves = await this.selectLeaves(amountSats);

    leaves = await this.checkRefreshTimelockNodes(leaves);
    leaves = await this.checkExtendTimeLockNodes(leaves);

    const feeEstimate = await sspClient.getCoopExitFeeEstimate({
      leafExternalIds: leaves.map((leaf) => leaf.id),
      withdrawalAddress,
    });

    return feeEstimate;
  }

  // ***** Token Flow *****

  /**
   * Synchronizes token outputs for the wallet.
   *
   * @returns {Promise<void>}
   * @private
   */
  protected async syncTokenOutputs() {
    this.tokenOutputs.clear();

    const unsortedTokenOutputs =
      await this.tokenTransactionService.fetchOwnedTokenOutputs(
        [await this.config.signer.getIdentityPublicKey()],
        [],
      );

    const filteredTokenOutputs = unsortedTokenOutputs.filter(
      (output) =>
        !this.pendingWithdrawnOutputIds.includes(output.output?.id || ""),
    );

    const fetchedOutputIds = new Set(
      unsortedTokenOutputs.map((output) => output.output?.id).filter(Boolean),
    );
    this.pendingWithdrawnOutputIds = this.pendingWithdrawnOutputIds.filter(
      (id) => fetchedOutputIds.has(id),
    );

    // Group leaves by token key
    const groupedOutputs = new Map<
      string,
      OutputWithPreviousTransactionData[]
    >();

    filteredTokenOutputs.forEach((output) => {
      const tokenKey = bytesToHex(output.output!.tokenPublicKey!);
      const index = output.previousTransactionVout!;

      if (!groupedOutputs.has(tokenKey)) {
        groupedOutputs.set(tokenKey, []);
      }

      groupedOutputs.get(tokenKey)!.push({
        ...output,
        previousTransactionVout: index,
      });
    });

    this.tokenOutputs = groupedOutputs;
  }

  /**
   * Transfers tokens to another user.
   *
   * @param {Object} params - Parameters for the token transfer
   * @param {string} params.tokenPublicKey - The public key of the token to transfer
   * @param {bigint} params.tokenAmount - The amount of tokens to transfer
   * @param {string} params.receiverSparkAddress - The recipient's public key
   * @param {OutputWithPreviousTransactionData[]} [params.selectedOutputs] - Optional specific leaves to use for the transfer
   * @returns {Promise<string>} The transaction ID of the token transfer
   */
  public async transferTokens({
    tokenPublicKey,
    tokenAmount,
    receiverSparkAddress,
    outputSelectionStrategy,
    selectedOutputs,
  }: {
    tokenPublicKey: string;
    tokenAmount: bigint;
    receiverSparkAddress: string;
    outputSelectionStrategy?: "SMALL_FIRST" | "LARGE_FIRST";
    selectedOutputs?: OutputWithPreviousTransactionData[];
  }): Promise<string> {
    await this.syncTokenOutputs();

    return this.tokenTransactionService.tokenTransfer(
      this.tokenOutputs,
      [
        {
          tokenPublicKey,
          tokenAmount,
          receiverSparkAddress,
        },
      ],
      outputSelectionStrategy ?? "SMALL_FIRST",
      selectedOutputs,
    );
  }

  /**
   * Transfers tokens with multiple outputs
   *
   * @param {Array} receiverOutputs - Array of transfer parameters
   * @param {string} receiverOutputs[].tokenPublicKey - The public key of the token to transfer
   * @param {bigint} receiverOutputs[].tokenAmount - The amount of tokens to transfer
   * @param {string} receiverOutputs[].receiverSparkAddress - The recipient's public key
   * @param {OutputWithPreviousTransactionData[]} [selectedOutputs] - Optional specific leaves to use for the transfer
   * @returns {Promise<string[]>} Array of transaction IDs for the token transfers
   */
  public async batchTransferTokens(
    receiverOutputs: {
      tokenPublicKey: string;
      tokenAmount: bigint;
      receiverSparkAddress: string;
    }[],
    outputSelectionStrategy: "SMALL_FIRST" | "LARGE_FIRST" = "SMALL_FIRST",
    selectedOutputs?: OutputWithPreviousTransactionData[],
  ): Promise<string> {
    if (receiverOutputs.length === 0) {
      throw new ValidationError("At least one receiver output is required", {
        field: "receiverOutputs",
        value: receiverOutputs,
        expected: "Non-empty array",
      });
    }
    const firstTokenPublicKey = receiverOutputs[0]!.tokenPublicKey;
    const allSameToken = receiverOutputs.every(
      (output) => output.tokenPublicKey === firstTokenPublicKey,
    );
    if (!allSameToken) {
      throw new ValidationError(
        "All receiver outputs must have the same token public key",
        {
          field: "receiverOutputs",
          value: receiverOutputs,
          expected: "All outputs must have the same token public key",
        },
      );
    }

    await this.syncTokenOutputs();

    return this.tokenTransactionService.tokenTransfer(
      this.tokenOutputs,
      receiverOutputs,
      outputSelectionStrategy,
      selectedOutputs,
    );
  }

  /**
   * Retrieves token transaction history for specified tokens owned by the wallet.
   * Can optionally filter by specific transaction hashes.
   *
   * @param tokenPublicKeys - Array of token public keys to query transactions for
   * @param tokenTransactionHashes - Optional array of specific transaction hashes to filter by
   * @returns Promise resolving to array of token transactions with their current status
   */
  public async queryTokenTransactions(
    tokenPublicKeys: string[],
    tokenTransactionHashes?: string[],
  ): Promise<TokenTransactionWithStatus[]> {
    const sparkClient = await this.connectionManager.createSparkClient(
      this.config.getCoordinatorAddress(),
    );

    let queryParams;
    if (tokenTransactionHashes?.length) {
      queryParams = {
        tokenPublicKeys: tokenPublicKeys?.map(hexToBytes)!,
        ownerPublicKeys: [hexToBytes(await this.getIdentityPublicKey())],
        tokenTransactionHashes: tokenTransactionHashes.map(hexToBytes),
      };
    } else {
      queryParams = {
        tokenPublicKeys: tokenPublicKeys?.map(hexToBytes)!,
        ownerPublicKeys: [hexToBytes(await this.getIdentityPublicKey())],
      };
    }

    const response = await sparkClient.query_token_transactions(queryParams);
    return response.tokenTransactionsWithStatus;
  }

  public async getTokenL1Address(): Promise<string> {
    return getP2WPKHAddressFromPublicKey(
      await this.config.signer.getIdentityPublicKey(),
      this.config.getNetwork(),
    );
  }

  /**
   * Signs a message with the identity key.
   *
   * @param {string} message - The message to sign
   * @param {boolean} [compact] - Whether to use compact encoding. If false, the message will be encoded as DER.
   * @returns {Promise<string>} The signed message
   */
  public async signMessageWithIdentityKey(
    message: string,
    compact?: boolean,
  ): Promise<string> {
    const hash = sha256(message);
    const signature = await this.config.signer.signMessageWithIdentityKey(
      hash,
      compact,
    );
    return bytesToHex(signature);
  }

  /**
   * Validates a message with the identity key.
   *
   * @param {string} message - The original message that was signed
   * @param {string | Uint8Array} signature - Signature to validate
   * @returns {Promise<boolean>} Whether the message is valid
   */
  public async validateMessageWithIdentityKey(
    message: string,
    signature: string | Uint8Array,
  ): Promise<boolean> {
    const hash = sha256(message);
    if (typeof signature === "string") {
      signature = hexToBytes(signature);
    }
    return this.config.signer.validateMessageWithIdentityKey(hash, signature);
  }

  /**
   * Signs a transaction with wallet keys.
   *
   * @param {string} txHex - The transaction hex to sign
   * @param {string} keyType - The type of key to use for signing ("identity", "deposit", or "auto-detect")
   * @returns {Promise<string>} The signed transaction hex
   */
  public async signTransaction(
    txHex: string,
    keyType: string = "auto-detect",
  ): Promise<string> {
    try {
      // Parse the transaction
      const tx = Transaction.fromRaw(hexToBytes(txHex));

      let publicKey: Uint8Array;

      switch (keyType.toLowerCase()) {
        case "identity":
          publicKey = await this.config.signer.getIdentityPublicKey();
          break;
        case "deposit":
          publicKey = await this.config.signer.getDepositSigningKey();
          break;
        case "auto-detect":
        default:
          // Try to auto-detect which key to use by examining the transaction inputs
          const detectedKey = await this.detectKeyForTransaction(tx);
          if (detectedKey) {
            publicKey = detectedKey.publicKey;
          } else {
            // Fallback to identity key
            publicKey = await this.config.signer.getIdentityPublicKey();
          }
          break;
      }

      // Check each input to determine which ones need signing
      let inputsSigned = 0;
      for (let i = 0; i < tx.inputsLength; i++) {
        const input = tx.getInput(i);
        if (!input?.witnessUtxo?.script) {
          continue;
        }

        const script = input.witnessUtxo.script;

        // Check if this is an ephemeral anchor (OP_TRUE script)
        // OP_TRUE is represented as a single byte: 0x51
        if (script.length === 1 && script[0] === 0x51) {
          continue;
        }

        // Check if this script matches one of our keys
        const identityScript = getP2TRScriptFromPublicKey(
          publicKey,
          this.config.getNetwork(),
        );

        if (bytesToHex(script) === bytesToHex(identityScript)) {
          // Sign this specific input
          try {
            this.config.signer.signTransactionIndex(tx, i, publicKey);
            inputsSigned++;
          } catch (error) {
            throw new ValidationError(`Failed to sign input ${i}: ${error}`, {
              field: "input",
              value: i,
            });
          }
        }
      }

      if (inputsSigned === 0) {
        throw new Error(
          "No inputs were signed. Check that the transaction contains inputs controlled by this wallet.",
        );
      }

      tx.finalize();

      const signedTxHex = tx.hex;

      return signedTxHex;
    } catch (error) {
      console.error("❌ Error signing transaction:", error);
      throw error;
    }
  }

  /**
   * Helper method to auto-detect which key should be used for signing a transaction.
   */
  private async detectKeyForTransaction(tx: Transaction): Promise<{
    publicKey: Uint8Array;
    keyType: string;
  } | null> {
    try {
      // Get available keys
      const identityPubKey = await this.config.signer.getIdentityPublicKey();
      const depositPubKey = await this.config.signer.getDepositSigningKey();

      // Check if any inputs reference outputs that would be controlled by our keys
      for (let i = 0; i < tx.inputsLength; i++) {
        const input = tx.getInput(i);
        if (input?.witnessUtxo?.script) {
          const script = input.witnessUtxo.script;

          // Check if this script corresponds to one of our keys
          // This is a simplified check - in practice, you might need more sophisticated script analysis
          const identityScript = getP2TRScriptFromPublicKey(
            identityPubKey,
            this.config.getNetwork(),
          );
          const depositScript = getP2TRScriptFromPublicKey(
            depositPubKey,
            this.config.getNetwork(),
          );

          if (bytesToHex(script) === bytesToHex(identityScript)) {
            return {
              publicKey: identityPubKey,
              keyType: "identity",
            };
          }

          if (bytesToHex(script) === bytesToHex(depositScript)) {
            return {
              publicKey: depositPubKey,
              keyType: "deposit",
            };
          }
        }
      }

      return null;
    } catch (error) {
      console.warn("Error during key auto-detection:", error);
      return null;
    }
  }

  /**
   * Get a Lightning receive request by ID.
   *
   * @param {string} id - The ID of the Lightning receive request
   * @returns {Promise<LightningReceiveRequest | null>} The Lightning receive request
   */
  public async getLightningReceiveRequest(
    id: string,
  ): Promise<LightningReceiveRequest | null> {
    const sspClient = this.getSspClient();
    return await sspClient.getLightningReceiveRequest(id);
  }

  /**
   * Get a Lightning send request by ID.
   *
   * @param {string} id - The ID of the Lightning send request
   * @returns {Promise<LightningSendRequest | null>} The Lightning send request
   */
  public async getLightningSendRequest(
    id: string,
  ): Promise<LightningSendRequest | null> {
    const sspClient = this.getSspClient();
    return await sspClient.getLightningSendRequest(id);
  }

  /**
   * Get a coop exit request by ID.
   *
   * @param {string} id - The ID of the coop exit request
   * @returns {Promise<CoopExitRequest | null>} The coop exit request
   */
  public async getCoopExitRequest(id: string): Promise<CoopExitRequest | null> {
    const sspClient = this.getSspClient();
    return await sspClient.getCoopExitRequest(id);
  }

  /**
   * Check the remaining timelock on a given node.
   *
   * @param {string} nodeId - The ID of the node to check
   * @returns {Promise<{nodeTimelock: number, refundTimelock: number}>} The remaining timelocks in blocks for both node and refund transactions
   */
  public async checkTimelock(nodeId: string): Promise<{
    nodeTimelock: number;
    refundTimelock: number;
  }> {
    const sparkClient = await this.connectionManager.createSparkClient(
      this.config.getCoordinatorAddress(),
    );

    try {
      const response = await sparkClient.query_nodes({
        source: {
          $case: "nodeIds",
          nodeIds: {
            nodeIds: [nodeId],
          },
        },
        includeParents: false,
        network: NetworkToProto[this.config.getNetwork()],
      });

      const node = response.nodes[nodeId];
      if (!node) {
        throw new ValidationError("Node not found", {
          field: "nodeId",
          value: nodeId,
        });
      }

      // Check if this is a root node (no parent)
      const isRootNode = !node.parentNodeId;

      // Validate transaction data exists
      if (!node.nodeTx || node.nodeTx.length === 0) {
        throw new ValidationError(
          `Node transaction data is missing or empty for ${isRootNode ? "root" : "non-root"} node`,
          {
            field: "nodeTx",
            value: node.nodeTx?.length || 0,
          },
        );
      }

      if (!node.refundTx || node.refundTx.length === 0) {
        throw new ValidationError(
          `Refund transaction data is missing or empty for ${isRootNode ? "root" : "non-root"} node`,
          {
            field: "refundTx",
            value: node.refundTx?.length || 0,
          },
        );
      }

      let nodeTx, refundTx;

      try {
        // Get the node transaction to check its timelock
        nodeTx = getTxFromRawTxBytes(node.nodeTx);
      } catch (error) {
        throw new ValidationError(
          `Failed to parse node transaction for ${isRootNode ? "root" : "non-root"} node: ${error instanceof Error ? error.message : String(error)}`,
          {
            field: "nodeTx",
            value: node.nodeTx.length,
          },
        );
      }

      try {
        // Get the refund transaction to check its timelock
        refundTx = getTxFromRawTxBytes(node.refundTx);
      } catch (error) {
        throw new ValidationError(
          `Failed to parse refund transaction for ${isRootNode ? "root" : "non-root"} node: ${error instanceof Error ? error.message : String(error)}`,
          {
            field: "refundTx",
            value: node.refundTx.length,
          },
        );
      }

      const nodeInput = nodeTx.getInput(0);
      if (!nodeInput) {
        throw new ValidationError(
          `Node transaction has no inputs for ${isRootNode ? "root" : "non-root"} node`,
          {
            field: "nodeInput",
            value: nodeTx.inputsLength,
          },
        );
      }

      if (!nodeInput.sequence) {
        throw new ValidationError(
          `Node transaction has no sequence for ${isRootNode ? "root" : "non-root"} node`,
          {
            field: "sequence",
            value: nodeInput.sequence,
          },
        );
      }

      const refundInput = refundTx.getInput(0);
      if (!refundInput) {
        throw new ValidationError(
          `Refund transaction has no inputs for ${isRootNode ? "root" : "non-root"} node`,
          {
            field: "refundInput",
            value: refundTx.inputsLength,
          },
        );
      }

      if (!refundInput.sequence) {
        throw new ValidationError(
          `Refund transaction has no sequence for ${isRootNode ? "root" : "non-root"} node`,
          {
            field: "sequence",
            value: refundInput.sequence,
          },
        );
      }

      // Extract timelock from sequence (lower 16 bits)
      const nodeTimelock = nodeInput.sequence & 0xffff;
      const refundTimelock = refundInput.sequence & 0xffff;

      return {
        nodeTimelock,
        refundTimelock,
      };
    } catch (error) {
      throw new NetworkError(
        `Failed to check timelock for node ${nodeId}`,
        {
          method: "query_nodes",
        },
        error as Error,
      );
    }
  }

  /**
   * Refresh the timelock of a specific node.
   *
   * @param {string} nodeId - The ID of the node to refresh
   * @returns {Promise<void>} Promise that resolves when the timelock is refreshed
   */
  public async testOnly_expireTimelock(nodeId: string): Promise<void> {
    const sparkClient = await this.connectionManager.createSparkClient(
      this.config.getCoordinatorAddress(),
    );

    try {
      // First, get the node and its parent
      const response = await sparkClient.query_nodes({
        source: {
          $case: "nodeIds",
          nodeIds: {
            nodeIds: [nodeId],
          },
        },
        includeParents: true,
      });

      const node = response.nodes[nodeId];
      if (!node) {
        throw new ValidationError("Node not found", {
          field: "nodeId",
          value: nodeId,
        });
      }

      if (!node.parentNodeId) {
        throw new ValidationError("Node has no parent", {
          field: "parentNodeId",
          value: node.parentNodeId,
        });
      }

      const parentNode = response.nodes[node.parentNodeId];
      if (!parentNode) {
        throw new ValidationError("Parent node not found", {
          field: "parentNodeId",
          value: node.parentNodeId,
        });
      }

      // Generate signing public key for this node
      const signingPubKey = await this.config.signer.generatePublicKey(
        sha256(node.id),
      );

      // Call the transfer service to refresh the timelock
      const result = await this.transferService.refreshTimelockNodes(
        [node],
        parentNode,
        signingPubKey,
      );

      // Update the local leaves if this node is in our wallet
      const leafIndex = this.leaves.findIndex((leaf) => leaf.id === node.id);
      if (leafIndex !== -1 && result.nodes.length > 0) {
        const newNode = result.nodes[0];
        if (newNode) {
          this.leaves[leafIndex] = newNode;
        }
      }
    } catch (error) {
      throw new NetworkError(
        "Failed to refresh timelock",
        {
          method: "refresh_timelock",
        },
        error as Error,
      );
    }
  }

  /**
   * Refresh the timelock of a specific node's refund transaction only.
   *
   * @param {string} nodeId - The ID of the node whose refund transaction to refresh
   * @returns {Promise<void>} Promise that resolves when the refund timelock is refreshed
   */
  public async testOnly_expireTimelockRefundTx(nodeId: string): Promise<void> {
    const sparkClient = await this.connectionManager.createSparkClient(
      this.config.getCoordinatorAddress(),
    );

    try {
      // Get the node
      const response = await sparkClient.query_nodes({
        source: {
          $case: "nodeIds",
          nodeIds: {
            nodeIds: [nodeId],
          },
        },
        includeParents: false,
      });

      const node = response.nodes[nodeId];
      if (!node) {
        throw new ValidationError("Node not found", {
          field: "nodeId",
          value: nodeId,
        });
      }

      // Generate signing public key for this node
      const signingPubKey = await this.config.signer.generatePublicKey(
        sha256(node.id),
      );

      // Call the transfer service to refresh the refund timelock
      const result = await this.transferService.refreshTimelockRefundTx(
        node,
        signingPubKey,
      );

      // Update the local leaves if this node is in our wallet
      const leafIndex = this.leaves.findIndex((leaf) => leaf.id === node.id);
      if (leafIndex !== -1 && result.nodes.length > 0) {
        const newNode = result.nodes[0];
        if (newNode) {
          this.leaves[leafIndex] = newNode;
        }
      }
    } catch (error) {
      throw new NetworkError(
        "Failed to refresh refund timelock",
        {
          method: "refresh_timelock_refund_tx",
        },
        error as Error,
      );
    }
  }

  private cleanup() {
    if (this.claimTransfersInterval) {
      clearInterval(this.claimTransfersInterval);
      this.claimTransfersInterval = null;
    }
    this.streamController?.abort();
    this.removeAllListeners();
  }

  public async cleanupConnections() {
    this.cleanup();
    await this.connectionManager.closeConnections();
    await this.lrc20ConnectionManager.closeConnection();
  }

  // Add this new method to start periodic claiming
  private startPeriodicClaimTransfers() {
    // Clear any existing interval first
    if (this.claimTransfersInterval) {
      clearInterval(this.claimTransfersInterval);
    }

    // Set up new interval to claim transfers every 5 seconds
    // @ts-ignore
    this.claimTransfersInterval = setInterval(async () => {
      try {
        await this.claimTransfers(undefined, true);
      } catch (error) {
        console.error("Error in periodic transfer claiming:", error);
      }
    }, 10000);
  }

  private async updateLeaves(
    leavesToRemove: string[],
    leavesToAdd: TreeNode[],
  ) {
    const leavesToRemoveSet = new Set(leavesToRemove);
    this.leaves = this.leaves.filter((leaf) => !leavesToRemoveSet.has(leaf.id));
    this.leaves.push(...leavesToAdd);
  }

  private async queryNodes(
    baseRequest: Omit<QueryNodesRequest, "limit" | "offset">,
    sparkClientAddress?: string,
    pageSize: number = 100,
  ): Promise<QueryNodesResponse> {
    const address = sparkClientAddress ?? this.config.getCoordinatorAddress();
    const aggregatedNodes: {
      [key: string]: QueryNodesResponse["nodes"][string];
    } = {};
    let offset = 0;

    while (true) {
      const sparkClient =
        await this.connectionManager.createSparkClient(address);

      const response = await sparkClient.query_nodes({
        ...baseRequest,
        limit: pageSize,
        offset,
      });

      /* Merge nodes from this page. If user is sending or receiving payments results can shift
         accross pages, potentially causing duplicates. Dedupe by node id: */
      Object.assign(aggregatedNodes, response.nodes ?? {});

      /* If we received fewer nodes than requested, this was the last page. */
      const received = Object.keys(response.nodes ?? {}).length;
      if (received < pageSize) {
        return {
          nodes: aggregatedNodes,
          offset: response.offset,
        } as QueryNodesResponse;
      }

      offset += pageSize;
    }
  }
}
