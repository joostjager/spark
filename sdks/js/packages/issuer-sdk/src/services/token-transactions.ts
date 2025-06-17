import { WalletConfigService } from "@buildonspark/spark-sdk/config";
import { ConnectionManager } from "@buildonspark/spark-sdk/connection";
import { TokenTransaction as TokenTransactionV0 } from "@buildonspark/spark-sdk/proto/spark";
import { TokenTransaction } from "@buildonspark/spark-sdk/proto/spark_token";
import { TokenTransactionService } from "@buildonspark/spark-sdk/token-transactions";
import { numberToBytesBE } from "@noble/curves/abstract/utils";

export class IssuerTokenTransactionService extends TokenTransactionService {
  constructor(
    config: WalletConfigService,
    connectionManager: ConnectionManager,
  ) {
    super(config, connectionManager);
  }

  async constructMintTokenTransactionV0(
    tokenPublicKey: Uint8Array,
    tokenAmount: bigint,
  ): Promise<TokenTransactionV0> {
    return {
      network: this.config.getNetworkProto(),
      tokenInputs: {
        $case: "mintInput",
        mintInput: {
          issuerPublicKey: tokenPublicKey,
          issuerProvidedTimestamp: Date.now(),
        },
      },
      tokenOutputs: [
        {
          ownerPublicKey: tokenPublicKey,
          tokenPublicKey: tokenPublicKey,
          tokenAmount: numberToBytesBE(tokenAmount, 16),
        },
      ],
      sparkOperatorIdentityPublicKeys:
        super.collectOperatorIdentityPublicKeys(),
    };
  }

  async constructMintTokenTransaction(
    tokenPublicKey: Uint8Array,
    tokenAmount: bigint,
  ): Promise<TokenTransaction> {
    return {
      version: 1,
      network: this.config.getNetworkProto(),
      tokenInputs: {
        $case: "mintInput",
        mintInput: {
          issuerPublicKey: tokenPublicKey,
          issuerProvidedTimestamp: Date.now(),
        },
      },
      tokenOutputs: [
        {
          ownerPublicKey: tokenPublicKey,
          tokenPublicKey: tokenPublicKey,
          tokenAmount: numberToBytesBE(tokenAmount, 16),
        },
      ],
      sparkOperatorIdentityPublicKeys:
        super.collectOperatorIdentityPublicKeys(),
      expiryTime: undefined,
    };
  }
}
