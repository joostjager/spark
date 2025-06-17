import { numberToBytesBE } from "@noble/curves/abstract/utils";
import { hashTokenTransaction } from "../utils/token-hashing.js";
import { Network, OutputWithPreviousTransactionData } from "../proto/spark.js";
import { TokenTransactionService } from "../services/token-transactions.js";
import { WalletConfigService } from "../services/config.js";
import { ConnectionManager } from "../services/connection.js";

describe("hash token transaction", () => {
  it("should produce the exact same hash", () => {
    const tokenAmount: bigint = 1000n;

    const tokenPublicKey = new Uint8Array([
      242, 155, 208, 90, 72, 211, 120, 244, 69, 99, 28, 101, 149, 222, 123, 50,
      252, 63, 99, 54, 137, 226, 7, 224, 163, 122, 93, 248, 42, 159, 173, 45,
    ]);

    const identityPubKey = new Uint8Array([
      25, 155, 208, 90, 72, 211, 120, 244, 69, 99, 28, 101, 149, 222, 123, 50,
      252, 63, 99, 54, 137, 226, 7, 224, 163, 122, 93, 248, 42, 159, 173, 46,
    ]);

    const tokenTransaction = {
      tokenInputs: {
        $case: "mintInput" as const,
        mintInput: {
          issuerPublicKey: tokenPublicKey,
          issuerProvidedTimestamp: 100,
        },
      },
      tokenOutputs: [
        {
          id: "db1a4e48-0fc5-4f6c-8a80-d9d6c561a436",
          ownerPublicKey: identityPubKey,
          withdrawBondSats: 10000,
          withdrawRelativeBlockLocktime: 100,
          tokenPublicKey: tokenPublicKey,
          tokenAmount: numberToBytesBE(tokenAmount, 16),
          revocationCommitment: identityPubKey,
        },
      ],
      sparkOperatorIdentityPublicKeys: [],
      network: Network.REGTEST,
    };

    const hash = hashTokenTransaction(tokenTransaction, false);

    expect(Array.from(hash)).toEqual([
      66, 235, 134, 101, 172, 110, 147, 77, 122, 48, 86, 240, 239, 9, 163, 82,
      120, 234, 246, 206, 245, 242, 186, 180, 154, 41, 207, 179, 194, 31, 211,
      36,
    ]);
  });
});

describe("select token outputs", () => {
  let tokenTransactionService: TokenTransactionService;

  beforeEach(() => {
    const mockConfig = {} as WalletConfigService;
    const mockConnectionManager = {} as ConnectionManager;
    tokenTransactionService = new TokenTransactionService(
      mockConfig,
      mockConnectionManager,
    );
  });

  const createMockTokenOutput = (
    id: string,
    tokenAmount: bigint,
    tokenPublicKey: Uint8Array = new Uint8Array(32).fill(1),
    ownerPublicKey: Uint8Array = new Uint8Array(32).fill(2),
  ): OutputWithPreviousTransactionData => ({
    output: {
      id,
      ownerPublicKey,
      tokenPublicKey,
      tokenAmount: numberToBytesBE(tokenAmount, 16),
      revocationCommitment: new Uint8Array(32).fill(3),
    },
    previousTransactionHash: new Uint8Array(32).fill(4),
    previousTransactionVout: 0,
  });

  describe("exact match scenarios", () => {
    it("should return exact match when available", () => {
      const tokenOutputs = [
        createMockTokenOutput("output1", 100n),
        createMockTokenOutput("output2", 500n),
        createMockTokenOutput("output3", 1000n),
      ];

      const result = tokenTransactionService.selectTokenOutputs(
        tokenOutputs,
        500n,
        "SMALL_FIRST",
      );

      expect(result).toHaveLength(1);
      expect(result[0]!.output!.id).toBe("output2");
    });
  });

  describe("SMALL_FIRST strategy", () => {
    it("should select smallest outputs first when no exact match", () => {
      const tokenOutputs = [
        createMockTokenOutput("output1", 1000n),
        createMockTokenOutput("output2", 100n),
        createMockTokenOutput("output3", 300n),
      ];

      const result = tokenTransactionService.selectTokenOutputs(
        tokenOutputs,
        350n,
        "SMALL_FIRST",
      );

      expect(result).toHaveLength(2);
      expect(result[0]!.output!.id).toBe("output2"); // 100n
      expect(result[1]!.output!.id).toBe("output3"); // 300n
      // Total: 400n >= 350n
    });

    it("should select minimum number of outputs needed", () => {
      const tokenOutputs = [
        createMockTokenOutput("output1", 50n),
        createMockTokenOutput("output2", 100n),
        createMockTokenOutput("output3", 200n),
        createMockTokenOutput("output4", 1000n),
      ];

      const result = tokenTransactionService.selectTokenOutputs(
        tokenOutputs,
        300n,
        "SMALL_FIRST",
      );

      expect(result).toHaveLength(3);
      expect(result[0]!.output!.id).toBe("output1"); // 50n
      expect(result[1]!.output!.id).toBe("output2"); // 100n
      expect(result[2]!.output!.id).toBe("output3"); // 200n
      // Total: 350n >= 300n
    });
  });

  describe("LARGE_FIRST strategy", () => {
    it("should select largest outputs first when no exact match", () => {
      const tokenOutputs = [
        createMockTokenOutput("output1", 100n),
        createMockTokenOutput("output2", 1000n),
        createMockTokenOutput("output3", 300n),
      ];

      const result = tokenTransactionService.selectTokenOutputs(
        tokenOutputs,
        350n,
        "LARGE_FIRST",
      );

      expect(result).toHaveLength(1);
      expect(result[0]!.output!.id).toBe("output2"); // 1000n >= 350n
    });

    it("should select multiple outputs if largest is insufficient", () => {
      const tokenOutputs = [
        createMockTokenOutput("output1", 100n),
        createMockTokenOutput("output2", 200n),
        createMockTokenOutput("output3", 150n),
      ];

      const result = tokenTransactionService.selectTokenOutputs(
        tokenOutputs,
        350n,
        "LARGE_FIRST",
      );

      expect(result).toHaveLength(2);
      expect(result[0]!.output!.id).toBe("output2"); // 200n
      expect(result[1]!.output!.id).toBe("output3"); // 150n
      // Total: 350n >= 350n
    });
  });

  describe("edge cases", () => {
    it("should handle single output that exactly matches", () => {
      const tokenOutputs = [createMockTokenOutput("output1", 500n)];

      const result = tokenTransactionService.selectTokenOutputs(
        tokenOutputs,
        500n,
        "SMALL_FIRST",
      );

      expect(result).toHaveLength(1);
      expect(result[0]!.output!.id).toBe("output1");
    });

    it("should handle zero amount request", () => {
      const tokenOutputs = [createMockTokenOutput("output1", 100n)];

      const result = tokenTransactionService.selectTokenOutputs(
        tokenOutputs,
        0n,
        "SMALL_FIRST",
      );

      expect(result).toHaveLength(0);
    });

    it("should select all outputs if needed", () => {
      const tokenOutputs = [
        createMockTokenOutput("output1", 100n),
        createMockTokenOutput("output2", 200n),
        createMockTokenOutput("output3", 300n),
      ];

      const result = tokenTransactionService.selectTokenOutputs(
        tokenOutputs,
        600n,
        "SMALL_FIRST",
      );

      expect(result).toHaveLength(3);
      // Total: 600n >= 600n
    });
  });
});
