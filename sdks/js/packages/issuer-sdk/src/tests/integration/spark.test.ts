import { filterTokenBalanceForTokenPublicKey } from "@buildonspark/spark-sdk/utils";
import { jest } from "@jest/globals";
import { encodeSparkAddress } from "@buildonspark/spark-sdk/address";
import {
  LOCAL_WALLET_CONFIG_ECDSA,
  LOCAL_WALLET_CONFIG_SCHNORR,
} from "../../../../spark-sdk/src/services/wallet-config.js";
import { BitcoinFaucet } from "../../../../spark-sdk/src/tests/utils/test-faucet.js";
import { IssuerSparkWalletTesting } from "../utils/issuer-test-wallet.js";
import { SparkWalletTesting } from "../utils/spark-testing-wallet.js";
import { IssuerSparkWallet } from "../../index.js";
import { OperationType } from "@buildonspark/spark-sdk/proto/lrc20";

function hexStringToUint8Array(hexString) {
  if (hexString.length % 2 !== 0) {
    throw new Error("Hex string must have an even number of characters.");
  }

  const uint8Array = new Uint8Array(hexString.length / 2);

  for (let i = 0; i < hexString.length; i += 2) {
    const byte = parseInt(hexString.substring(i, i + 2), 16);
    uint8Array[i / 2] = byte;
  }

  return uint8Array;
}

const brokenTestFn = process.env.GITHUB_ACTIONS ? it.skip : it;
describe("token integration tests", () => {
  jest.setTimeout(80000);

  it("should fail when minting tokens without announcement", async () => {
    const tokenAmount: bigint = 1000n;
    const { wallet } = await IssuerSparkWalletTesting.initialize({
      options: LOCAL_WALLET_CONFIG_ECDSA,
    });

    await expect(wallet.mintTokens(tokenAmount)).rejects.toThrow();
  });

  it("should fail when announce decimal is greater than js MAX_SAFE_INTEGER", async () => {
    const tokenAmount: bigint = 1000n;
    const { wallet } = await IssuerSparkWalletTesting.initialize({
      options: LOCAL_WALLET_CONFIG_ECDSA,
    });

    await expect(
      fundAndAnnounce(
        wallet,
        tokenAmount,
        2 ** 53,
        "2Pow53Decimal",
        "2P53D",
        false,
      ),
    ).rejects.toThrow();
  });

  it("should fail when minting more than max supply", async () => {
    const tokenAmount: bigint = 1000n;
    const { wallet } = await IssuerSparkWalletTesting.initialize({
      options: LOCAL_WALLET_CONFIG_SCHNORR,
    });

    await fundAndAnnounce(wallet, 2n, 0, "MaxSupply", "MST");
    await expect(wallet.mintTokens(tokenAmount)).rejects.toThrow();
  });

  it("should announce token and issue tokens successfully", async () => {
    const tokenAmount: bigint = 1000n;
    const tokenName = "AnnounceIssue";
    const tokenSymbol = "AIT";
    const { wallet } = await IssuerSparkWalletTesting.initialize({
      options: LOCAL_WALLET_CONFIG_SCHNORR,
    });

    await fundAndAnnounce(wallet, 100000n, 0, tokenName, tokenSymbol);

    const publicKeyInfo = await wallet.getIssuerTokenInfo();

    // Assert token public key info values
    const identityPublicKey = await wallet.getIdentityPublicKey();
    expect(publicKeyInfo?.tokenName).toEqual(tokenName);
    expect(publicKeyInfo?.tokenSymbol).toEqual(tokenSymbol);
    expect(publicKeyInfo?.tokenDecimals).toEqual(0);
    expect(publicKeyInfo?.maxSupply).toEqual(100000n);
    expect(publicKeyInfo?.isFreezable).toEqual(false);

    // Compare the public key using bytesToHex
    const pubKeyHex = publicKeyInfo?.tokenPublicKey;
    expect(pubKeyHex).toEqual(identityPublicKey);

    await wallet.mintTokens(tokenAmount);

    const tokenBalance = await wallet.getIssuerTokenBalance();
    expect(tokenBalance.balance).toEqual(tokenAmount);
  });

  it("should announce, mint, and transfer tokens with ECDSA", async () => {
    const tokenAmount: bigint = 1000n;

    const { wallet: issuerWallet } = await IssuerSparkWalletTesting.initialize({
      options: LOCAL_WALLET_CONFIG_ECDSA,
    });

    const { wallet: destinationWallet } = await SparkWalletTesting.initialize({
      options: LOCAL_WALLET_CONFIG_ECDSA,
    });

    await fundAndAnnounce(issuerWallet, 100000n, 0, "ECDSATransfer", "ETT");

    await issuerWallet.mintTokens(tokenAmount);
    await issuerWallet.transferTokens({
      tokenAmount,
      tokenPublicKey: await issuerWallet.getIdentityPublicKey(),
      receiverSparkAddress: await destinationWallet.getSparkAddress(),
    });
    const sourceBalance = (await issuerWallet.getIssuerTokenBalance()).balance;
    expect(sourceBalance).toEqual(0n);

    const tokenPublicKey = await issuerWallet.getIdentityPublicKey();
    const balanceObj = await destinationWallet.getBalance();
    const destinationBalance = filterTokenBalanceForTokenPublicKey(
      balanceObj?.tokenBalances,
      tokenPublicKey,
    );
    expect(destinationBalance.balance).toEqual(tokenAmount);
  });

  it("should announce, mint, get list all transactions, and transfer tokens with ECDSA multiple times, get list all transactions again and check difference", async () => {
    const tokenAmount: bigint = 100n;

    const { wallet: issuerWallet } = await IssuerSparkWalletTesting.initialize({
      options: LOCAL_WALLET_CONFIG_ECDSA,
    });

    const { wallet: destinationWallet } = await SparkWalletTesting.initialize({
      options: LOCAL_WALLET_CONFIG_ECDSA,
    });

    await fundAndAnnounce(issuerWallet, 100000n, 0, "ECDSATransfer", "ETT");

    {
      const transactions = await issuerWallet.getIssuerTokenActivity();
      const amount_of_transactions = transactions.transactions.length;
      expect(amount_of_transactions).toEqual(0);
    }

    await issuerWallet.mintTokens(tokenAmount);

    {
      const transactions = await issuerWallet.getIssuerTokenActivity();
      const amount_of_transactions = transactions.transactions.length;
      expect(amount_of_transactions).toEqual(1);
    }

    await issuerWallet.transferTokens({
      tokenAmount,
      tokenPublicKey: await issuerWallet.getIdentityPublicKey(),
      receiverSparkAddress: await destinationWallet.getSparkAddress(),
    });

    {
      const transactions = await issuerWallet.getIssuerTokenActivity();
      const amount_of_transactions = transactions.transactions.length;
      expect(amount_of_transactions).toEqual(2);
    }

    for (let index = 0; index < 100; ++index) {
      await issuerWallet.mintTokens(tokenAmount);
      await issuerWallet.transferTokens({
        tokenAmount,
        tokenPublicKey: await issuerWallet.getIdentityPublicKey(),
        receiverSparkAddress: await destinationWallet.getSparkAddress(),
      });
    } // 202 in total

    let all_transactions = await issuerWallet.getIssuerTokenActivity(250);
    const amount_of_transactions = all_transactions.transactions.length;
    expect(amount_of_transactions).toEqual(202);

    {
      const transactions = await issuerWallet.getIssuerTokenActivity(10);
      const amount_of_transactions = transactions.transactions.length;
      expect(amount_of_transactions).toEqual(10);
    }

    {
      let hashset_of_all_transactions: Set<String> = new Set();

      let transactions = await issuerWallet.getIssuerTokenActivity(10);
      let amount_of_transactions = transactions.transactions.length;
      expect(amount_of_transactions).toEqual(10);
      let page_num = 0;
      for (let index = 0; index < transactions.transactions.length; ++index) {
        const element = transactions.transactions[index];
        if (!(element.transaction === undefined)) {
          let hash: String = "";
          if (element.transaction.$case === "spark") {
            hash = element.transaction.spark.transactionHash;
          } else if (element.transaction.$case === "onChain") {
            hash = element.transaction.onChain.transactionHash;
          }
          if (hashset_of_all_transactions.has(hash)) {
            expect(
              `Dublicate found. Pagination is broken? Index of transaction: ${index} ; page №: ${page_num} ; page size: 10 ; hash_dublicate: ${hash}`,
            ).toEqual("");
          } else {
            hashset_of_all_transactions.add(hash);
          }
        } else {
          expect(
            `Transaction is undefined. Something is really wrong. Index of transaction: ${index} ; page №: ${page_num} ; page size: 10`,
          ).toEqual("");
        }
      }

      while (!(undefined === transactions.nextCursor)) {
        let transactions_2 = await issuerWallet.getIssuerTokenActivity(10, {
          lastTransactionHash: hexStringToUint8Array(
            transactions.nextCursor.lastTransactionHash,
          ),
          layer: transactions.nextCursor.layer,
        });

        ++page_num;

        for (
          let index = 0;
          index < transactions_2.transactions.length;
          ++index
        ) {
          const element = transactions_2.transactions[index];
          if (!(element.transaction === undefined)) {
            let hash: String = "";
            if (element.transaction.$case === "spark") {
              hash = element.transaction.spark.transactionHash;
            } else if (element.transaction.$case === "onChain") {
              hash = element.transaction.onChain.transactionHash;
            }
            if (hashset_of_all_transactions.has(hash)) {
              expect(
                `Dublicate found. Pagination is broken? Index of transaction: ${index} ; page №: ${page_num} ; page size: 10 ; hash_dublicate: ${hash}`,
              ).toEqual("");
            } else {
              hashset_of_all_transactions.add(hash);
            }
          } else {
            expect(
              `Transaction is undefined. Something is really wrong. Index of transaction: ${index} ; page №: ${page_num} ; page size: 10`,
            ).toEqual("");
          }
        }

        transactions = transactions_2;
      }

      expect(hashset_of_all_transactions.size == 202);
    }
  });

  it("should announce, mint, and batchtransfer tokens with ECDSA", async () => {
    const tokenAmount: bigint = 999n;

    const { wallet: issuerWallet } = await IssuerSparkWalletTesting.initialize({
      options: LOCAL_WALLET_CONFIG_ECDSA,
    });

    const { wallet: destinationWallet } = await SparkWalletTesting.initialize({
      options: LOCAL_WALLET_CONFIG_ECDSA,
    });

    const { wallet: destinationWallet2 } = await SparkWalletTesting.initialize({
      options: LOCAL_WALLET_CONFIG_ECDSA,
    });

    const { wallet: destinationWallet3 } = await SparkWalletTesting.initialize({
      options: LOCAL_WALLET_CONFIG_ECDSA,
    });

    await fundAndAnnounce(issuerWallet, 100000n, 0, "ECDSATransfer", "ETT");

    await issuerWallet.mintTokens(tokenAmount);
    await issuerWallet.batchTransferTokens([
      {
        tokenAmount: tokenAmount / 3n,
        tokenPublicKey: await issuerWallet.getIdentityPublicKey(),
        receiverSparkAddress: await destinationWallet.getSparkAddress(),
      },
      {
        tokenAmount: tokenAmount / 3n,
        tokenPublicKey: await issuerWallet.getIdentityPublicKey(),
        receiverSparkAddress: await destinationWallet2.getSparkAddress(),
      },
      {
        tokenAmount: tokenAmount / 3n,
        tokenPublicKey: await issuerWallet.getIdentityPublicKey(),
        receiverSparkAddress: await destinationWallet3.getSparkAddress(),
      },
    ]);
    const sourceBalance = (await issuerWallet.getIssuerTokenBalance()).balance;
    expect(sourceBalance).toEqual(0n);

    const tokenPublicKey = await issuerWallet.getIdentityPublicKey();
    const balanceObj = await destinationWallet.getBalance();
    const destinationBalance = filterTokenBalanceForTokenPublicKey(
      balanceObj?.tokenBalances,
      tokenPublicKey,
    );
    expect(destinationBalance.balance).toEqual(tokenAmount / 3n);
    const balanceObj2 = await destinationWallet2.getBalance();
    const destinationBalance2 = filterTokenBalanceForTokenPublicKey(
      balanceObj2?.tokenBalances,
      tokenPublicKey,
    );
    expect(destinationBalance2.balance).toEqual(tokenAmount / 3n);
    const balanceObj3 = await destinationWallet3.getBalance();
    const destinationBalance3 = filterTokenBalanceForTokenPublicKey(
      balanceObj3?.tokenBalances,
      tokenPublicKey,
    );
    expect(destinationBalance3.balance).toEqual(tokenAmount / 3n);
  });

  it("should announce, mint, and batchtransfer tokens with Schnorr", async () => {
    const tokenAmount: bigint = 999n;

    const { wallet: issuerWallet } = await IssuerSparkWalletTesting.initialize({
      options: LOCAL_WALLET_CONFIG_SCHNORR,
    });

    const { wallet: destinationWallet } = await SparkWalletTesting.initialize({
      options: LOCAL_WALLET_CONFIG_SCHNORR,
    });

    const { wallet: destinationWallet2 } = await SparkWalletTesting.initialize({
      options: LOCAL_WALLET_CONFIG_SCHNORR,
    });

    const { wallet: destinationWallet3 } = await SparkWalletTesting.initialize({
      options: LOCAL_WALLET_CONFIG_SCHNORR,
    });

    await fundAndAnnounce(issuerWallet, 100000n, 0, "SchnorrTransfer", "STT");

    await issuerWallet.mintTokens(tokenAmount);
    await issuerWallet.batchTransferTokens([
      {
        tokenAmount: tokenAmount / 3n,
        tokenPublicKey: await issuerWallet.getIdentityPublicKey(),
        receiverSparkAddress: await destinationWallet.getSparkAddress(),
      },
      {
        tokenAmount: tokenAmount / 3n,
        tokenPublicKey: await issuerWallet.getIdentityPublicKey(),
        receiverSparkAddress: await destinationWallet2.getSparkAddress(),
      },
      {
        tokenAmount: tokenAmount / 3n,
        tokenPublicKey: await issuerWallet.getIdentityPublicKey(),
        receiverSparkAddress: await destinationWallet3.getSparkAddress(),
      },
    ]);
    const sourceBalance = (await issuerWallet.getIssuerTokenBalance()).balance;
    expect(sourceBalance).toEqual(0n);

    const tokenPublicKey = await issuerWallet.getIdentityPublicKey();
    const balanceObj = await destinationWallet.getBalance();
    const destinationBalance = filterTokenBalanceForTokenPublicKey(
      balanceObj?.tokenBalances,
      tokenPublicKey,
    );
    expect(destinationBalance.balance).toEqual(tokenAmount / 3n);
    const balanceObj2 = await destinationWallet2.getBalance();
    const destinationBalance2 = filterTokenBalanceForTokenPublicKey(
      balanceObj2?.tokenBalances,
      tokenPublicKey,
    );
    expect(destinationBalance2.balance).toEqual(tokenAmount / 3n);
    const balanceObj3 = await destinationWallet3.getBalance();
    const destinationBalance3 = filterTokenBalanceForTokenPublicKey(
      balanceObj3?.tokenBalances,
      tokenPublicKey,
    );
    expect(destinationBalance3.balance).toEqual(tokenAmount / 3n);
  });

  it("should track token operations in monitoring", async () => {
    const tokenAmount: bigint = 1000n;

    const { wallet: issuerWallet } = await IssuerSparkWalletTesting.initialize({
      options: LOCAL_WALLET_CONFIG_ECDSA,
    });

    const { wallet: destinationWallet } = await SparkWalletTesting.initialize({
      options: LOCAL_WALLET_CONFIG_ECDSA,
    });

    await fundAndAnnounce(issuerWallet, 100000n, 0, "ECDSATransfer", "ETT");

    await issuerWallet.mintTokens(tokenAmount);
    await issuerWallet.transferTokens({
      tokenAmount,
      tokenPublicKey: await issuerWallet.getIdentityPublicKey(),
      receiverSparkAddress: await destinationWallet.getSparkAddress(),
    });
    const sourceBalance = (await issuerWallet.getIssuerTokenBalance()).balance;
    expect(sourceBalance).toEqual(0n);

    const tokenPublicKey = await issuerWallet.getIdentityPublicKey();
    const balanceObj = await destinationWallet.getBalance();
    const destinationBalance = filterTokenBalanceForTokenPublicKey(
      balanceObj?.tokenBalances,
      tokenPublicKey,
    );
    expect(destinationBalance.balance).toEqual(tokenAmount);
  });

  it("should track token operations in monitoring", async () => {
    const tokenAmount: bigint = 1000n;

    const { wallet: issuerWallet } = await IssuerSparkWalletTesting.initialize({
      options: LOCAL_WALLET_CONFIG_ECDSA,
    });

    const { wallet: destinationWallet } = await SparkWalletTesting.initialize({
      options: LOCAL_WALLET_CONFIG_ECDSA,
    });

    await fundAndAnnounce(issuerWallet, 100000n, 0, "Monitoring", "MOT");

    await issuerWallet.mintTokens(tokenAmount);
    await issuerWallet.transferTokens({
      tokenAmount,
      tokenPublicKey: await issuerWallet.getIdentityPublicKey(),
      receiverSparkAddress: await destinationWallet.getSparkAddress(),
    });
    const sourceBalance = (await issuerWallet.getIssuerTokenBalance()).balance;
    expect(sourceBalance).toEqual(0n);

    const tokenPublicKey = await issuerWallet.getIdentityPublicKey();
    const balanceObj = await destinationWallet.getBalance();
    const destinationBalance = filterTokenBalanceForTokenPublicKey(
      balanceObj?.tokenBalances,
      tokenPublicKey,
    );
    expect(destinationBalance.balance).toEqual(tokenAmount);

    const issuerOperations = await issuerWallet.getIssuerTokenActivity();
    expect(issuerOperations.transactions.length).toBe(2);
    const issuerOperationTx = issuerOperations.transactions[0].transaction;
    expect(issuerOperationTx?.$case).toBe("spark");
    let mint_operation = 0;
    let transfer_operation = 0;
    issuerOperations.transactions.forEach((transaction) => {
      if (transaction.transaction?.$case === "spark") {
        if (transaction.transaction.spark.operationType === "ISSUER_MINT") {
          mint_operation++;
        } else if (
          transaction.transaction.spark.operationType === "ISSUER_TRANSFER"
        ) {
          transfer_operation++;
        }
      }
    });
    expect(mint_operation).toBe(1);
    expect(transfer_operation).toBe(1);
  });

  it("should announce, mint, and transfer tokens with Schnorr", async () => {
    const tokenAmount: bigint = 1000n;

    const { wallet: issuerWallet } = await IssuerSparkWalletTesting.initialize({
      options: LOCAL_WALLET_CONFIG_SCHNORR,
    });

    const { wallet: destinationWallet } = await SparkWalletTesting.initialize({
      options: LOCAL_WALLET_CONFIG_SCHNORR,
    });

    await fundAndAnnounce(issuerWallet, 100000n, 0, "SchnorrTransfer", "STT");

    await issuerWallet.mintTokens(tokenAmount);
    await issuerWallet.transferTokens({
      tokenPublicKey: await issuerWallet.getIdentityPublicKey(),
      tokenAmount,
      receiverSparkAddress: await destinationWallet.getSparkAddress(),
    });
    const sourceBalance = (await issuerWallet.getIssuerTokenBalance()).balance;
    expect(sourceBalance).toEqual(0n);
    const tokenPublicKey = await issuerWallet.getIdentityPublicKey();
    const balanceObj = await destinationWallet.getBalance();
    const destinationBalance = filterTokenBalanceForTokenPublicKey(
      balanceObj?.tokenBalances,
      tokenPublicKey,
    );
    expect(destinationBalance.balance).toEqual(tokenAmount);
  });

  it("it should mint token with 1 max supply without issue", async () => {
    const tokenAmount: bigint = 1n;
    const { wallet: issuerWallet } = await IssuerSparkWalletTesting.initialize({
      options: LOCAL_WALLET_CONFIG_SCHNORR,
    });

    const { wallet: destinationWallet } = await SparkWalletTesting.initialize({
      options: LOCAL_WALLET_CONFIG_SCHNORR,
    });

    await fundAndAnnounce(issuerWallet, 1n, 0, "MaxSupply", "MST");
    await issuerWallet.mintTokens(tokenAmount);

    const tokenBalance = await issuerWallet.getIssuerTokenBalance();
    expect(tokenBalance.balance).toEqual(tokenAmount);
  });

  it("it should be able to announce a token with name of size equal to MAX_SYMBOL_SIZE", async () => {
    const { wallet: issuerWallet } = await IssuerSparkWalletTesting.initialize({
      options: LOCAL_WALLET_CONFIG_SCHNORR,
    });

    await fundAndAnnounce(issuerWallet, 1n, 0, "MaxSupply", "TESTAA");
  });

  it("it should be able to announce a token with symbol of size equal to MAX_NAME_SIZE", async () => {
    const { wallet: issuerWallet } = await IssuerSparkWalletTesting.initialize({
      options: LOCAL_WALLET_CONFIG_SCHNORR,
    });

    await fundAndAnnounce(issuerWallet, 1n, 0, "ABCDEFGHIJKLMNOPQ", "MQS");
  });

  it("it should NOT be able to announce a token with ( symbol size + name size ) > MAX_NAME_AND_SYMBOL_SIZE", async () => {
    const { wallet: issuerWallet } = await IssuerSparkWalletTesting.initialize({
      options: LOCAL_WALLET_CONFIG_SCHNORR,
    });

    await expect(
      fundAndAnnounce(issuerWallet, 1n, 0, "ABCDEFGHIJKLMNOPQ", "TESTAB"),
    ).rejects.toThrow();
  });

  it("it should NOT be able to announce a token with ( symbol size + name size ) > MAX_NAME_AND_SYMBOL_SIZE, and size is calculated in bytes", async () => {
    const { wallet: issuerWallet } = await IssuerSparkWalletTesting.initialize({
      options: LOCAL_WALLET_CONFIG_SCHNORR,
    });

    await expect(
      fundAndAnnounce(issuerWallet, 1n, 0, "ABCDEFGHIJKLMNOPQ", "🥸🥸"),
    ).rejects.toThrow();
  });

  // freeze is hardcoded to mainnet
  brokenTestFn(
    "should announce, mint, freeze and unfreeze tokens with ECDSA",
    async () => {
      const tokenAmount: bigint = 1000n;
      const { wallet: issuerWallet } =
        await IssuerSparkWalletTesting.initialize({
          options: LOCAL_WALLET_CONFIG_ECDSA,
        });

      await fundAndAnnounce(issuerWallet, 100000n, 0, "ECDSAFreeze", "EFT");
      await issuerWallet.mintTokens(tokenAmount);

      // Check issuer balance after minting
      const issuerBalanceAfterMint = (
        await issuerWallet.getIssuerTokenBalance()
      ).balance;
      expect(issuerBalanceAfterMint).toEqual(tokenAmount);

      const { wallet: userWallet } = await SparkWalletTesting.initialize({
        options: LOCAL_WALLET_CONFIG_ECDSA,
      });
      const userWalletPublicKey = await userWallet.getSparkAddress();

      await issuerWallet.transferTokens({
        tokenAmount,
        tokenPublicKey: await issuerWallet.getIdentityPublicKey(),
        receiverSparkAddress: userWalletPublicKey,
      });
      const issuerBalanceAfterTransfer = (
        await issuerWallet.getIssuerTokenBalance()
      ).balance;
      expect(issuerBalanceAfterTransfer).toEqual(0n);

      const tokenPublicKey = await issuerWallet.getIdentityPublicKey();
      const userBalanceObj = await userWallet.getBalance();
      const userBalanceAfterTransfer = filterTokenBalanceForTokenPublicKey(
        userBalanceObj?.tokenBalances,
        tokenPublicKey,
      );
      expect(userBalanceAfterTransfer.balance).toEqual(tokenAmount);
      // Freeze tokens
      const freezeResponse =
        await issuerWallet.freezeTokens(userWalletPublicKey);
      expect(freezeResponse.impactedOutputIds.length).toBeGreaterThan(0);
      expect(freezeResponse.impactedTokenAmount).toEqual(tokenAmount);

      // Unfreeze tokens
      const unfreezeResponse =
        await issuerWallet.unfreezeTokens(userWalletPublicKey);
      expect(unfreezeResponse.impactedOutputIds.length).toBeGreaterThan(0);
      expect(unfreezeResponse.impactedTokenAmount).toEqual(tokenAmount);
    },
  );

  // freeze is hardcoded to mainnet
  brokenTestFn(
    "should announce, mint, freeze and unfreeze tokens with Schnorr",
    async () => {
      const tokenAmount: bigint = 1000n;
      const { wallet: issuerWallet } =
        await IssuerSparkWalletTesting.initialize({
          options: LOCAL_WALLET_CONFIG_SCHNORR,
        });

      await fundAndAnnounce(issuerWallet, 100000n, 0, "SchnorrFreeze", "SFT");

      await issuerWallet.mintTokens(tokenAmount);

      // Check issuer balance after minting
      const issuerBalanceAfterMint = (
        await issuerWallet.getIssuerTokenBalance()
      ).balance;
      expect(issuerBalanceAfterMint).toEqual(tokenAmount);

      const { wallet: userWallet } = await SparkWalletTesting.initialize({
        options: LOCAL_WALLET_CONFIG_SCHNORR,
      });
      const userWalletPublicKey = await userWallet.getSparkAddress();

      await issuerWallet.transferTokens({
        tokenAmount,
        tokenPublicKey: await issuerWallet.getIdentityPublicKey(),
        receiverSparkAddress: userWalletPublicKey,
      });

      const issuerBalanceAfterTransfer = (
        await issuerWallet.getIssuerTokenBalance()
      ).balance;
      expect(issuerBalanceAfterTransfer).toEqual(0n);

      const tokenPublicKey = await issuerWallet.getIdentityPublicKey();
      const userBalanceObj = await userWallet.getBalance();
      const userBalanceAfterTransfer = filterTokenBalanceForTokenPublicKey(
        userBalanceObj?.tokenBalances,
        tokenPublicKey,
      );
      expect(userBalanceAfterTransfer.balance).toEqual(tokenAmount);

      const freezeResult = await issuerWallet.freezeTokens(userWalletPublicKey);
      expect(freezeResult.impactedOutputIds.length).toBe(1);
      expect(freezeResult.impactedTokenAmount).toBe(1000n);

      const unfreezeResult =
        await issuerWallet.unfreezeTokens(userWalletPublicKey);
      expect(unfreezeResult.impactedOutputIds.length).toBe(1);
      expect(unfreezeResult.impactedTokenAmount).toBe(1000n);
    },
  );

  it("should announce, mint, and burn tokens with ECDSA", async () => {
    const tokenAmount: bigint = 200n;
    const { wallet: issuerWallet } = await IssuerSparkWalletTesting.initialize({
      options: LOCAL_WALLET_CONFIG_ECDSA,
    });

    await fundAndAnnounce(issuerWallet, 100000n, 0, "ECDSABurn", "EBT");
    await issuerWallet.mintTokens(tokenAmount);

    const issuerTokenBalance = (await issuerWallet.getIssuerTokenBalance())
      .balance;
    expect(issuerTokenBalance).toEqual(tokenAmount);

    await issuerWallet.burnTokens(tokenAmount);

    const issuerTokenBalanceAfterBurn = (
      await issuerWallet.getIssuerTokenBalance()
    ).balance;
    expect(issuerTokenBalanceAfterBurn).toEqual(0n);
  });

  it("should announce, mint, and burn tokens with ECDSA and totalSupply has to be equal amount of token minted minus burned tokens", async () => {
    const tokenAmount_init: bigint = 2000n;
    const tokenAmount_burn: bigint = 1000n;

    const { wallet: issuerWallet } = await IssuerSparkWalletTesting.initialize({
      options: LOCAL_WALLET_CONFIG_ECDSA,
    });

    await fundAndAnnounce(issuerWallet, 100000n, 0, "ECDSATotalSupply", "ETS");
    await issuerWallet.mintTokens(tokenAmount_init);

    await issuerWallet.burnTokens(tokenAmount_burn);

    const smth_with_total_supply = await issuerWallet.getIssuerTokenInfo();

    expect(smth_with_total_supply?.totalSupply).toEqual(
      tokenAmount_init - tokenAmount_burn,
    );
  });

  it("should announce, mint, and burn tokens with Schnorr", async () => {
    const tokenAmount: bigint = 200n;
    const { wallet: issuerWallet } = await IssuerSparkWalletTesting.initialize({
      options: LOCAL_WALLET_CONFIG_SCHNORR,
    });

    await fundAndAnnounce(issuerWallet, 100000n, 0, "SchnorrBurn", "SBT");
    await issuerWallet.mintTokens(tokenAmount);

    const issuerTokenBalance = (await issuerWallet.getIssuerTokenBalance())
      .balance;
    expect(issuerTokenBalance).toEqual(tokenAmount);

    await issuerWallet.burnTokens(tokenAmount);

    const issuerTokenBalanceAfterBurn = (
      await issuerWallet.getIssuerTokenBalance()
    ).balance;
    expect(issuerTokenBalanceAfterBurn).toEqual(0n);
  });

  it("should complete full token lifecycle with ECDSA: announce, mint, transfer, return, burn", async () => {
    const tokenAmount: bigint = 1000n;

    const { wallet: issuerWallet } = await IssuerSparkWalletTesting.initialize({
      options: LOCAL_WALLET_CONFIG_ECDSA,
    });

    const { wallet: userWallet } = await SparkWalletTesting.initialize({
      options: LOCAL_WALLET_CONFIG_ECDSA,
    });

    await fundAndAnnounce(issuerWallet, 100000n, 0, "ECDSAFullCycle", "EFCT");
    await issuerWallet.mintTokens(tokenAmount);

    const issuerBalanceAfterMint = (await issuerWallet.getIssuerTokenBalance())
      .balance;
    expect(issuerBalanceAfterMint).toEqual(tokenAmount);

    const userWalletPublicKey = await userWallet.getSparkAddress();

    await issuerWallet.transferTokens({
      tokenAmount,
      tokenPublicKey: await issuerWallet.getIdentityPublicKey(),
      receiverSparkAddress: userWalletPublicKey,
    });

    const issuerBalanceAfterTransfer = (
      await issuerWallet.getIssuerTokenBalance()
    ).balance;
    expect(issuerBalanceAfterTransfer).toEqual(0n);
    const tokenPublicKeyHex = await issuerWallet.getIdentityPublicKey();
    const userWalletPublicKeyHex = await userWallet.getSparkAddress();
    const userBalanceObj = await userWallet.getBalance();
    const userBalanceAfterTransfer = filterTokenBalanceForTokenPublicKey(
      userBalanceObj?.tokenBalances,
      tokenPublicKeyHex,
    );
    expect(userBalanceAfterTransfer.balance).toEqual(tokenAmount);
    await userWallet.transferTokens({
      tokenPublicKey: tokenPublicKeyHex,
      tokenAmount,
      receiverSparkAddress: await issuerWallet.getSparkAddress(),
    });

    const userBalanceObjAfterTransferBack = await userWallet.getBalance();
    const userBalanceAfterTransferBack = filterTokenBalanceForTokenPublicKey(
      userBalanceObjAfterTransferBack?.tokenBalances,
      tokenPublicKeyHex,
    );

    expect(userBalanceAfterTransferBack.balance).toEqual(0n);

    const issuerTokenBalance = (await issuerWallet.getIssuerTokenBalance())
      .balance;
    expect(issuerTokenBalance).toEqual(tokenAmount);
    await issuerWallet.burnTokens(tokenAmount);
    const issuerTokenBalanceAfterBurn = (
      await issuerWallet.getIssuerTokenBalance()
    ).balance;
    expect(issuerTokenBalanceAfterBurn).toEqual(0n);
  });

  it("should complete full token lifecycle with Schnorr: announce, mint, transfer, return, burn", async () => {
    const tokenAmount: bigint = 1000n;

    const { wallet: issuerWallet } = await IssuerSparkWalletTesting.initialize({
      options: LOCAL_WALLET_CONFIG_SCHNORR,
    });

    const { wallet: userWallet } = await SparkWalletTesting.initialize({
      options: LOCAL_WALLET_CONFIG_SCHNORR,
    });

    await fundAndAnnounce(issuerWallet, 100000n, 0, "SchnorrFullCycle", "SFCT");
    await issuerWallet.mintTokens(tokenAmount);

    const issuerBalanceAfterMint = (await issuerWallet.getIssuerTokenBalance())
      .balance;
    expect(issuerBalanceAfterMint).toEqual(tokenAmount);

    const userWalletPublicKey = await userWallet.getSparkAddress();

    await issuerWallet.transferTokens({
      tokenAmount,
      tokenPublicKey: await issuerWallet.getIdentityPublicKey(),
      receiverSparkAddress: userWalletPublicKey,
    });

    const issuerBalanceAfterTransfer = (
      await issuerWallet.getIssuerTokenBalance()
    ).balance;
    expect(issuerBalanceAfterTransfer).toEqual(0n);

    const tokenPublicKeyHex = await issuerWallet.getIdentityPublicKey();
    const userBalanceObj = await userWallet.getBalance();
    const userBalanceAfterTransfer = filterTokenBalanceForTokenPublicKey(
      userBalanceObj?.tokenBalances,
      tokenPublicKeyHex,
    );
    expect(userBalanceAfterTransfer.balance).toEqual(tokenAmount);

    await userWallet.transferTokens({
      tokenPublicKey: tokenPublicKeyHex,
      tokenAmount,
      receiverSparkAddress: await issuerWallet.getSparkAddress(),
    });

    const userBalanceObjAfterTransferBack = await userWallet.getBalance();
    const userBalanceAfterTransferBack = filterTokenBalanceForTokenPublicKey(
      userBalanceObjAfterTransferBack?.tokenBalances,
      tokenPublicKeyHex,
    );
    expect(userBalanceAfterTransferBack.balance).toEqual(0n);

    const issuerTokenBalance = (await issuerWallet.getIssuerTokenBalance())
      .balance;
    expect(issuerTokenBalance).toEqual(tokenAmount);

    await issuerWallet.burnTokens(tokenAmount);

    const issuerTokenBalanceAfterBurn = (
      await issuerWallet.getIssuerTokenBalance()
    ).balance;
    expect(issuerTokenBalanceAfterBurn).toEqual(0n);
  });
  it("should correctly assign operation types for complete token lifecycle operations", async () => {
    const { wallet: issuerWallet } = await IssuerSparkWalletTesting.initialize({
      options: LOCAL_WALLET_CONFIG_SCHNORR,
    });

    const { wallet: userWallet } = await SparkWalletTesting.initialize({
      options: LOCAL_WALLET_CONFIG_SCHNORR,
    });

    const tokenAmount = 1000n;

    await fundAndAnnounce(issuerWallet, 100000n, 0, "OperationTypeTest", "OTT");
    await issuerWallet.mintTokens(tokenAmount);

    await issuerWallet.transferTokens({
      tokenAmount: 500n,
      tokenPublicKey: await issuerWallet.getIdentityPublicKey(),
      receiverSparkAddress: await userWallet.getSparkAddress(),
    });

    const tokenPublicKeyHex = await issuerWallet.getIdentityPublicKey();

    await userWallet.transferTokens({
      tokenPublicKey: tokenPublicKeyHex,
      tokenAmount: 250n,
      receiverSparkAddress: await issuerWallet.getSparkAddress(),
    });

    // as in userWallet we didn't have burnTokens method, we need to transfer tokens to burn address manually
    const BURN_ADDRESS = "02".repeat(33);
    const burnAddress = encodeSparkAddress({
      identityPublicKey: BURN_ADDRESS,
      network: "LOCAL",
    });

    await userWallet.transferTokens({
      tokenPublicKey: tokenPublicKeyHex,
      tokenAmount: 250n,
      receiverSparkAddress: burnAddress,
    });

    await issuerWallet.burnTokens(250n);

    const activity = await issuerWallet.getIssuerTokenActivity();

    const mintTransaction = activity.transactions.find(
      (tx) =>
        tx.transaction?.$case === "spark" &&
        tx.transaction.spark.operationType === "ISSUER_MINT",
    );

    const transferTransaction = activity.transactions.find(
      (tx) =>
        tx.transaction?.$case === "spark" &&
        tx.transaction.spark.operationType === "ISSUER_TRANSFER",
    );

    const burnTransaction = activity.transactions.find(
      (tx) =>
        tx.transaction?.$case === "spark" &&
        tx.transaction.spark.operationType === "ISSUER_BURN",
    );

    const transferBackTransaction = activity.transactions.find(
      (tx) =>
        tx.transaction?.$case === "spark" &&
        tx.transaction.spark.operationType === "USER_TRANSFER",
    );

    const userBurnTransaction = activity.transactions.find(
      (tx) =>
        tx.transaction?.$case === "spark" &&
        tx.transaction.spark.operationType === "USER_BURN",
    );

    expect(mintTransaction).toBeDefined();
    expect(transferTransaction).toBeDefined();
    expect(burnTransaction).toBeDefined();
    expect(transferBackTransaction).toBeDefined();
    expect(userBurnTransaction).toBeDefined();
  });
});

async function fundAndAnnounce(
  wallet: IssuerSparkWallet,
  maxSupply: bigint = 100000n,
  decimals: number = 0,
  tokenName: string = "TestToken1",
  tokenSymbol: string = "TT1",
  isFreezable: boolean = false,
) {
  // Faucet funds to the Issuer wallet because announcing a token
  // requires ownership of an L1 UTXO.
  const faucet = BitcoinFaucet.getInstance();
  const l1WalletPubKey = await wallet.getTokenL1Address();
  await faucet.sendToAddress(l1WalletPubKey, 100_000n);
  await faucet.mineBlocks(6);

  await new Promise((resolve) => setTimeout(resolve, 3000));

  try {
    const response = await wallet.announceTokenL1(
      tokenName,
      tokenSymbol,
      decimals,
      maxSupply,
      isFreezable,
    );
    console.log("Announce token response:", response);
  } catch (error: any) {
    console.error("Error when announcing token on L1:", error);
    throw error;
  }
  await faucet.mineBlocks(2);

  // Wait for LRC20 processing.
  const SECONDS = 1000;
  await new Promise((resolve) => setTimeout(resolve, 3 * SECONDS));
}
