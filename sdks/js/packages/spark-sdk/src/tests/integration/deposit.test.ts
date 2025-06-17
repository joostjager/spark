import { describe, expect, it } from "@jest/globals";
import { Address, OutScript, Transaction } from "@scure/btc-signer";
import { RPCError } from "../../errors/types.js";
import { getTxId } from "../../utils/bitcoin.js";
import { getNetwork, Network } from "../../utils/network.js";
import { SparkWalletTesting } from "../utils/spark-testing-wallet.js";
import { BitcoinFaucet } from "../utils/test-faucet.js";

describe("deposit", () => {
  it("should generate a deposit address", async () => {
    const { wallet: sdk } = await SparkWalletTesting.initialize({
      options: {
        network: "LOCAL",
      },
    });

    const depositAddress = await sdk.getSingleUseDepositAddress();

    expect(depositAddress).toBeDefined();
  }, 30000);

  it("should generate a staticdeposit address", async () => {
    const { wallet: sdk } = await SparkWalletTesting.initialize({
      options: {
        network: "LOCAL",
      },
    });

    const depositAddress = await sdk.getStaticDepositAddress();

    expect(depositAddress).toBeDefined();

    // Verify that static deposit addresses don't appear in unused deposit addresses
    const unusedDepositAddresses = await sdk.getUnusedDepositAddresses();
    expect(unusedDepositAddresses).toHaveLength(0);

    // Check that the same static deposit address is returned a second time.
    const secondDepositAddress = await sdk.getStaticDepositAddress();
    expect(secondDepositAddress).toBeDefined();
    expect(secondDepositAddress).toEqual(depositAddress);
  }, 30000);

  it("should create a tree root", async () => {
    const faucet = BitcoinFaucet.getInstance();

    const { wallet: sdk } = await SparkWalletTesting.initialize({
      options: {
        network: "LOCAL",
      },
    });

    const depositResp = await sdk.getSingleUseDepositAddress();
    if (!depositResp) {
      throw new RPCError("Deposit address not found", {
        method: "getDepositAddress",
      });
    }

    const signedTx = await faucet.sendToAddress(depositResp, 100_000n);

    await sdk.claimDeposit(signedTx.id);
  }, 30000);

  it("should restart wallet and recover signing private key", async () => {
    const faucet = BitcoinFaucet.getInstance();

    const { wallet: sdk, mnemonic } = await SparkWalletTesting.initialize({
      options: {
        network: "LOCAL",
      },
    });

    // Generate deposit address
    const depositResp = await sdk.getSingleUseDepositAddress();
    if (!depositResp) {
      throw new RPCError("Deposit address not found", {
        method: "getDepositAddress",
      });
    }

    const signedTx = await faucet.sendToAddress(depositResp, 100_000n);
    await faucet.mineBlocks(6);

    const { wallet: newSdk } = await SparkWalletTesting.initialize({
      mnemonicOrSeed: mnemonic,
      options: {
        network: "LOCAL",
      },
    });

    await newSdk.claimDeposit(signedTx.id);
  }, 30000);

  it("should handle non-trusty deposit", async () => {
    const faucet = BitcoinFaucet.getInstance();

    const { wallet: sdk } = await SparkWalletTesting.initialize({
      options: {
        network: "LOCAL",
      },
    });

    const coin = await faucet.fund();

    const depositTx = new Transaction();
    const sendAmount = 50_000n;

    depositTx.addInput(coin!.outpoint);

    const depositAddress = await sdk.getSingleUseDepositAddress();
    if (!depositAddress) {
      throw new Error("Failed to get deposit address");
    }

    const destinationAddress = Address(getNetwork(Network.LOCAL)).decode(
      depositAddress,
    );
    const destinationScript = OutScript.encode(destinationAddress);
    depositTx.addOutput({
      script: destinationScript,
      amount: sendAmount,
    });

    const unsignedTxHex = depositTx.hex;

    const depositResult = await sdk.advancedDeposit(unsignedTxHex);
    expect(depositResult).toBeDefined();

    const signedTx = await faucet.signFaucetCoin(
      depositTx,
      coin!.txout,
      coin!.key,
    );

    const broadcastResult = await faucet.broadcastTx(signedTx.hex);
    expect(broadcastResult).toBeDefined();

    await faucet.generateToAddress(1, depositAddress);

    // Sleep to allow chain watcher to catch up
    await new Promise((resolve) => setTimeout(resolve, 3000));

    const balance = await sdk.getBalance();
    expect(balance.balance).toEqual(sendAmount);

    await expect(sdk.advancedDeposit(unsignedTxHex)).rejects.toThrow(
      `No unused deposit address found for tx: ${getTxId(depositTx)}`,
    );
  }, 30000);

  it("should handle single tx with multiple outputs to unused deposit addresses", async () => {
    const faucet = BitcoinFaucet.getInstance();

    const { wallet: sdk } = await SparkWalletTesting.initialize({
      options: {
        network: "LOCAL",
      },
    });

    const coin = await faucet.fund();

    const depositTx = new Transaction();
    const sendAmount = 50_000n;

    depositTx.addInput(coin!.outpoint);

    const depositAddress = await sdk.getSingleUseDepositAddress();
    if (!depositAddress) {
      throw new Error("Failed to get deposit address");
    }

    const depositAddress2 = await sdk.getSingleUseDepositAddress();
    if (!depositAddress2) {
      throw new Error("Failed to get deposit address");
    }

    const destinationAddress = Address(getNetwork(Network.LOCAL)).decode(
      depositAddress,
    );
    const destinationScript = OutScript.encode(destinationAddress);
    depositTx.addOutput({
      script: destinationScript,
      amount: sendAmount,
    });

    const destinationAddress2 = Address(getNetwork(Network.LOCAL)).decode(
      depositAddress2,
    );
    const destinationScript2 = OutScript.encode(destinationAddress2);
    depositTx.addOutput({
      script: destinationScript2,
      amount: sendAmount,
    });

    const unsignedTxHex = depositTx.hex;

    const depositResult = await sdk.advancedDeposit(unsignedTxHex);
    expect(depositResult).toBeDefined();

    const signedTx = await faucet.signFaucetCoin(
      depositTx,
      coin!.txout,
      coin!.key,
    );

    const broadcastResult = await faucet.broadcastTx(signedTx.hex);
    expect(broadcastResult).toBeDefined();

    await faucet.generateToAddress(1, depositAddress);

    // Sleep to allow chain watcher to catch up
    await new Promise((resolve) => setTimeout(resolve, 3000));

    const balance = await sdk.getBalance();
    expect(balance.balance).toEqual(sendAmount * 2n);
  }, 30000);
});

describe("refund static deposit", () => {
  it("should refund a static deposit", async () => {
    const faucet = BitcoinFaucet.getInstance();

    await faucet.fund();

    const { wallet: sdk } = await SparkWalletTesting.initialize({
      options: {
        network: "LOCAL",
      },
    });

    const depositAddress = await sdk.getStaticDepositAddress();
    if (!depositAddress) {
      throw new Error("Failed to get deposit address");
    }

    const signedTx = await faucet.sendToAddress(depositAddress, 10_000n);

    await faucet.mineBlocks(10);

    const withdrawalAddress = await faucet.getNewAddress();

    await faucet.generateToAddress(1, withdrawalAddress);

    // Sleep to allow chain watcher to catch up
    await new Promise((resolve) => setTimeout(resolve, 3000));

    await faucet.mineBlocks(10);

    const refundTx = await sdk.refundStaticDeposit({
      depositTransactionId: signedTx.id,
      destinationAddress: withdrawalAddress,
      fee: 1000,
    });

    const broadcastResult = await faucet.broadcastTx(refundTx);
    expect(broadcastResult).toBeDefined();
  }, 30000);
});
