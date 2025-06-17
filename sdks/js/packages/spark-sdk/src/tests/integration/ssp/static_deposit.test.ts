import { describe, expect, it } from "@jest/globals";
import { SparkWalletTesting } from "../../utils/spark-testing-wallet.js";
import { BitcoinFaucet } from "../../utils/test-faucet.js";

const DEPOSIT_AMOUNT = 10000n;
const SECOND_DEPOSIT_AMOUNT = 20000n;

// TODO: reenable this test when we have a way to test SSP tests consistently
describe.skip("SSP static deposit address integration", () => {
  it("should claim deposits to a static deposit address", async () => {
    const faucet = BitcoinFaucet.getInstance();

    const { wallet: userWallet } = await SparkWalletTesting.initialize(
      {
        options: {
          network: "LOCAL",
        },
      },
      false,
    );

    const depositAddress = await userWallet.getStaticDepositAddress();
    expect(depositAddress).toBeDefined();

    const signedTx = await faucet.sendToAddress(depositAddress, DEPOSIT_AMOUNT);

    // Wait for the transaction to be mined
    await faucet.mineBlocks(6);

    expect(signedTx).toBeDefined();

    const transactionId = signedTx.id;

    let vout;

    for (let i = 0; i < signedTx.outputsLength; i++) {
      const output = signedTx.getOutput(i);
      if (output.amount === DEPOSIT_AMOUNT) {
        vout = i;
        break;
      }
    }

    const quote = await userWallet.getClaimStaticDepositQuote(
      transactionId,
      vout!,
    );

    const quoteAmount = quote!.creditAmountSats;
    const sspSignature = quote!.signature;

    await userWallet.claimStaticDeposit({
      transactionId,
      creditAmountSats: quoteAmount,
      sspSignature,
      outputIndex: vout!,
    });

    await new Promise((resolve) => setTimeout(resolve, 1000));

    const { balance } = await userWallet.getBalance();
    expect(balance).toBe(BigInt(quoteAmount));

    // Test depositing money to the same address and second time and claiming.
    const signedTx2 = await faucet.sendToAddress(
      depositAddress,
      SECOND_DEPOSIT_AMOUNT,
    );
    const transactionId2 = signedTx2.id;
    // Wait for the transaction to be mined
    await faucet.mineBlocks(6);

    // Test claiming and getting the quote without passing in the output index.
    const quote2 = await userWallet.getClaimStaticDepositQuote(transactionId2);

    const quoteAmount2 = quote2!.creditAmountSats;
    const sspSignature2 = quote2!.signature;

    await userWallet.claimStaticDeposit({
      transactionId: transactionId2,
      creditAmountSats: quoteAmount2,
      sspSignature: sspSignature2,
    });

    await new Promise((resolve) => setTimeout(resolve, 1000));

    const { balance: balance2 } = await userWallet.getBalance();
    expect(balance2).toBe(BigInt(quoteAmount + quoteAmount2));

    // Get transfers should include static deposit transfers.
    const transfers = await userWallet.getTransfers();
    expect(transfers.transfers.length).toBe(2);
  }, 60000);
});
