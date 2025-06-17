import {
  BitcoinOutput,
  MultisigReceiptOutput,
  OPReturnOutput,
  ReceiptOutput,
  SparkExitOutput,
  TxOutput,
  TokenPubkeyAnnouncement,
  TxFreezeAnnouncement,
  FreezeTxToggle,
  TransferOwnershipAnnouncement,
  PubkeyFreezeAnnouncement,
  BitcoinInput,
  MultisigReceiptInput,
  ReceiptInput,
  TxInput,
  Receipt,
} from "../types/index.ts";
import { DUST_AMOUNT, findNotFirstUsingFind, reverseBuffer, toXOnly } from "../utils/index.ts";
import { Psbt, Payment, payments, Transaction, script, opcodes, type Network } from "bitcoinjs-lib";
import * as varuint from "varuint-bitcoin";
import { TokenSigner } from "../signer/signer.ts";

export class TransactionBuilder {
  private signer: TokenSigner;
  private network: Network;

  constructor(signer: TokenSigner, network: Network) {
    this.signer = signer;
    this.network = network;
  }

  async buildTransferOwnershipOutput(transferAnnouncement: TransferOwnershipAnnouncement) {
    const opReturnPrefixBuff = Buffer.from([76, 82, 67, 50, 48, 0, 3]);
    console.log("buildTransferOwnershipOutput: ", transferAnnouncement);
    return {
      type: "OPReturnOutput",
      satoshis: 0,
      data: [opReturnPrefixBuff, transferAnnouncement.toBuffer()],
    };
  }

  async buildAnnouncementOutput(tokenPubkeyAnnouncement: TokenPubkeyAnnouncement) {
    const opReturnPrefixBuff = Buffer.from([76, 82, 67, 50, 48, 0, 0]);
    return {
      type: "OPReturnOutput",
      satoshis: 0,
      data: [Buffer.concat([opReturnPrefixBuff, tokenPubkeyAnnouncement.toBuffer()])],
    };
  }

  async buildIssuanceOutput(futureOutputs: Array<TxOutput>) {
    const receiptsOutputs = futureOutputs
      .filter((item) => item.type === "ReceiptOutput" || item.type === "MultisigReceiptOutput")
      .map((item) => item as ReceiptOutput);

    if (findNotFirstUsingFind(receiptsOutputs.map((receipt) => receipt.receipt.tokenPubkey.pubkey))) {
      throw new Error("Found other tokenPubkeys");
    }

    const opReturnPrefixBuff = Buffer.from([76, 82, 67, 50, 48, 0, 2]);
    const receiptsSum = receiptsOutputs.reduce(
      (acc, currentValue) => acc + (currentValue as ReceiptOutput).receipt.tokenAmount.amount,
      BigInt(0),
    );
    const receiptsSumLEBuff = reverseBuffer(
      Buffer.from(receiptsSum.toString(16).padStart(32, "0").slice(0, 32), "hex"),
    );
    const tokenPubkeyBuff = receiptsOutputs[0].receipt.tokenPubkey.pubkey;
    return {
      type: "OPReturnOutput",
      satoshis: 0,
      data: [Buffer.concat([opReturnPrefixBuff, tokenPubkeyBuff, receiptsSumLEBuff])],
    };
  }

  // TODO: build freeze
  async buildFreezeOutput(freeze: TxFreezeAnnouncement | PubkeyFreezeAnnouncement) {
    const opReturnPrefixBuff = Buffer.from([76, 82, 67, 50, 48, 0, 1]);

    if (freeze instanceof PubkeyFreezeAnnouncement) {
      const tokenPubkeyBuff = freeze.tokenPubkey.inner;
      const ownerPubkeyBuff = freeze.ownerPubkey;

      return {
        type: "OPReturnOutput",
        satoshis: 0,
        data: [Buffer.concat([opReturnPrefixBuff, ownerPubkeyBuff, tokenPubkeyBuff])],
      };
    } else {
      const { txid, vout } = freeze.outpoint;
      const txidBuff = Buffer.from(txid, "hex");
      const indexBuff = Buffer.from(vout.toString(16).padStart(8, "0"), "hex");
      const tokenPubkeyBuff = freeze.tokenPubkey.inner;

      return {
        type: "OPReturnOutput",
        satoshis: 0,
        data: [Buffer.concat([opReturnPrefixBuff, txidBuff, indexBuff, tokenPubkeyBuff])],
      };
    }
  }

  async buildAndSignTransaction(
    inputs: TxInput[],
    outputs: TxOutput[],
    changeOutput: TxOutput,
    feeRateVb: number,
    locktime = 0,
    sequence?: number,
  ): Promise<Transaction> {
    const psbt = new Psbt({ network: this.network });
    psbt.setVersion(2);
    psbt.setLocktime(locktime);

    let changeOutputConstructed = await this.updateChangeOutput(
      psbt.clone(),
      inputs,
      outputs,
      changeOutput,
      feeRateVb,
      sequence,
    );

    const constructedOutputs = [...outputs];
    if (changeOutputConstructed.satoshis > DUST_AMOUNT) {
      constructedOutputs.push(changeOutputConstructed);
    }

    await this.constructPsbtFromInsAndOuts(psbt, [...inputs], constructedOutputs, sequence);

    const finalTx = psbt.extractTransaction();

    return finalTx;
  }

  private async constructPsbtFromInsAndOuts(
    psbt: Psbt,
    inputs: TxInput[],
    outputs: TxOutput[],
    sequence?: number,
  ): Promise<Psbt> {
    outputs.forEach((output, index) => {
      const payment = this.outputToPayment(output);
      psbt.addOutput({
        script: payment.output!,
        value: output.satoshis,
      });
    });

    inputs.forEach((input, i) => {
      psbt.addInput({
        hash: input.txId,
        index: input.index,
        nonWitnessUtxo: Buffer.from(input.hex, "hex"),
      });

      if (sequence) {
        psbt.setInputSequence(i, sequence);
      }
    });

    inputs.forEach(async (input, i) => {
      switch (input.type) {
        case "BitcoinInput":
          await this.signer.signPsbt(psbt, i, null);
          psbt.finalizeInput(i);
          break;
        case "ReceiptInput":
          if (!(input as ReceiptInput).isP2WSH) {
            await this.signer.signPsbt(psbt, i, null, (input as ReceiptInput).proof);
            psbt.finalizeInput(i);
            break;
          }
      }
    });

    return psbt;
  }

  private witnessStackToScriptWitness(witness: Buffer[]): Buffer {
    let buffer = Buffer.alloc(0);

    buffer = Buffer.from(this.writeVarInt(witness.length, buffer));
    witness.forEach((witnessElement) => {
      buffer = Buffer.from(this.writeVarInt(witnessElement.length, buffer));
      buffer = Buffer.concat([buffer, Buffer.from(witnessElement)]);
    });

    return buffer;
  }

  private writeVarInt(i: number, buffer: Buffer): Buffer {
    const currentLen = buffer.length;
    const varintLen = varuint.encodingLength(i);

    buffer = Buffer.concat([buffer, Buffer.allocUnsafe(varintLen)]);
    varuint.encode(i, buffer, currentLen);
    return buffer;
  }

  private async updateChangeOutput(
    psbt: Psbt,
    inputs: TxInput[],
    outputs: TxOutput[],
    changeOutput: TxOutput,
    feeRateVb: number,
    sequence?: number,
  ) {
    const psbtToEstimate = this.constructPsbtFromInsAndOuts(psbt, inputs, [...outputs, changeOutput], sequence);
    const fee = Math.ceil(this.estimateFee(await psbtToEstimate, feeRateVb));

    const inputsSum = this.sumSatoshis(inputs);
    const outputsSum = this.sumSatoshis(outputs);

    const change = inputsSum - outputsSum - fee;

    if (change < 0) {
      throw new Error("Not enough satoshis to pay fees");
    }

    changeOutput.satoshis = change;
    return changeOutput;
  }

  private estimateFee(feeEstimationPsbt: Psbt, feeRateVb: number): number {
    // feeEstimationPsbt.txInputs.forEach(input => {
    //   console.log(reverseBuffer(input.hash).toString("hex"), input.index)
    // })

    // feeEstimationPsbt.txOutputs.forEach(output => {
    //   console.log(output);
    // })

    const feeEstimationTx = feeEstimationPsbt.extractTransaction(true);
    return (feeEstimationTx.virtualSize() + feeEstimationTx.ins.length) * feeRateVb;
  }

  public outputToPayment(output: TxOutput): Payment {
    let payment: Payment;

    switch (output.type) {
      case "BitcoinOutput":
        const { bech32Result, receiverPubKey } = output as BitcoinOutput;
        const hash = bech32Result?.data?.length ? bech32Result.data : undefined;
        const pubkey = hash ? undefined : receiverPubKey;
        if (hash) {
          payment = payments.p2wpkh({
            hash,
            network: this.network,
          });
        } else {
          payment = payments.p2wpkh({
            pubkey,
            network: this.network,
          });
        }
        break;
      case "ReceiptOutput":
        const receiptKey = Receipt.receiptPublicKey(
          (output as ReceiptOutput).receiverPubKey,
          (output as ReceiptOutput).receipt,
        );

        payment = payments.p2wpkh({
          pubkey: Buffer.from(receiptKey),
          network: this.network,
        });
        break;
      case "MultisigReceiptOutput":
        payment = (output as MultisigReceiptOutput).toScript(this.network);

        break;
      case "OPReturnOutput":
        payment = payments.embed({ data: (output as OPReturnOutput).data });
        break;
      case "SparkExitOutput":
        const { revocationPubkey, delayPubkey, locktime, receipt } = output as SparkExitOutput;
        const tweakedDelayKey = Receipt.receiptPublicKey(delayPubkey, receipt);

        const scriptPathScript = script.compile([
          script.number.encode(locktime),
          opcodes.OP_CHECKLOCKTIMEVERIFY,
          opcodes.OP_DROP,
          toXOnly(tweakedDelayKey),
          opcodes.OP_CHECKSIG,
        ]);

        const tapLeaf = { output: scriptPathScript, version: 0 };

        payment = payments.p2tr({
          internalPubkey: toXOnly(revocationPubkey),
          scriptTree: tapLeaf,
          network: this.network,
        });
        break;
      default:
        throw new Error("Output type is unknown");
    }

    return payment;
  }

  private sumSatoshis(data: (TxInput | TxOutput)[]): number {
    return data.reduce((accumulator, currentValue) => accumulator + (currentValue as any).satoshis, 0);
  }

  async buildAndSignMakerPsbt(inputs: TxInput[], output: TxOutput): Promise<Transaction> {
    const psbt = await this.constructMakerPsbtFromInsAndOuts(inputs, output);

    return psbt.extractTransaction();
  }

  async buildAndSignOneInputTx(input: TxInput): Promise<Transaction> {
    let psbt = new Psbt({ network: this.network });
    psbt.setVersion(2);
    psbt.setLocktime(0);

    psbt.addInput({
      hash: input.txId,
      index: input.index,
      nonWitnessUtxo: Buffer.from(input.hex, "hex"),
      sighashType: Transaction.SIGHASH_NONE + Transaction.SIGHASH_ANYONECANPAY,
    });

    switch (input.type) {
      case "BitcoinInput":
        psbt = await this.signer.signPsbt(psbt, 0, [Transaction.SIGHASH_NONE + Transaction.SIGHASH_ANYONECANPAY]);
        psbt.finalizeInput(0);
        break;
      case "ReceiptInput":
        psbt = await this.signer.signPsbt(
          psbt,
          0,
          [Transaction.SIGHASH_NONE + Transaction.SIGHASH_ANYONECANPAY],
          (input as ReceiptInput).proof,
        );
        psbt.finalizeInput(0);
    }

    return psbt.extractTransaction(true);
  }

  async constructTakerSingePsbtFromInsAndOuts(input: TxInput, output: TxOutput): Promise<Psbt> {
    let psbt = new Psbt({ network: this.network });
    psbt.setVersion(2);
    psbt.setLocktime(0);

    psbt.addOutput({
      script: this.outputToPayment(output).output!,
      value: output.satoshis,
    });

    psbt.addInput({
      hash: input.txId,
      index: input.index,
      nonWitnessUtxo: Buffer.from(input.hex, "hex"),
      sighashType: Transaction.SIGHASH_SINGLE + Transaction.SIGHASH_ANYONECANPAY,
    });

    switch (input.type) {
      case "BitcoinInput":
        psbt = await this.signer.signPsbt(psbt, 0, [Transaction.SIGHASH_SINGLE + Transaction.SIGHASH_ANYONECANPAY]);
        break;
      case "ReceiptInput":
        psbt = await this.signer.signPsbt(
          psbt,
          0,
          [Transaction.SIGHASH_SINGLE + Transaction.SIGHASH_ANYONECANPAY],
          (input as ReceiptInput).proof,
        );
    }

    psbt.finalizeInput(0);

    return psbt;
  }

  private async constructMakerPsbtFromInsAndOuts(inputs: TxInput[], output: TxOutput): Promise<Psbt> {
    let psbt = new Psbt({ network: this.network });
    psbt.setVersion(2);
    psbt.setLocktime(0);

    psbt.addOutput({
      script: this.outputToPayment(output).output!,
      value: output.satoshis,
    });

    inputs.forEach((input, i) => {
      psbt.addInput({
        hash: input.txId,
        index: input.index,
        nonWitnessUtxo: Buffer.from(input.hex, "hex"),
        sighashType: Transaction.SIGHASH_SINGLE + Transaction.SIGHASH_ANYONECANPAY,
      });
    });

    inputs.forEach(async (input, i) => {
      switch (input.type) {
        case "BitcoinInput":
          psbt = await this.signer.signPsbt(psbt, i, [Transaction.SIGHASH_SINGLE + Transaction.SIGHASH_ANYONECANPAY]);
          break;
        case "ReceiptInput":
          psbt = await this.signer.signPsbt(
            psbt,
            i,
            [Transaction.SIGHASH_SINGLE + Transaction.SIGHASH_ANYONECANPAY],
            (input as ReceiptInput).proof,
          );
      }

      psbt.finalizeInput(i);
    });

    return psbt;
  }

  async buildAndSignTakerPsbt(
    psbt: Psbt,
    makerInputs: TxInput[],
    takerInputs: TxInput[],
    outputs: TxOutput[],
    feeRateVb: number,
  ): Promise<Transaction> {
    let inputsToSign = Array.from({ length: takerInputs.length }, (_, index) => index);
    this.updateTakerPsbtChangeOutput(psbt.clone(), makerInputs, takerInputs, outputs, inputsToSign, feeRateVb);

    const psbtWithChange = await this.constructTakerPsbtFromInsAndOuts(psbt, takerInputs, outputs, inputsToSign);

    psbtWithChange.txInputs.map((input, i) => {
      if (psbtWithChange.data.inputs[i].finalScriptWitness === undefined) {
        psbtWithChange.data.inputs[i].finalScriptWitness =
          psbtWithChange.data.inputs[psbtWithChange.data.inputs.length - 1].finalScriptWitness;
      }
    });

    return psbtWithChange.extractTransaction();
  }

  private async updateTakerPsbtChangeOutput(
    psbt: Psbt,
    makerInputs: TxInput[],
    takerInputs: TxInput[],
    outputs: TxOutput[],
    inputsToSign: number[],
    feeRateVb: number,
  ) {
    const psbtToEstimate = await this.constructTakerPsbtFromInsAndOuts(psbt, takerInputs, outputs, inputsToSign);

    psbtToEstimate.txInputs.map((input, i) => {
      if (psbtToEstimate.data.inputs[i].finalScriptWitness === undefined) {
        psbtToEstimate.data.inputs[i].finalScriptWitness =
          psbtToEstimate.data.inputs[psbtToEstimate.data.inputs.length - 1].finalScriptWitness;
      }
    });

    const fee = Math.ceil(this.estimateFee(psbtToEstimate, feeRateVb));

    const inputsSum = this.sumSatoshis([...makerInputs, ...takerInputs]);
    const outputsSum = this.sumSatoshis(outputs);

    const change = inputsSum - outputsSum - fee - psbt.txOutputs[0].value;
    if (change < 0) {
      throw new Error("Not enough satoshis to pay fees");
    }

    outputs[outputs.length - 1].satoshis = change;
  }

  private async constructTakerPsbtFromInsAndOuts(
    psbt: Psbt,
    inputs: TxInput[],
    outputs: TxOutput[],
    inputsToSign: number[],
  ): Promise<Psbt> {
    outputs.forEach((output) => {
      psbt.addOutput({
        script: this.outputToPayment(output).output!,
        value: output.satoshis,
      });
    });

    const takerInputs = psbt.txInputs.length;
    inputs.forEach((input, i) => {
      psbt.addInput({
        hash: input.txId,
        index: input.index,
        nonWitnessUtxo: Buffer.from(input.hex, "hex"),
      });
    });

    inputs.forEach(async (input, i) => {
      if (inputsToSign.includes(i)) {
        switch (input.type) {
          case "BitcoinInput":
            psbt = await this.signer.signPsbt(psbt, takerInputs + i);
            break;
          case "ReceiptInput":
            psbt = await this.signer.signPsbt(psbt, takerInputs + i, null, (input as ReceiptInput).proof);
        }
      }
    });

    inputsToSign.map((value) => {
      psbt.finalizeInput(takerInputs + value);
    });

    return psbt;
  }

  public async signRawTransaction(unsignedTx: Transaction, prevouts: Map<String, String>): Promise<Transaction> {
    let psbt = new Psbt({ network: this.network });
    psbt.setVersion(unsignedTx.version);
    psbt.setLocktime(unsignedTx.locktime);

    unsignedTx.outs.forEach((out) => {
      psbt.addOutput(out);
    });

    unsignedTx.ins.forEach((input) => {
      psbt.addInput({
        hash: input.hash,
        index: input.index,
        nonWitnessUtxo: Buffer.from(prevouts.get(input.hash.toString("hex")), "hex"),
      });
    });

    psbt.txInputs.forEach(async (_, index) => {
      psbt = await this.signer.signPsbt(psbt, index);
    });

    psbt.finalizeAllInputs();

    return psbt.extractTransaction();
  }
}
