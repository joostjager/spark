import * as bitcoin from "bitcoinjs-lib";
import { LRCWallet } from "@buildonspark/lrc20-sdk";
import { NetworkType } from "@buildonspark/lrc20-sdk";
import {
  TokenPubkey,
  TxFreezeAnnouncement as TxFreezeAnnouncement,
  Lrc20TransactionDto,
} from "@buildonspark/lrc20-sdk";
import { JSONStringify } from "@buildonspark/lrc20-sdk";

let wallet = new LRCWallet(bitcoin.networks.regtest, NetworkType.REGTEST);

async function main() {
  await wallet.syncWallet();

  console.log(wallet.p2wpkhAddress);
  console.log(wallet.pubkey.toString("hex"));

  let tokenPubkey = new TokenPubkey(
    Buffer.from(
      "03acc24e8b9519696109d81c5e2ae327547eef3ab4a1f7ce552c582bb170f76e47",
      "hex",
    ),
  );
  let freezeAnnouncement = new TxFreezeAnnouncement(tokenPubkey, {
    txid: "8c6d40fc5c759ba8a9413d7b94cf8163678cea4c22deea089750abd6c9d41581",
    vout: 1,
  });

  let freezeTx = await wallet.prepareFreeze(freezeAnnouncement, 1.0);

  let txDto = Lrc20TransactionDto.fromLrc20Transaction(freezeTx);
  console.log(JSONStringify(txDto));

  let res = await wallet.broadcast(txDto);

  console.log(res);
}

main();
