import * as bitcoin from "bitcoinjs-lib";
import { LRCWallet } from "@buildonspark/lrc20-sdk";
import { NetworkType } from "@buildonspark/lrc20-sdk";
import { TokenPubkey, TokenPubkeyAnnouncement } from "@buildonspark/lrc20-sdk";

let wallet = new LRCWallet(bitcoin.networks.regtest, NetworkType.REGTEST);

async function main() {
  await wallet.syncWallet();

  let tokenPubkey = new TokenPubkey(
    Buffer.from(
      "03acc24e8b9519696109d81c5e2ae327547eef3ab4a1f7ce552c582bb170f76e47",
      "hex",
    ),
  );

  let name = "Wrapped USDT";
  let symbol = "WUSDT";
  let decimal = 6;
  let maxSupply = 0n;
  let isFreezable = true;

  let tokenPubkeyAnnouncement = new TokenPubkeyAnnouncement(
    tokenPubkey,
    name,
    symbol,
    decimal,
    maxSupply,
    isFreezable,
  );

  let announcementTx = await wallet.prepareAnnouncement(
    tokenPubkeyAnnouncement,
    1.0,
  );

  let res = await wallet.broadcastRawBtcTransaction(
    announcementTx.bitcoin_tx.toHex(),
  );

  console.log(res);
}

main();
