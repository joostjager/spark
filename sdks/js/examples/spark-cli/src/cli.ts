import { IssuerSparkWallet } from "@buildonspark/issuer-sdk";
import { getLatestDepositTxId } from "@buildonspark/spark-sdk";
import {
  decodeSparkAddress,
  encodeSparkAddress,
} from "@buildonspark/spark-sdk/address";
import {
  TokenTransactionStatus,
  TreeNode,
} from "@buildonspark/spark-sdk/proto/spark";
import {
  ConfigOptions,
  LOCAL_WALLET_CONFIG,
  MAINNET_WALLET_CONFIG,
  REGTEST_WALLET_CONFIG,
} from "@buildonspark/spark-sdk/services/wallet-config";
import { ExitSpeed } from "@buildonspark/spark-sdk/types";
import {
  constructUnilateralExitFeeBumpPackages,
  getNetwork,
  getP2TRScriptFromPublicKey,
  getP2WPKHAddressFromPublicKey,
  isEphemeralAnchorOutput,
  Network,
  NetworkType,
} from "@buildonspark/spark-sdk/utils";
import { bytesToHex, hexToBytes } from "@noble/curves/abstract/utils";
import { schnorr, secp256k1 } from "@noble/curves/secp256k1";
import { ripemd160 } from "@noble/hashes/legacy";
import { sha256 } from "@noble/hashes/sha2";
import { hex } from "@scure/base";
import { Address, OutScript, Transaction } from "@scure/btc-signer";
import fs from "fs";
import readline from "readline";

// Types for fee bump functionality
export interface Utxo {
  txid: string;
  vout: number;
  value: bigint;
  script: string;
  publicKey: string; // Private key in hex format for signing
}

export interface FeeRate {
  satPerVbyte: number;
}

// Helper function to convert WIF private key to hex
function wifToHex(wif: string): string {
  try {
    // WIF decoding using base58 (simplified version)
    const base58Alphabet =
      "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

    // Decode base58
    let decoded = BigInt(0);
    for (let i = 0; i < wif.length; i++) {
      const char = wif[i];
      const index = base58Alphabet.indexOf(char);
      if (index === -1) {
        throw new Error("Invalid character in WIF");
      }
      decoded = decoded * BigInt(58) + BigInt(index);
    }

    // Convert to hex and pad to ensure proper length
    let hex = decoded.toString(16);

    // WIF format: [version][32-byte private key][compression flag][4-byte checksum]
    // We want the 32-byte private key part (skip version byte, take 32 bytes)
    if (hex.length >= 74) {
      // 1 + 32 + 1 + 4 = 38 bytes = 76 hex chars minimum
      // Skip version byte (2 hex chars) and take 32 bytes (64 hex chars)
      const privateKeyHex = hex.substring(2, 66);
      return privateKeyHex;
    }

    throw new Error("Invalid WIF length");
  } catch (error) {
    throw new Error(`Failed to convert WIF to hex: ${error}`);
  }
}

// Helper function to create RIPEMD160(SHA256(data)) hash
function hash160(data: Uint8Array): Uint8Array {
  // Proper implementation using RIPEMD160(SHA256(data))
  const sha256Hash = sha256(data);
  return ripemd160(sha256Hash);
}

async function signPsbtWithExternalKey(
  psbtHex: string,
  privateKeyInput: string,
): Promise<string> {
  const tx = Transaction.fromPSBT(hexToBytes(psbtHex), {
    allowUnknown: true,
    allowLegacyWitnessUtxo: true,
    version: 3,
  });
  const privateKey = hexToBytes(privateKeyInput);
  for (let i = 0; i < tx.inputsLength; i++) {
    const input = tx.getInput(i);
    if (
      isEphemeralAnchorOutput(
        input?.witnessUtxo?.script,
        input?.witnessUtxo?.amount,
      )
    ) {
      continue;
    }
    tx.updateInput(i, {
      witnessScript: input?.witnessUtxo?.script,
    });
    tx.signIdx(privateKey, i);
    tx.finalizeIdx(i);
  }
  return bytesToHex(tx.toBytes(true, true));
}

// Helper function to sign a transaction with an external private key
async function signTransactionWithExternalKey(
  txHex: string,
  privateKeyInput: string,
): Promise<string> {
  try {
    // Parse the transaction
    const tx = Transaction.fromRaw(hexToBytes(txHex));

    let privateKey: Uint8Array;

    // Check if input is WIF format (starts with L, K, 5, c, or 9) or hex
    if (privateKeyInput.match(/^[LK5c9]/)) {
      console.log("Detected WIF format, converting to hex...");
      const privateKeyHex = wifToHex(privateKeyInput);
      console.log(`Converted WIF to hex: ${privateKeyHex}`);
      privateKey = hexToBytes(privateKeyHex);
    } else if (/^[0-9A-Fa-f]{64}$/.test(privateKeyInput)) {
      console.log("Detected hex format private key");
      privateKey = hexToBytes(privateKeyInput);
    } else {
      throw new Error(
        "Invalid private key format. Must be 64 hex characters or WIF format (starting with L, K, 5, c, or 9)",
      );
    }

    console.log(`Signing transaction with external private key...`);
    console.log(`Number of inputs: ${tx.inputsLength}`);
    console.log(`Number of outputs: ${tx.outputsLength}`);

    // Get the public key from the private key
    const publicKey = secp256k1.getPublicKey(privateKey, true);

    // Create the P2WPKH script for this key
    const pubKeyHash = hash160(publicKey);
    const p2wpkhScript = new Uint8Array([0x00, 0x14, ...pubKeyHash]); // OP_0 + 20-byte hash

    console.log(`Public key: ${bytesToHex(publicKey)}`);
    console.log(`P2WPKH script: ${bytesToHex(p2wpkhScript)}`);

    // Check each input to determine which ones need signing
    let inputsSigned = 0;
    for (let i = 0; i < tx.inputsLength; i++) {
      const input = tx.getInput(i);

      // If witnessUtxo is missing, we need to add it
      if (!input?.witnessUtxo?.script) {
        console.log(
          `Input ${i}: No witnessUtxo script, attempting to add P2WPKH script`,
        );

        // For now, we'll assume this input should use our P2WPKH script
        // In a real scenario, you'd need to know the actual UTXO amount
        // Let's use a placeholder amount - you'll need to provide the correct amount
        const placeholderAmount = 10534n; // You'll need to replace this with actual UTXO amounts

        tx.updateInput(i, {
          witnessUtxo: {
            script: p2wpkhScript,
            amount: placeholderAmount,
          },
        });

        console.log(
          `Input ${i}: Added P2WPKH witnessUtxo with amount ${placeholderAmount}`,
        );
      }

      const script = tx.getInput(i)?.witnessUtxo?.script;
      if (!script) {
        console.log(`Input ${i}: Still no script after update, skipping`);
        continue;
      }

      // Check if this is an ephemeral anchor (OP_TRUE script)
      if (script.length === 1 && script[0] === 0x51) {
        console.log(
          `Input ${i}: Ephemeral anchor (OP_TRUE), skipping signature`,
        );
        continue;
      }

      // Check if this script matches our P2WPKH script
      if (bytesToHex(script) === bytesToHex(p2wpkhScript)) {
        console.log(`Input ${i}: Matches our P2WPKH script, signing`);

        // Sign this specific input
        try {
          tx.signIdx(privateKey, i);
          tx.finalizeIdx(i);
          inputsSigned++;
          console.log(`✅ Successfully signed input ${i}`);
        } catch (error) {
          console.log(`❌ Failed to sign input ${i}: ${error}`);
        }
      } else {
        console.log(
          `Input ${i}: Script doesn't match our P2WPKH script, skipping`,
        );
        console.log(`  Expected: ${bytesToHex(p2wpkhScript)}`);
        console.log(`  Actual:   ${bytesToHex(script)}`);
      }
    }

    if (inputsSigned === 0) {
      throw new Error(
        "No inputs were signed. Check that the transaction contains inputs controlled by the provided private key, or provide the correct UTXO amounts.",
      );
    }

    const signedTxHex = tx.hex;
    console.log("✅ Transaction signed successfully!");
    console.log(`Signed ${inputsSigned} out of ${tx.inputsLength} inputs`);
    console.log(`Signed transaction size: ${signedTxHex.length / 2} bytes`);
    console.log(`Transaction ID: ${tx.id}`);

    return signedTxHex;
  } catch (error) {
    console.error("❌ Error signing transaction with external key:", error);
    throw error;
  }
}

// Helper function to convert hex private key to WIF
function hexToWif(hexPrivateKey: string): string {
  try {
    // For regtest, the version byte is 0xEF
    const privateKeyBytes = hexToBytes(hexPrivateKey);

    // WIF format: [version][32-byte private key][compression flag][4-byte checksum]
    const version = 0xef; // Regtest version byte
    const compressionFlag = 0x01; // Compressed public key

    // Combine version + private key + compression flag
    const combined = new Uint8Array([
      version,
      ...privateKeyBytes,
      compressionFlag,
    ]);

    // Calculate double SHA256 checksum
    const hash1 = sha256(combined);
    const hash2 = sha256(hash1);
    const checksum = hash2.slice(0, 4);

    // Combine everything
    const withChecksum = new Uint8Array([...combined, ...checksum]);

    // Base58 encode
    const base58Alphabet =
      "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    let num = BigInt("0x" + bytesToHex(withChecksum));
    let encoded = "";

    while (num > 0) {
      const remainder = Number(num % 58n);
      encoded = base58Alphabet[remainder] + encoded;
      num = num / 58n;
    }

    // Add leading zeros for leading zero bytes
    for (let i = 0; i < withChecksum.length && withChecksum[i] === 0; i++) {
      encoded = "1" + encoded;
    }

    return encoded;
  } catch (error) {
    throw new Error(`Failed to convert hex to WIF: ${error}`);
  }
}

const commands = [
  "initwallet",
  "getbalance",
  "getdepositaddress",
  "getstaticdepositaddress",
  "getsparkaddress",
  "getlatesttx",
  "claimdeposit",
  "claimstaticdepositquote",
  "claimstaticdeposit",
  "refundstaticdeposit",
  "createpaymentintent",
  "createinvoice",
  "payinvoice",
  "sendtransfer",
  "withdraw",
  "withdrawalfee",
  "lightningsendfee",
  "getlightningsendrequest",
  "getlightningreceiverequest",
  "getcoopexitrequest",
  "gettransfers",
  "transfertokens",
  "gettokenl1address",
  "getissuertokenbalance",
  "getissuertokeninfo",
  "getissuertokenpublickey",
  "minttokens",
  "burntokens",
  "freezetokens",
  "unfreezetokens",
  "getissuertokenactivity",
  "announcetoken",
  "nontrustydeposit",
  "querytokentransactions",

  "generatefeebumppackagetobroadcast",
  "testonly_generateexternalwallet",
  "signfeebump",
  "checktimelock",
  "getleaves",
  "leafidtohex",
  "testonly_generateutxostring",
  "testonly_expiretimelock",
  "testonly_expiretimelockrefundtx",

  "help",
  "exit",
  "quit",
];

// Initialize Spark Wallet
const walletMnemonic =
  "cctypical stereo dose party penalty decline neglect feel harvest abstract stage winter";

// Helper function to get explorer URL for a transaction
function getExplorerUrl(network: string, txid: string): string {
  switch (network) {
    case "MAINNET":
      return `https://mempool.space/tx/${txid}`;
    case "REGTEST":
      return `https://regtest-mempool.us-west-2.sparkinfra.net/tx/${txid}`;
    case "LOCAL":
      return `http://127.0.0.1:30000/tx/${txid}`;
    default:
      return `Transaction ID: ${txid}`;
  }
}

async function runCLI() {
  // Get network from environment variable
  const network = (() => {
    const envNetwork = process.env.NETWORK?.toUpperCase();
    if (envNetwork === "MAINNET") return "MAINNET";
    if (envNetwork === "LOCAL") return "LOCAL";
    return "REGTEST"; // default
  })();

  const configFile = process.env.CONFIG_FILE;
  let config: ConfigOptions = {};
  if (configFile) {
    try {
      const data = fs.readFileSync(configFile, "utf8");
      config = JSON.parse(data);
      if (config.network !== network) {
        console.error("Network mismatch in config file");
        return;
      }
    } catch (err) {
      console.error("Error reading config file:", err);
      return;
    }
  } else {
    switch (network) {
      case "MAINNET":
        config = MAINNET_WALLET_CONFIG;
        break;
      case "REGTEST":
        config = REGTEST_WALLET_CONFIG;
        break;
      default:
        config = LOCAL_WALLET_CONFIG;
        break;
    }
  }

  let wallet: IssuerSparkWallet | undefined;

  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
    completer: (line: string) => {
      const completions = commands.filter((c) => c.startsWith(line));
      return [completions.length ? completions : commands, line];
    },
  });
  const helpMessage = `
  Available commands:
  initwallet [mnemonic | seed]                                        - Create a new wallet from a mnemonic or seed. If no mnemonic or seed is provided, a new mnemonic will be generated.
  getbalance                                                          - Get the wallet's balance
  getdepositaddress                                                   - Get an address to deposit funds from L1 to Spark
  getstaticdepositaddress                                             - Get a static address to deposit funds from L1 to Spark
  identity                                                            - Get the wallet's identity public key
  getsparkaddress                                                     - Get the wallet's spark address
  decodesparkaddress <sparkAddress> <network(MAINNET|REGTEST|SIGNET|TESTNET|LOCAL))> - Decode a spark address to get the identity public key
  getlatesttx <address>                                               - Get the latest deposit transaction id for an address
  claimdeposit <txid>                                                 - Claim any pending deposits to the wallet
  claimstaticdepositquote <txid> [outputIndex]                        - Get a quote for claiming a static deposit
  claimstaticdeposit <txid> <creditAmountSats> <sspSignature> [outputIndex] - Claim a static deposits
  refundstaticdeposit <depositTransactionId> <destinationAddress> <fee> [outputIndex] - Refund a static deposit
  gettransfers [limit] [offset]                                       - Get a list of transfers
  createinvoice <amount> <memo> <includeSparkAddress> [receiverIdentityPubkey] [descriptionHash] - Create a new lightning invoice
  payinvoice <invoice> <maxFeeSats> <preferSpark>                     - Pay a lightning invoice
  createpaymentintent <asset("btc" | tokenPubKey)> <amount> <memo>   - Create a spark payment request
  sendtransfer <amount> <receiverSparkAddress>                        - Send a spark transfer
  withdraw <amount> <onchainAddress> <exitSpeed(FAST|MEDIUM|SLOW)>    - Withdraw funds to an L1 address
  withdrawalfee <amount> <withdrawalAddress>                          - Get a fee estimate for a withdrawal (cooperative exit)
  lightningsendfee <invoice>                                          - Get a fee estimate for a lightning send
  getlightningsendrequest <requestId>                                 - Get a lightning send request by ID
  getlightningreceiverequest <requestId>                              - Get a lightning receive request by ID
  getcoopexitrequest <requestId>                                      - Get a coop exit request by ID
  generatefeebumppackagetobroadcast <feeRate> <utxo1:txid:vout:value:script:publicKey> [utxo2:...] [nodeHexString1] [nodeHexString2 ...] - Get fee bump packages for unilateral exit transactions (if no nodes provided, uses all wallet leaves)
  signfeebump <feeBumpPsbt> <privateKey>                                - Sign a fee bump package with the utxo private key
  testonly_generateexternalwallet                              - Generate test wallet to fund utxos for fee bumping
  testonly_generateutxostring <txid> <vout> <value> <publicKey>                      - Generate correctly formatted UTXO string from your private key
  checktimelock <leafId>                                              - Get the remaining timelock for a given leaf
  testonly_expiretimelock <leafId>                                            - Refresh the timelock for a given leaf
  testonly_expiretimelockrefundtx <leafId>                                    - Refresh only the refund transaction timelock for a given leaf
  leafidtohex <leafId1> [leafId2] [leafId3] ...                              - Convert leaf ID to hex string for unilateral exit
  getleaves                                                           - Get all leaves owned by the wallet

  💡 Simplified Unilateral Exit Flow:
  'generatefeebumppackagetobroadcast <feeRate> <utxos>' for fee bumping.
  The advanced commands below are for specific use cases.

  Token Holder Commands:
  transfertokens <tokenPubKey> <receiverSparkAddress> <amount>        - Transfer tokens
  batchtransfertokens <tokenPubKey> <receiverAddress1:amount1> <receiverAddress2:amount2> ... - Transfer tokens with multiple outputs

  Token Issuer Commands:
  gettokenl1address                                                   - Get the L1 address for on-chain token operations
  getissuertokenbalance                                               - Get the issuer's token balance
  getissuertokeninfo                                                  - Get the issuer's token information
  getissuertokenpublickey                                             - Get the issuer's token public key
  minttokens <amount>                                                 - Mint new tokens
  burntokens <amount>                                                 - Burn tokens
  freezetokens <sparkAddress>                                         - Freeze tokens for a specific address
  unfreezetokens <sparkAddress>                                       - Unfreeze tokens for a specific address
  getissuertokenactivity                                              - Get issuer's token activity
  announcetoken <tokenName> <tokenTicker> <decimals> <maxSupply> <isFreezable> - Announce token on L1

  help                                                                - Show this help message
  exit/quit                                                           - Exit the program
`;
  console.log(helpMessage);
  console.log(
    "\x1b[41m%s\x1b[0m",
    "⚠️  WARNING: This is an example CLI implementation and is not intended for production use. Use at your own risk. The official package is available at https://www.npmjs.com/package/@buildonspark/spark-sdk  ⚠️",
  );
  while (true) {
    const command = await new Promise<string>((resolve) => {
      rl.question("> ", resolve);
    });

    const [firstWord, ...args] = command.split(" ");
    const lowerCommand = firstWord.toLowerCase();

    if (lowerCommand === "exit" || lowerCommand === "quit") {
      rl.close();
      break;
    }

    try {
      switch (lowerCommand) {
        case "help":
          console.log(helpMessage);
          break;
        case "nontrustydeposit":
          if (process.env.NODE_ENV !== "development" || network !== "REGTEST") {
            console.log(
              "This command is only available in the development environment and on the REGTEST network",
            );
            break;
          }
          /**
           * This is an example of how to create a non-trusty deposit. Real implementation may differ.
           *
           * 1. Get an address to deposit funds from L1 to Spark
           * 2. Construct a tx spending from the L1 address to the Spark address
           * 3. Call initalizeDeposit with the tx hex
           * 4. Sign the tx
           * 5. Broadcast the tx
           */

          if (!wallet) {
            console.log("Please initialize a wallet first");
            break;
          }
          if (args.length !== 1) {
            console.log("Usage: nontrustydeposit <destinationBtcAddress>");
            break;
          }

          const privateKey =
            "9303c68c414a6208dbc0329181dd640b135e669647ad7dcb2f09870c54b26ed9";

          // IMPORTANT: This address needs to be funded with regtest BTC before running this example
          const sourceAddress =
            "bcrt1pzrfhq4gm7kuww875lkj27cx005x08g2jp6qxexnu68gytn7sjqss3s6j2c";

          try {
            // Fetch transactions for the address
            const response = await fetch(
              `${config.electrsUrl}/address/${sourceAddress}/txs`,
              {
                headers: {
                  Authorization:
                    "Basic " +
                    Buffer.from("spark-sdk:mCMk1JqlBNtetUNy").toString(
                      "base64",
                    ),
                },
              },
            );

            const transactions: any = await response.json();

            // Find unspent outputs
            const utxos: {
              txid: string;
              vout: number;
              value: bigint;
              scriptPubKey: string;
              desc: string;
            }[] = [];
            for (const tx of transactions) {
              for (let voutIndex = 0; voutIndex < tx.vout.length; voutIndex++) {
                const output = tx.vout[voutIndex];
                if (output.scriptpubkey_address === sourceAddress) {
                  const isSpent = transactions.some((otherTx: any) =>
                    otherTx.vin.some(
                      (input: any) =>
                        input.txid === tx.txid && input.vout === voutIndex,
                    ),
                  );

                  if (!isSpent) {
                    utxos.push({
                      txid: tx.txid,
                      vout: voutIndex,
                      value: BigInt(output.value),
                      scriptPubKey: output.scriptpubkey,
                      desc: output.desc,
                    });
                  }
                }
              }
            }

            if (utxos.length === 0) {
              console.log(
                `No unspent outputs found. Please fund the address ${sourceAddress} first`,
              );
              break;
            }

            // Create unsigned transaction
            const tx = new Transaction();

            const sendAmount = 10000n; // 10000 sats
            const utxo = utxos[0];

            // Add input without signing
            tx.addInput({
              txid: utxo.txid,
              index: utxo.vout,
              witnessUtxo: {
                script: getP2TRScriptFromPublicKey(
                  secp256k1.getPublicKey(hexToBytes(privateKey)),
                  Network.REGTEST,
                ),
                amount: utxo.value,
              },
              tapInternalKey: schnorr.getPublicKey(hexToBytes(privateKey)),
            });

            // Add output for destination
            const destinationAddress = Address(
              getNetwork(Network.REGTEST),
            ).decode(args[0]);
            const desitnationScript = OutScript.encode(destinationAddress);
            tx.addOutput({
              script: desitnationScript,
              amount: sendAmount,
            });

            // Get unsigned transaction hex
            // Initialize deposit with unsigned transaction
            console.log("Initializing deposit with unsigned transaction...");
            const depositResult = await wallet.advancedDeposit(tx.hex);
            console.log("Deposit initialization result:", depositResult);

            // Now sign the transaction
            console.log("Signing transaction...");
            tx.sign(hexToBytes(privateKey));
            tx.finalize();

            const signedTxHex = hex.encode(tx.extract());

            // Broadcast the signed transaction
            const broadcastResponse = await fetch(`${config.electrsUrl}/tx`, {
              method: "POST",
              headers: {
                Authorization:
                  "Basic " +
                  Buffer.from("spark-sdk:mCMk1JqlBNtetUNy").toString("base64"),
                "Content-Type": "text/plain",
              },
              body: signedTxHex,
            });

            if (!broadcastResponse.ok) {
              const error = await broadcastResponse.text();
              throw new Error(`Failed to broadcast transaction: ${error}`);
            }

            const txid = await broadcastResponse.text();
            console.log("Transaction broadcast successful!", txid);
          } catch (error: any) {
            console.error("Error creating deposit:", error);
            console.error("Error details:", error.message);
          }
          break;
        case "getlatesttx":
          const latestTx = await getLatestDepositTxId(args[0]);
          console.log(latestTx);
          break;
        case "claimdeposit":
          if (!wallet) {
            console.log("Please initialize a wallet first");
            break;
          }
          const depositResult = await wallet.claimDeposit(args[0]);

          await new Promise((resolve) => setTimeout(resolve, 1000));

          console.log(depositResult);
          break;
        case "gettransfers":
          if (!wallet) {
            console.log("Please initialize a wallet first");
            break;
          }
          const limit = args[0] ? parseInt(args[0]) : 10;
          const offset = args[1] ? parseInt(args[1]) : 0;
          if (isNaN(limit) || isNaN(offset)) {
            console.log("Invalid limit or offset");
            break;
          }
          if (limit < 0 || offset < 0) {
            console.log("Limit and offset must be non-negative");
            break;
          }
          const transfers = await wallet.getTransfers(limit, offset);
          console.log(transfers);
          break;
        case "getlightningsendrequest":
          if (!wallet) {
            console.log("Please initialize a wallet first");
            break;
          }
          const lightningSendRequest = await wallet.getLightningSendRequest(
            args[0],
          );
          console.log(lightningSendRequest);
          break;
        case "getlightningreceiverequest":
          if (!wallet) {
            console.log("Please initialize a wallet first");
            break;
          }
          const lightningReceiveRequest =
            await wallet.getLightningReceiveRequest(args[0]);
          console.log(lightningReceiveRequest);
          break;
        case "getcoopexitrequest":
          if (!wallet) {
            console.log("Please initialize a wallet first");
            break;
          }
          const coopExitRequest = await wallet.getCoopExitRequest(args[0]);
          console.log(coopExitRequest);
          break;
        case "initwallet":
          if (wallet) {
            wallet.cleanupConnections();
          }
          let mnemonicOrSeed;
          let accountNumber;
          if (args.length == 13) {
            mnemonicOrSeed = args.slice(0, -1).join(" ");
            accountNumber = parseInt(args[args.length - 1]);
          } else if (args.length == 12) {
            mnemonicOrSeed = args.join(" ");
          } else if (args.length !== 0) {
            console.log(
              "Invalid number of arguments - usage: initwallet [mnemonic | seed] [accountNumber (optional)]",
            );
            break;
          }
          let options: ConfigOptions = {
            ...config,
            network,
          };
          try {
            const { wallet: newWallet, mnemonic: newMnemonic } =
              await IssuerSparkWallet.initialize({
                mnemonicOrSeed,
                options,
                accountNumber,
              });
            wallet = newWallet;
            console.log("Mnemonic:", newMnemonic);
            console.log("Network:", options.network);
            wallet.on(
              "deposit:confirmed",
              (depositId: string, balance: number) => {
                console.log(
                  `Deposit ${depositId} marked as available. New balance: ${balance}`,
                );
              },
            );

            wallet.on(
              "transfer:claimed",
              (transferId: string, balance: number) => {
                console.log(
                  `Transfer ${transferId} claimed. New balance: ${balance}`,
                );
              },
            );
            wallet.on("stream:connected", () => {
              console.log("Stream connected");
            });
            wallet.on(
              "stream:reconnecting",
              (
                attempt: number,
                maxAttempts: number,
                delayMs: number,
                error: string,
              ) => {
                console.log(
                  "Stream reconnecting",
                  attempt,
                  maxAttempts,
                  delayMs,
                  error,
                );
              },
            );
            wallet.on("stream:disconnected", (reason: string) => {
              console.log("Stream disconnected", reason);
            });
          } catch (error: any) {
            console.error("Error initializing wallet:", error);
            break;
          }
          break;
        case "getbalance":
          if (!wallet) {
            console.log("Please initialize a wallet first");
            break;
          }
          const balanceInfo = await wallet.getBalance();
          console.log("Sats Balance: " + balanceInfo.balance);
          if (balanceInfo.tokenBalances && balanceInfo.tokenBalances.size > 0) {
            console.log("\nToken Balances:");
            for (const [
              tokenPublicKey,
              tokenInfo,
            ] of balanceInfo.tokenBalances.entries()) {
              console.log(`  Token (${tokenPublicKey}):`);
              console.log(`    Balance: ${tokenInfo.balance}`);
            }
          }
          break;
        case "getdepositaddress":
          if (!wallet) {
            console.log("Please initialize a wallet first");
            break;
          }
          const depositAddress = await wallet.getSingleUseDepositAddress();
          console.log(
            "WARNING: This is a single-use address, DO NOT deposit more than once or you will lose funds!",
          );
          console.log(depositAddress);
          break;
        case "getstaticdepositaddress":
          if (!wallet) {
            console.log("Please initialize a wallet first");
            break;
          }
          const staticDepositAddress = await wallet.getStaticDepositAddress();
          console.log("This is a multi-use address.");
          console.log(staticDepositAddress);
          break;
        case "claimstaticdepositquote":
          if (!wallet) {
            console.log("Please initialize a wallet first");
            break;
          }

          if (args[1] === undefined) {
            const claimDepositQuote = await wallet.getClaimStaticDepositQuote(
              args[0],
            );

            console.log(claimDepositQuote);
          } else {
            const outputIndex = parseInt(args[1]);
            const claimDepositQuote = await wallet.getClaimStaticDepositQuote(
              args[0],
              outputIndex,
            );

            console.log(claimDepositQuote);
          }
          break;
        case "claimstaticdeposit":
          if (!wallet) {
            console.log("Please initialize a wallet first");
            break;
          }

          if (args[3] === undefined) {
            const claimDeposit = await wallet.claimStaticDeposit({
              transactionId: args[0],
              creditAmountSats: parseInt(args[1]),
              sspSignature: args[2],
            });

            console.log(claimDeposit);
          } else {
            const claimDeposit = await wallet.claimStaticDeposit({
              transactionId: args[0],
              creditAmountSats: parseInt(args[1]),
              sspSignature: args[2],
              outputIndex: parseInt(args[3]),
            });

            console.log(claimDeposit);
          }
          break;
        case "refundstaticdeposit":
          if (!wallet) {
            console.log("Please initialize a wallet first");
            break;
          }
          const refundDeposit = await wallet.refundStaticDeposit({
            depositTransactionId: args[0],
            destinationAddress: args[1],
            fee: parseInt(args[2]),
            outputIndex: args[3] ? parseInt(args[3]) : undefined,
          });
          console.log("Broadcast the transaction below to refund the deposit");
          console.log(refundDeposit);
          break;
        case "identity":
          if (!wallet) {
            console.log("Please initialize a wallet first");
            break;
          }
          const identity = await wallet.getIdentityPublicKey();
          console.log(identity);
          break;
        case "getsparkaddress":
          if (!wallet) {
            console.log("Please initialize a wallet first");
            break;
          }
          const sparkAddress = await wallet.getSparkAddress();
          console.log(sparkAddress);
          break;
        case "decodesparkaddress":
          if (args.length !== 2) {
            console.log(
              "Usage: decodesparkaddress <sparkAddress> <network> (mainnet, regtest, testnet, signet, local)",
            );
            break;
          }

          const decodedAddress = decodeSparkAddress(
            args[0],
            args[1].toUpperCase() as NetworkType,
          );
          console.log(decodedAddress);
          break;
        case "encodeaddress":
          if (args.length !== 2) {
            console.log(
              "Usage: encodeaddress <sparkAddress> <network> (mainnet, regtest, testnet, signet, local)",
            );
            break;
          }
          const encodedAddress = encodeSparkAddress({
            identityPublicKey: args[0],
            network: args[1].toUpperCase() as NetworkType,
          });
          console.log(encodedAddress);
          break;
        case "createinvoice":
          if (!wallet) {
            console.log("Please initialize a wallet first");
            break;
          }
          const invoice = await wallet.createLightningInvoice({
            amountSats: parseInt(args[0]),
            memo: args[1],
            includeSparkAddress: args[2] === "true",
            receiverIdentityPubkey: args[3],
            descriptionHash: args[4],
          });
          console.log(invoice);
          break;
        case "payinvoice":
          if (!wallet) {
            console.log("Please initialize a wallet first");
            break;
          }
          let maxFeeSats = parseInt(args[1]);
          if (isNaN(maxFeeSats)) {
            console.log("Invalid maxFeeSats value");
            break;
          }
          const payment = await wallet.payLightningInvoice({
            invoice: args[0],
            maxFeeSats: maxFeeSats,
            preferSpark: args[2] === "true",
          });
          console.log(payment);
          break;
        case "createpaymentintent":
          if (!wallet) {
            console.log("Please initialize a wallet first");
            break;
          }
          const paymentRequest = await wallet.createSparkPaymentIntent(
            args[0] === "btc" ? undefined : args[0],
            BigInt(args[1]),
            args[2],
          );
          console.log(paymentRequest);
          break;
        case "sendtransfer":
          if (!wallet) {
            console.log("Please initialize a wallet first");
            break;
          }
          const transfer = await wallet.transfer({
            amountSats: parseInt(args[0]),
            receiverSparkAddress: args[1],
          });
          console.log(transfer);
          break;
        case "transfertokens":
          if (!wallet) {
            console.log("Please initialize a wallet first");
            break;
          }
          if (args.length < 3) {
            console.log(
              "Usage: transfertokens <tokenPubKey> <receiverPubKey> <amount>",
            );
            break;
          }

          const tokenPubKey = args[0];
          const tokenReceiverPubKey = args[1];
          const tokenAmount = BigInt(parseInt(args[2]));

          try {
            const result = await wallet.transferTokens({
              tokenPublicKey: tokenPubKey,
              tokenAmount: tokenAmount,
              receiverSparkAddress: tokenReceiverPubKey,
            });
            console.log("Transfer Transaction ID:", result);
          } catch (error) {
            let errorMsg = "Unknown error";
            if (error instanceof Error) {
              errorMsg = error.message;
            }
            console.error(`Failed to transfer tokens: ${errorMsg}`);
          }
          break;
        case "batchtransfertokens":
          if (!wallet) {
            console.log("Please initialize a wallet first");
            break;
          }
          if (args.length < 2) {
            console.log(
              "Usage: batchtransfertokens <tokenPubKey> <receiverAddress1:amount1> <receiverAddress2:amount2> ...",
            );
            break;
          }

          const batchTokenPubKey = args[0];
          let tokenTransfers = [];

          for (let i = 1; i < args.length; i++) {
            const parts = args[i].split(":");
            if (parts.length !== 2) {
              console.log(
                `Invalid format for argument ${i}: ${args[i]}. Expected format: address:amount`,
              );
              break;
            }

            const receiverAddress = parts[0];
            const amount = parseInt(parts[1]);

            if (isNaN(amount)) {
              console.log(`Invalid amount for argument ${i}: ${parts[1]}`);
              break;
            }

            tokenTransfers.push({
              tokenPublicKey: batchTokenPubKey,
              tokenAmount: BigInt(amount),
              receiverSparkAddress: receiverAddress,
            });
          }

          if (tokenTransfers.length === 0) {
            console.log("No valid transfers provided");
            break;
          }

          try {
            const results = await wallet.batchTransferTokens(tokenTransfers);
            console.log("Transfer Transaction ID:", results);
            console.log(`Successfully sent ${tokenTransfers.length} outputs`);
          } catch (error) {
            let errorMsg = "Unknown error";
            if (error instanceof Error) {
              errorMsg = error.message;
            }
            console.error(`Failed to batch transfer tokens: ${errorMsg}`);
          }
          break;
        case "withdraw":
          if (!wallet) {
            console.log("Please initialize a wallet first");
            break;
          }
          const withdrawal = await wallet.withdraw({
            amountSats: parseInt(args[0]),
            onchainAddress: args[1],
            exitSpeed: args[2].toUpperCase() as ExitSpeed,
          });
          console.log(withdrawal);
          break;
        case "withdrawalfee": {
          if (!wallet) {
            console.log("Please initialize a wallet first");
            break;
          }
          const fee = await wallet.getWithdrawalFeeEstimate({
            amountSats: parseInt(args[0]),
            withdrawalAddress: args[1],
          });

          console.log(fee);
          break;
        }
        case "lightningsendfee": {
          if (!wallet) {
            console.log("Please initialize a wallet first");
            break;
          }
          const fee = await wallet.getLightningSendFeeEstimate({
            encodedInvoice: args[0],
          });
          console.log(fee);
          break;
        }
        case "gettokenl1address": {
          if (!wallet) {
            console.log("Please initialize a wallet first");
            break;
          }
          const l1Address = await wallet.getTokenL1Address();
          console.log(l1Address);
          break;
        }
        case "getissuertokenbalance": {
          if (!wallet) {
            console.log("Please initialize a wallet first");
            break;
          }
          const balance = await wallet.getIssuerTokenBalance();
          console.log("Issuer Token Balance:", balance.balance.toString());
          break;
        }
        case "getissuertokeninfo": {
          if (!wallet) {
            console.log("Please initialize a wallet first");
            break;
          }
          const info = await wallet.getIssuerTokenInfo();
          if (info) {
            console.log("Token Info:", {
              tokenPublicKey: info.tokenPublicKey,
              tokenName: info.tokenName,
              tokenSymbol: info.tokenSymbol,
              tokenDecimals: info.tokenDecimals,
              maxSupply: info.maxSupply.toString(),
              isFreezable: info.isFreezable,
            });
          } else {
            console.log("No token info found");
          }
          break;
        }
        case "getissuertokenpublickey": {
          if (!wallet) {
            console.log("Please initialize a wallet first");
            break;
          }
          const pubKey = await wallet.getIdentityPublicKey();
          console.log("Issuer Token Public Key:", pubKey);
          break;
        }
        case "minttokens": {
          if (!wallet) {
            console.log("Please initialize a wallet first");
            break;
          }
          const amount = BigInt(parseInt(args[0]));
          const result = await wallet.mintTokens(amount);
          console.log("Mint Transaction ID:", result);
          break;
        }
        case "burntokens": {
          if (!wallet) {
            console.log("Please initialize a wallet first");
            break;
          }
          const amount = BigInt(parseInt(args[0]));
          const result = await wallet.burnTokens(amount);
          console.log("Burn Transaction ID:", result);
          break;
        }
        case "freezetokens": {
          if (!wallet) {
            console.log("Please initialize a wallet first");
            break;
          }
          const result = await wallet.freezeTokens(args[0]);
          console.log("Freeze Result:", {
            impactedOutputIds: result.impactedOutputIds,
            impactedTokenAmount: result.impactedTokenAmount.toString(),
          });
          break;
        }
        case "unfreezetokens": {
          if (!wallet) {
            console.log("Please initialize a wallet first");
            break;
          }
          const result = await wallet.unfreezeTokens(args[0]);
          console.log("Unfreeze Result:", {
            impactedOutputIds: result.impactedOutputIds,
            impactedTokenAmount: result.impactedTokenAmount.toString(),
          });
          break;
        }
        case "getissuertokenactivity": {
          if (!wallet) {
            console.log("Please initialize a wallet first");
            break;
          }
          const result = await wallet.getIssuerTokenActivity();
          if (!result.transactions || result.transactions.length === 0) {
            console.log("No transactions found");
          }
          for (const transaction of result.transactions) {
            console.log(
              `Token Activity - case: ${transaction.transaction?.$case} | operation type: ${transaction.transaction?.$case === "spark" ? transaction.transaction?.spark.operationType : transaction.transaction?.onChain.operationType}`,
            );
          }
          break;
        }
        case "announcetoken": {
          if (!wallet) {
            console.log("Please initialize a wallet first");
            break;
          }
          if (args.length < 5) {
            console.log(
              "Usage: announcetoken <tokenName> <tokenTicker> <decimals> <maxSupply> <isFreezable>",
            );
            break;
          }
          const [tokenName, tokenTicker, decimals, maxSupply, isFreezable] =
            args;
          const result = await wallet.announceTokenL1(
            tokenName,
            tokenTicker,
            parseInt(decimals),
            BigInt(maxSupply),
            isFreezable.toLowerCase() === "true",
          );
          console.log("Token Announcement Transaction ID:", result);
          break;
        }
        case "querytokentransactions": {
          if (!wallet) {
            console.log("Please initialize a wallet first");
            break;
          }
          if (args.length > 2) {
            console.log(
              "Usage: querytokentransactions [tokenPublicKey] [tokenTransactionHash]",
            );
            break;
          }

          try {
            let tokenPublicKeys: string[];
            if (args.length === 0) {
              // If no token public key is provided, use the wallet's own public key
              const publicKey = await wallet.getIdentityPublicKey();
              tokenPublicKeys = [publicKey];
            } else {
              tokenPublicKeys = [args[0]];
            }

            const tokenTransactionHashes = args[1] ? [args[1]] : undefined;

            const transactions = await wallet.queryTokenTransactions(
              tokenPublicKeys,
              tokenTransactionHashes,
            );
            console.log("\nToken Transactions:");
            for (const tx of transactions) {
              console.log("\nTransaction Details:");
              console.log(`  Status: ${TokenTransactionStatus[tx.status]}`);

              if (tx.tokenTransaction?.tokenInputs) {
                const input = tx.tokenTransaction.tokenInputs;
                if (input.$case === "mintInput") {
                  console.log("  Type: Mint");
                  console.log(
                    `  Issuer Public Key: ${hex.encode(input.mintInput.issuerPublicKey)}`,
                  );
                  console.log(
                    `  Timestamp: ${new Date(input.mintInput.issuerProvidedTimestamp * 1000).toISOString()}`,
                  );
                } else if (input.$case === "transferInput") {
                  console.log("  Type: Transfer");
                  console.log(
                    `  Outputs to Spend: ${input.transferInput.outputsToSpend.length}`,
                  );
                }
              }

              if (tx.tokenTransaction?.tokenOutputs) {
                console.log("\n  Outputs:");
                for (const output of tx.tokenTransaction.tokenOutputs) {
                  console.log(
                    `    Owner Public Key: ${hex.encode(output.ownerPublicKey)}`,
                  );
                  console.log(
                    `    Token Public Key: ${hex.encode(output.tokenPublicKey)}`,
                  );
                  console.log(
                    `    Token Amount: ${hex.encode(output.tokenAmount)}`,
                  );
                  if (output.withdrawBondSats !== undefined) {
                    console.log(
                      `    Withdraw Bond Sats: ${output.withdrawBondSats}`,
                    );
                  }
                  if (output.withdrawRelativeBlockLocktime !== undefined) {
                    console.log(
                      `    Withdraw Relative Block Locktime: ${output.withdrawRelativeBlockLocktime}`,
                    );
                  }
                  console.log("    ---");
                }
              }
              console.log("----------------------------------------");
            }
          } catch (error) {
            console.error("Error querying token transactions:", error);
          }
          break;
        }
        case "signfeebump": {
          if (args.length < 2) {
            console.log("Usage: signfeebump <feeBumpTx> <privateKeyHex>");
            break;
          }

          const feeBumpTx = args[0];
          const privateKeyHex = args[1];
          const signedTx = await signPsbtWithExternalKey(
            feeBumpTx,
            privateKeyHex,
          );
          console.log("Signed Fee Bump Transaction:", signedTx);
          break;
        }
        case "generatefeebumppackagetobroadcast": {
          if (!wallet) {
            console.log("Please initialize a wallet first");
            break;
          }
          if (args.length < 1) {
            console.log(
              "Usage: generatefeebumppackagetobroadcast <feeRate> <utxo1:txid:vout:value:script:privateKey> [utxo2:...] [nodeHexString1] [nodeHexString2 ...]",
            );
            console.log(
              "  If no node hex strings are provided, all wallet leaves will be used automatically.",
            );
            console.log(
              "  privateKey can be in hex format (64 chars) or WIF format (starting with L, K, 5, c, or 9)",
            );
            console.log(
              "Example: generatefeebumppackagetobroadcast 10 abc123:0:10000:76a914...:9303c68c414a... def456:1:20000:76a914...:L23csh2NVzWyCZFK... nodeHex1 nodeHex2",
            );
            console.log(
              "Example (auto-fetch leaves): generatefeebumppackagetobroadcast 10 abc123:0:10000:76a914...:9303c68c414a...",
            );
            break;
          }

          try {
            const feeRate = parseFloat(args[0]);
            if (isNaN(feeRate) || feeRate <= 0) {
              console.log(
                "Invalid fee rate. Must be a positive number (sat/vbyte)",
              );
              break;
            }

            // Parse UTXOs and node hex strings
            const utxos = [];
            const nodeHexStrings = [];
            let parsingUtxos = true;
            let validationFailed = false;

            for (let i = 1; i < args.length; i++) {
              const arg = args[i];

              // Check if this looks like a UTXO (contains colons) or a node hex string
              if (parsingUtxos && arg.includes(":")) {
                const parts = arg.split(":");
                if (parts.length === 5) {
                  const [txid, vout, value, script, publicKey] = parts;
                  const voutNum = parseInt(vout);
                  let valueNum: bigint;

                  try {
                    valueNum = BigInt(value);
                  } catch (error) {
                    console.log(
                      `Invalid UTXO value: ${value}. Must be a valid integer.`,
                    );
                    validationFailed = true;
                    break;
                  }

                  if (isNaN(voutNum)) {
                    console.log(
                      `Invalid UTXO format: ${arg}. Expected format: txid:vout:value:script:privateKey`,
                    );
                    validationFailed = true;
                    break;
                  }

                  utxos.push({
                    txid,
                    vout: voutNum,
                    value: valueNum,
                    script,
                    publicKey,
                  });
                } else {
                  console.log(
                    `Invalid UTXO format: ${arg}. Expected format: txid:vout:value:script:publicKey`,
                  );
                  validationFailed = true;
                  break;
                }
              } else {
                // This must be a node hex string
                parsingUtxos = false;
                nodeHexStrings.push(arg);
              }
            }

            // Exit early if validation failed
            if (validationFailed) {
              break;
            }

            if (utxos.length === 0) {
              console.log("At least one UTXO is required for fee bumping");
              break;
            }

            if (nodeHexStrings.length === 0) {
              // No node hex strings provided - fetch all user leaves and convert to hex
              console.log(
                "No node hex strings provided. Fetching all wallet leaves...",
              );

              const leaves = await wallet.getLeaves();
              if (leaves.length === 0) {
                console.log("No leaves found in wallet. Nothing to exit.");
                break;
              }

              console.log(
                `Found ${leaves.length} leaves. Converting to hex strings...`,
              );

              for (const leaf of leaves) {
                try {
                  // Encode the TreeNode to bytes and then to hex
                  const encodedBytes = TreeNode.encode(leaf).finish();
                  const hexString = bytesToHex(encodedBytes);
                  nodeHexStrings.push(hexString);
                  console.log(`✅ Leaf ID: ${leaf.id} (${leaf.value} sats)`);
                } catch (error) {
                  console.log(`❌ Error converting leaf ${leaf.id}: ${error}`);
                }
              }

              if (nodeHexStrings.length === 0) {
                console.log("Failed to convert any leaves to hex strings.");
                break;
              }

              console.log(
                `Successfully converted ${nodeHexStrings.length} leaves to hex strings.`,
              );
              console.log("");
            }

            console.log(
              `Using ${utxos.length} UTXOs and ${nodeHexStrings.length} nodes`,
            );
            console.log(`Fee rate: ${feeRate} sat/vbyte`);

            // Get sparkClient from wallet's connection manager
            const sparkClient = await (
              wallet as any
            ).connectionManager.createSparkClient(
              (wallet as any).config.getCoordinatorAddress(),
            );

            // Get network from wallet config
            const network = (wallet as any).config.getNetwork();

            // Get electrs URL from wallet config
            const electrsUrl = (wallet as any).config.getElectrsUrl();

            const feeBumpChains = await constructUnilateralExitFeeBumpPackages(
              nodeHexStrings,
              utxos,
              { satPerVbyte: feeRate },
              electrsUrl,
              sparkClient,
              network,
            );

            console.log(
              "\nUnilateral Exit Fee Bump Packages (SIGNED & READY TO BROADCAST):",
            );
            for (const chain of feeBumpChains) {
              console.log(`\nLeaf ID: ${chain.leafId}`);
              console.log("Transaction Packages:");
              for (let i = 0; i < chain.txPackages.length; i++) {
                const pkg = chain.txPackages[i];
                let label: string;
                if (
                  i === chain.txPackages.length - 1 &&
                  chain.txPackages.length > 1
                ) {
                  label = "leaf refund tx";
                } else {
                  label = `${i + 1}. node tx`;
                }
                console.log(`  ${label}:`);
                console.log(`    Original tx: ${pkg.tx}`);
                if (pkg.feeBumpPsbt) {
                  console.log(
                    `    Fee bump psbt (UNSIGNED): ${pkg.feeBumpPsbt}`,
                  );
                } else {
                  console.log(`    No fee bump needed`);
                }
              }
            }
          } catch (error) {
            console.error(
              "Error getting unilateral exit fee bump packages:",
              error,
            );
          }
          break;
        }
        case "checktimelock": {
          if (!wallet) {
            console.log("Please initialize a wallet first");
            break;
          }
          if (args.length === 0) {
            console.log("Usage: checktimelock <leafId>");
            break;
          }

          try {
            console.log(`Checking timelock for node: ${args[0]}`);
            const { nodeTimelock, refundTimelock } = await wallet.checkTimelock(
              args[0],
            );
            console.log(`Node timelock: ${nodeTimelock} blocks`);
            console.log(`Refund timelock: ${refundTimelock} blocks`);
          } catch (error) {
            console.error("Error checking timelock:", error);
          }
          break;
        }
        case "testonly_expiretimelock": {
          if (!wallet) {
            console.log("Please initialize a wallet first");
            break;
          }
          if (args.length === 0) {
            console.log("Usage: refreshtimelock <leafId>");
            break;
          }

          let refreshCount = 0;
          let continueRefreshing = true;

          console.log(`Starting timelock refresh loop for node: ${args[0]}`);

          while (continueRefreshing) {
            try {
              await wallet.testOnly_expireTimelock(args[0]);
              refreshCount++;
              console.log(
                `Successfully refreshed timelock for node: ${args[0]} (refresh #${refreshCount})`,
              );

              // Add a small delay between refreshes to avoid overwhelming the system
              await new Promise((resolve) => setTimeout(resolve, 100));
            } catch (error) {
              console.log(
                `Timelock refresh completed after ${refreshCount} refresh(es). Node timelock has expired.`,
              );
              console.log("Final error:", error);
              continueRefreshing = false;
            }
          }
          break;
        }
        case "testonly_expiretimelockrefundtx": {
          if (!wallet) {
            console.log("Please initialize a wallet first");
            break;
          }
          if (args.length === 0) {
            console.log("Usage: refreshtimelockrefundtx <leafId>");
            break;
          }

          let refreshCount = 0;
          let continueRefreshing = true;

          console.log(
            `Starting refund timelock refresh loop for node: ${args[0]}`,
          );

          while (continueRefreshing) {
            try {
              await wallet.testOnly_expireTimelockRefundTx(args[0]);
              refreshCount++;
              console.log(
                `Successfully refreshed refund timelock for node: ${args[0]} (refresh #${refreshCount})`,
              );

              // Add a small delay between refreshes to avoid overwhelming the system
              await new Promise((resolve) => setTimeout(resolve, 100));
            } catch (error) {
              console.log(
                `Refund timelock refresh completed after ${refreshCount} refresh(es). Node refund timelock has expired.`,
              );
              console.log("Final error:", error);
              continueRefreshing = false;
            }
          }
          break;
        }
        case "leafidtohex": {
          if (!wallet) {
            console.log("Please initialize a wallet first");
            break;
          }
          if (args.length === 0) {
            console.log("Usage: leafidtohex <leafId1> [leafId2] [leafId3] ...");
            break;
          }

          try {
            // Get sparkClient from wallet's connection manager
            const sparkClient = await (
              wallet as any
            ).connectionManager.createSparkClient(
              (wallet as any).config.getCoordinatorAddress(),
            );

            const nodeIds = args;
            const hexStrings = [];

            console.log(
              `Converting ${nodeIds.length} node ID(s) to hex strings:`,
            );
            console.log("");

            for (const nodeId of nodeIds) {
              try {
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
                  console.log(`❌ Node with ID ${nodeId} not found`);
                  continue;
                }

                // Encode the TreeNode to bytes and then to hex
                const encodedBytes = TreeNode.encode(node).finish();
                const hexString = bytesToHex(encodedBytes);
                hexStrings.push(hexString);

                console.log(`✅ Leaf ID: ${nodeId}`);
                console.log(`   Hex string: ${hexString}`);
                console.log("");
              } catch (error) {
                console.log(`❌ Error converting leaf ID ${nodeId}: ${error}`);
                console.log("");
              }
            }

            if (hexStrings.length > 0) {
              console.log("=".repeat(60));
              console.log("Ready-to-use commands:");
              console.log("");

              console.log(
                "For fee bump unilateral exit (replace <feeRate> and <utxos>):",
              );
              console.log(
                `generatefeebumppackagetobroadcast <feeRate> <utxos> ${hexStrings.join(" ")}`,
              );
              console.log("");

              console.log("💡 TIP: You can also use the simplified commands:");
              console.log(
                "  generatefeebumppackagetobroadcast <feeRate> <utxos>  # Auto-fetches all your leaves",
              );
              console.log("");

              console.log("Example with test UTXOs:");
              console.log(
                "1. First generate a test wallet: testonly_generateexternalwallet",
              );
              console.log("2. Faucet funds to this address");
              console.log(
                "3. Use testonly_generateutxostring to get a string representation of the utxo to use in the next step",
              );
              console.log(
                `4. Then use: generatefeebumppackagetobroadcast 10 <generated_utxos> ${hexStrings.join(" ")}`,
              );
            } else {
              console.log("No valid hex strings generated.");
            }
          } catch (error) {
            console.error("Error converting node IDs to hex:", error);
          }
          break;
        }
        case "getleaves": {
          if (!wallet) {
            console.log("Please initialize a wallet first");
            break;
          }
          try {
            const leaves = await wallet.getLeaves();
            if (leaves.length === 0) {
              console.log("No leaves found");
            } else {
              console.log(`Found ${leaves.length} leaves:`);
              console.log("");
              for (const leaf of leaves) {
                console.log(`Leaf ID: ${leaf.id}`);
                console.log(`  Tree ID: ${leaf.treeId}`);
                console.log(`  Value: ${leaf.value} sats`);
                console.log(`  Status: ${leaf.status}`);
                console.log(`  Network: ${leaf.network}`);
                if (leaf.parentNodeId) {
                  console.log(`  Parent Leaf ID: ${leaf.parentNodeId}`);
                }
                console.log(`  Vout: ${leaf.vout}`);
                console.log(
                  `  Verifying Public Key: ${bytesToHex(leaf.verifyingPublicKey)}`,
                );
                console.log(
                  `  Owner Identity Public Key: ${bytesToHex(leaf.ownerIdentityPublicKey)}`,
                );
                console.log(`  Node Tx: ${bytesToHex(leaf.nodeTx)}`);
                console.log(`  Refund Tx: ${bytesToHex(leaf.refundTx)}`);
                console.log("  ---");
              }
              const totalValue = leaves.reduce(
                (sum: number, leaf: any) => sum + leaf.value,
                0,
              );
              console.log(`Total value: ${totalValue} sats`);
            }
          } catch (error) {
            console.error("Error getting leaves:", error);
          }
          break;
        }
        case "testonly_generateexternalwallet": {
          if (network !== "REGTEST") {
            console.log("❌ This command only works on regtest network");
            console.log("Set NETWORK=regtest environment variable");
            break;
          }

          // Generate a random private key for our test UTXOs
          const privateKeyBytes = secp256k1.utils.randomPrivateKey();
          const privateKeyHex = bytesToHex(privateKeyBytes);
          const privateKeyWif = hexToWif(privateKeyHex);

          // Get the public key and address
          const publicKey = secp256k1.getPublicKey(privateKeyBytes, true);
          const pubKeyHash = hash160(publicKey);
          const p2wpkhScript = new Uint8Array([0x00, 0x14, ...pubKeyHash]);

          // Create a regtest P2WPKH address
          const regtestAddress = getP2WPKHAddressFromPublicKey(
            publicKey,
            Network.REGTEST,
          );

          console.log(`Generated test wallet:`);
          console.log(`  Private Key (WIF): ${privateKeyWif}`);
          console.log(`  Private Key (Hex): ${privateKeyHex}`);
          console.log(`  Public Key: ${bytesToHex(publicKey)}`);
          console.log(`  Address: ${regtestAddress}`);
          console.log("");

          break;
        }
        case "testonly_generateutxostring": {
          if (args.length < 4 || args.length > 5) {
            console.log(
              "Usage: testonly_generateutxostring <txid> <vout> <valueSats> <publicKey>",
            );
            console.log(
              "  privateKey can be in hex format (64 chars) or WIF format (starting with L, K, 5, c, or 9)",
            );
            console.log("  Output format: txid:vout:value:scriptHex:publicKey");
            break;
          }

          const [txid, voutStr, valueStr, publicKey] = args;

          const vout = parseInt(voutStr);
          if (isNaN(vout) || vout < 0) {
            console.log("Invalid vout. Must be a non-negative integer.");
            break;
          }

          let value: bigint;
          try {
            value = BigInt(valueStr);
            if (value <= 0) {
              console.log("Invalid value. Must be a positive integer.");
              break;
            }
          } catch (error) {
            console.log("Invalid value. Must be a valid integer.");
            break;
          }

          try {
            const pubKeyHash = hash160(hexToBytes(publicKey));

            // P2WPKH: OP_0 <20-byte hash>
            const scriptBytes = new Uint8Array([0x00, 0x14, ...pubKeyHash]);

            const scriptHex = bytesToHex(scriptBytes);

            const utxoString = `${txid}:${vout}:${value.toString()}:${scriptHex}:${publicKey}`;
            console.log(`Generated UTXO String:`);
            console.log(utxoString);
          } catch (error: any) {
            console.error("Error generating UTXO string:", error.message);
          }
          break;
        }
      }
    } catch (error) {
      console.error("Error:", error);
    }
  }
}

runCLI();
