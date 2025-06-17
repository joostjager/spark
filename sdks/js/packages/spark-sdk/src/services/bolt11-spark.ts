import { bech32 } from "@scure/base";
import { sha256 } from "@noble/hashes/sha2";
import { secp256k1 } from "@noble/curves/secp256k1";
import { Network } from "../utils/network.js";
import { ValidationError } from "../errors/index.js";

interface DecodedInvoice {
  amountMSats: bigint | null;
  fallbackAddress: string | undefined;
  paymentHash: string;
}

export function decodeInvoice(invoice: string): DecodedInvoice {
  const { words, prefix } = bech32.decode(
    invoice as `${string}1${string}`,
    1_000,
  );
  verifySignature(words, prefix);

  const amountMSats = extractMillisatoshiAmountFromInvoice(invoice);

  let fallbackAddress: string | undefined = undefined;
  let paymentHash: string | undefined = undefined;
  let paymentSecret: string | undefined = undefined;

  // TLV data lives between the timestamp and the signature+recovery words
  let i = 7;
  const tlvEnd = words.length - 105;
  while (i + 2 < tlvEnd) {
    const tag = words[i];
    const len1 = words[i + 1];
    const len2 = words[i + 2];
    if (len1 === undefined || len2 === undefined) {
      console.log("No length word");
      break;
    }
    const len = (len1 << 5) + len2;
    const start = i + 3;
    const end = start + len;

    if (tag === 1) {
      // payment hash (tag 'p (1)')
      const hashWords = words.slice(start, end);
      const hashBytes = bech32WordsToBytes(hashWords);
      if (hashBytes.length === 32) {
        paymentHash = Buffer.from(hashBytes).toString("hex");
      }
    } else if (tag === 9) {
      // fallback address (tag 'f (9)')
      const verWord = words[start]; // 1st word = version (5-bit)
      if (verWord !== 31) {
        console.warn("Not our custom version-31");
        i = end;
        continue;
      }

      const payloadWords = words.slice(start + 1, end);
      const payloadBytes = bech32WordsToBytes(payloadWords);

      fallbackAddress = Buffer.from(payloadBytes).toString("hex");
    } else if (tag === 16) {
      // Payment secret (tag 's (16)') - should be 32 bytes (52 words)
      if (len !== 52) {
        throw new ValidationError("Invalid payment secret length", {
          field: "paymentSecret",
          value: len,
          expected: "52 words (32 bytes for 256-bit secret)",
        });
      }

      const secretWords = words.slice(start, end);
      const secretBytes = bech32WordsToBytes(secretWords);

      if (secretBytes.length !== 32) {
        throw new ValidationError("Invalid payment secret size", {
          field: "paymentSecret",
          value: secretBytes.length,
          expected: "32 bytes (256 bits)",
        });
      }

      paymentSecret = Buffer.from(secretBytes).toString("hex");
    }
    i = end; // next TLV
  }
  if (paymentHash === undefined) {
    throw new ValidationError("No payment hash found in invoice: " + invoice);
  }
  if (paymentSecret === undefined) {
    throw new ValidationError(
      "Invalid payment secret found in invoice: " + invoice,
    );
  }
  return { amountMSats, fallbackAddress, paymentHash };
}

function bech32WordsToBytes(words: number[]): Uint8Array {
  let acc = 0,
    bits = 0;
  const out: number[] = [];
  for (const w of words) {
    if (w < 0 || w > 31) throw new Error(`bad word ${w}`);
    acc = (acc << 5) | w;
    bits += 5;
    while (bits >= 8) {
      bits -= 8;
      out.push((acc >> bits) & 0xff);
    }
  }
  return new Uint8Array(out);
}

export function getNetworkFromInvoice(invoice: string): Network | null {
  // order matters here
  if (invoice.startsWith("lnbcrt")) return Network.REGTEST;
  if (invoice.startsWith("lnbc")) return Network.MAINNET;
  if (invoice.startsWith("lntb")) return Network.TESTNET;
  if (invoice.startsWith("lnsb")) return Network.SIGNET;

  return null;
}

function extractMillisatoshiAmountFromInvoice(invoice: string): bigint | null {
  const match = invoice.match(/^ln[a-z]+(\d+)([a-z]?)1/);
  if (!match) return null;

  const [, amount, multiplier] = match;
  if (!amount) return null;

  const value = BigInt(amount);
  const MILLISATS_PER_BTC = 100_000_000_000n;

  const divisors = {
    m: 1_000n,
    u: 1_000_000n,
    n: 1_000_000_000n,
    p: 10_000_000_000_000n,
  };

  if (multiplier) {
    // Validate multiplier is valid
    if (!(multiplier in divisors)) {
      throw new ValidationError(`Invalid multiplier: ${multiplier}`, {
        field: "multiplier",
        value: multiplier,
        expected: "valid bolt11 multiplier: m, u, n, p",
      });
    }

    const divisor = divisors[multiplier as keyof typeof divisors];

    // Check if division results in fractional millisatoshis
    if ((value * MILLISATS_PER_BTC) % divisor !== 0n) {
      throw new ValidationError("Invalid submillisatoshi precision", {
        field: "amount",
        value: `${amount}${multiplier}`,
        expected: "amount must result in whole millisatoshis",
      });
    }

    return (value * MILLISATS_PER_BTC) / divisor;
  } else {
    return value * MILLISATS_PER_BTC;
  }
}

export function hasSparkHeader(bytes: Uint8Array): boolean {
  if (bytes.length < 3) {
    return false;
  }

  return (
    bytes[0] === 0x53 && // 'S'
    bytes[1] === 0x50 && // 'P'
    bytes[2] === 0x4b // 'K'
  );
}

export function isValidSparkFallback(bytes: Uint8Array): boolean {
  // should be 36 bytes (3-byte SPK header + 33-byte identity public key)
  if (bytes.length !== 36) {
    return false;
  }
  return hasSparkHeader(bytes);
}

function verifySignature(words: number[], prefix: string) {
  if (words.length < 104) {
    throw new ValidationError("Invoice too short for signature");
  }

  const signatureStart = words.length - 104;
  const signatureEnd = words.length - 1;

  const hrp = prefix;
  const hrpBytes = new TextEncoder().encode(hrp);

  const dataWords = words.slice(0, signatureStart);
  const dataBytes = bech32WordsToBytes(dataWords);

  const sigWords = words.slice(signatureStart, signatureEnd);
  const sigBytes = bech32WordsToBytes(sigWords);
  if (sigBytes.length !== 64) {
    throw new ValidationError("Invalid signature length");
  }

  const recoveryId = words[words.length - 1];
  if (recoveryId === undefined) {
    throw new ValidationError("Missing recovery ID in signature");
  }

  const messageBytes = new Uint8Array(hrpBytes.length + dataBytes.length);
  messageBytes.set(hrpBytes, 0);
  messageBytes.set(dataBytes, hrpBytes.length);

  const messageHash = sha256(messageBytes);

  try {
    const signature =
      secp256k1.Signature.fromCompact(sigBytes).addRecoveryBit(recoveryId);

    signature.recoverPublicKey(messageHash);
  } catch (error) {
    throw new ValidationError(
      `Invalid BOLT11 signature: ${(error as Error).message}`,
    );
  }
}
