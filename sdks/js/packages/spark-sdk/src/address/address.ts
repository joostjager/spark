import { secp256k1 } from "@noble/curves/secp256k1";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils";
import { bech32m } from "@scure/base";
import { PaymentIntentFields, SparkAddress } from "../proto/spark.js";
import { NetworkType } from "../utils/network.js";
import { ValidationError } from "../errors/index.js";

import { UUID, uuidv7 } from "uuidv7";
import { bytesToNumberBE } from "@noble/curves/abstract/utils";

const AddressNetwork: Record<NetworkType, string> = {
  MAINNET: "sp",
  TESTNET: "spt",
  REGTEST: "sprt",
  SIGNET: "sps",
  LOCAL: "spl",
} as const;

export type SparkAddressFormat =
  `${(typeof AddressNetwork)[keyof typeof AddressNetwork]}1${string}`;

export interface SparkAddressData {
  identityPublicKey: string;
  network: NetworkType;
  paymentIntentFields?: PaymentIntentFields;
}

export interface DecodedSparkAddressData {
  identityPublicKey: string;
  network: NetworkType;
  paymentIntentFields?: {
    id: string;
    assetIdentifier?: string;
    assetAmount: bigint;
    memo?: string;
  };
}

export function encodeSparkAddress(
  payload: SparkAddressData,
): SparkAddressFormat {
  try {
    isValidPublicKey(payload.identityPublicKey);

    let paymentIntentFields: PaymentIntentFields | undefined;
    if (payload.paymentIntentFields) {
      paymentIntentFields = payload.paymentIntentFields;
    }

    const sparkAddressProto = SparkAddress.create({
      identityPublicKey: hexToBytes(payload.identityPublicKey),
      paymentIntentFields,
    });

    const serializedPayload = SparkAddress.encode(sparkAddressProto).finish();
    const words = bech32m.toWords(serializedPayload);

    return bech32m.encode(
      AddressNetwork[payload.network],
      words,
      500,
    ) as SparkAddressFormat;
  } catch (error) {
    throw new ValidationError(
      "Failed to encode Spark address",
      {
        field: "publicKey",
        value: payload.identityPublicKey,
      },
      error as Error,
    );
  }
}

export function decodeSparkAddress(
  address: string,
  network: NetworkType,
): DecodedSparkAddressData {
  try {
    const decoded = bech32m.decode(address as SparkAddressFormat, 500);

    if (decoded.prefix !== AddressNetwork[network]) {
      throw new ValidationError("Invalid Spark address prefix", {
        field: "address",
        value: address,
        expected: `prefix='${AddressNetwork[network]}'`,
      });
    }

    const payload = SparkAddress.decode(bech32m.fromWords(decoded.words));

    const publicKey = bytesToHex(payload.identityPublicKey);

    isValidPublicKey(publicKey);

    const paymentIntentFields = payload.paymentIntentFields;

    return {
      identityPublicKey: publicKey,
      network,
      paymentIntentFields: paymentIntentFields && {
        id: UUID.ofInner(paymentIntentFields.id).toString(),
        assetIdentifier: paymentIntentFields.assetIdentifier
          ? bytesToHex(paymentIntentFields.assetIdentifier)
          : undefined,
        assetAmount: bytesToNumberBE(paymentIntentFields.assetAmount),
        memo: paymentIntentFields.memo,
      },
    };
  } catch (error) {
    if (error instanceof ValidationError) {
      throw error;
    }
    throw new ValidationError(
      "Failed to decode Spark address",
      {
        field: "address",
        value: address,
      },
      error as Error,
    );
  }
}

export function isValidSparkAddress(address: string) {
  try {
    const network = Object.entries(AddressNetwork).find(([_, prefix]) =>
      address.startsWith(prefix),
    )?.[0] as NetworkType | undefined;

    if (!network) {
      throw new ValidationError("Invalid Spark address network", {
        field: "network",
        value: address,
        expected: Object.values(AddressNetwork),
      });
    }

    decodeSparkAddress(address, network);
    return true;
  } catch (error) {
    if (error instanceof ValidationError) {
      throw error;
    }
    throw new ValidationError(
      "Invalid Spark address",
      {
        field: "address",
        value: address,
      },
      error as Error,
    );
  }
}

export function isValidPublicKey(publicKey: string) {
  try {
    const point = secp256k1.ProjectivePoint.fromHex(publicKey);
    point.assertValidity();
  } catch (error) {
    throw new ValidationError(
      "Invalid public key",
      {
        field: "publicKey",
        value: publicKey,
      },
      error as Error,
    );
  }
}
