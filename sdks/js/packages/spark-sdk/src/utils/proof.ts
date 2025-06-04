import { sha256 } from "@noble/hashes/sha2";

export function proofOfPossessionMessageHashForDepositAddress(
  userPubkey: Uint8Array,
  operatorPubkey: Uint8Array,
  depositAddress: string,
): Uint8Array {
  const encoder = new TextEncoder();
  const depositAddressBytes = encoder.encode(depositAddress);

  const proofMsg = new Uint8Array([
    ...userPubkey,
    ...operatorPubkey,
    ...depositAddressBytes,
  ]);
  return sha256(proofMsg);
}
