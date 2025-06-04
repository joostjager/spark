
// Copyright ©, 2023-present, Lightspark Group, Inc. - All Rights Reserved


export enum ClaimStaticDepositStatus { 
/**
 * This is an enum value that represents values that could be added in the future.
 * Clients should support unknown values as more of them could be added without notice.
 */
 FUTURE_VALUE = "FUTURE_VALUE",

CREATED = "CREATED",

TRANSFER_CREATED = "TRANSFER_CREATED",

TRANSFER_CREATION_FAILED = "TRANSFER_CREATION_FAILED",

REFUND_SIGNING_COMMITMENTS_QUERYING_FAILED = "REFUND_SIGNING_COMMITMENTS_QUERYING_FAILED",

REFUND_SIGNING_FAILED = "REFUND_SIGNING_FAILED",

UTXO_SWAPPING_FAILED = "UTXO_SWAPPING_FAILED",

TRANSFER_FAILED = "TRANSFER_FAILED",

TRANSFER_COMPLETED = "TRANSFER_COMPLETED",

}

export default ClaimStaticDepositStatus;
