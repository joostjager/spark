package handler

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"sort"
	"strings"
	"time"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"github.com/google/uuid"
	"github.com/lightsparkdev/spark/common"
	"github.com/lightsparkdev/spark/common/logging"
	pb "github.com/lightsparkdev/spark/proto/spark"
	pbinternal "github.com/lightsparkdev/spark/proto/spark_internal"
	"github.com/lightsparkdev/spark/so"
	"github.com/lightsparkdev/spark/so/ent"
	st "github.com/lightsparkdev/spark/so/ent/schema/schematype"
	"github.com/lightsparkdev/spark/so/ent/tokentransaction"
	"github.com/lightsparkdev/spark/so/helper"
	"github.com/lightsparkdev/spark/so/lrc20"
	"github.com/lightsparkdev/spark/so/protoconverter"
	"github.com/lightsparkdev/spark/so/utils"
	"google.golang.org/protobuf/types/known/emptypb"
)

// InternalTokenTransactionHandler is the deposit handler for so internal
type InternalTokenTransactionHandler struct {
	config      *so.Config
	lrc20Client *lrc20.Client
}

// NewInternalTokenTransactionHandler creates a new InternalTokenTransactionHandler.
func NewInternalTokenTransactionHandler(config *so.Config, client *lrc20.Client) *InternalTokenTransactionHandler {
	return &InternalTokenTransactionHandler{config: config, lrc20Client: client}
}

func (h *InternalTokenTransactionHandler) StartTokenTransactionInternal(ctx context.Context, config *so.Config, req *pbinternal.StartTokenTransactionInternalRequest) (*emptypb.Empty, error) {
	logger := logging.GetLoggerFromContext(ctx)
	partialTransactionHash, err := utils.HashTokenTransactionV0(req.FinalTokenTransaction, true)
	if err != nil {
		return nil, formatErrorWithTransactionProtoInternal("failed to compute transaction hash", req.FinalTokenTransaction, err)
	}
	// Compute expiry time at the start to ensure later delays in this function (eg. due to DB locks)
	// do not impact the expiry value.
	// If the token transaction expiry duration is not set in the config, use the default value
	network, err := common.NetworkFromProtoNetwork(req.FinalTokenTransaction.Network)
	if err != nil {
		return nil, fmt.Errorf("failed to get network from proto network: %w", err)
	}
	expiryDuration := config.Lrc20Configs[network.String()].TransactionExpiryDuration
	transactionExpiryTime := time.Now().Add(expiryDuration)
	logger.Info("Starting token transaction", "partial_transaction_hash", hex.EncodeToString(partialTransactionHash), "keyshare_ids", req.KeyshareIds, "expiry_time", transactionExpiryTime.String(), "final_token_transaction", logging.FormatProto("final_token_transaction", req.FinalTokenTransaction))

	keyshareUUIDs := make([]uuid.UUID, len(req.KeyshareIds))
	// Ensure that the coordinator SO did not pass duplicate keyshare UUIDs for different outputs.
	seenUUIDs := make(map[uuid.UUID]bool)
	for i, id := range req.KeyshareIds {
		uuid, err := uuid.Parse(id)
		if err != nil {
			return nil, formatErrorWithTransactionProtoInternal("failed to parse keyshare ID", req.FinalTokenTransaction, err)
		}
		if seenUUIDs[uuid] {
			return nil, formatErrorWithTransactionProtoInternal("duplicate keyshare UUID found", req.FinalTokenTransaction, fmt.Errorf("duplicate keyshare UUID found: %s", uuid))
		}
		seenUUIDs[uuid] = true
		keyshareUUIDs[i] = uuid
	}
	logger.Info("Marking keyshares as used")
	keysharesMap, err := ent.MarkSigningKeysharesAsUsed(ctx, config, keyshareUUIDs)
	if err != nil {
		return nil, formatErrorWithTransactionProtoInternal("failed to mark keyshares as used", req.FinalTokenTransaction, err)
	}
	logger.Info("Keyshares marked as used")
	expectedRevocationPublicKeys := make([][]byte, len(req.KeyshareIds))
	for i, id := range keyshareUUIDs {
		keyshare, ok := keysharesMap[id]
		if !ok {
			return nil, formatErrorWithTransactionProtoInternal("keyshare ID not found", req.FinalTokenTransaction, fmt.Errorf("keyshare ID not found: %s", id))
		}
		expectedRevocationPublicKeys[i] = keyshare.PublicKey
	}

	logger.Info("Validating final token transaction")
	// Validate the final token transaction.
	err = validateFinalTokenTransaction(config, req.FinalTokenTransaction, req.TokenTransactionSignatures, expectedRevocationPublicKeys)
	if err != nil {
		return nil, fmt.Errorf("invalid final token transaction %s: %w", logging.FormatProto("final_token_transaction", req.FinalTokenTransaction), err)
	}
	if req.FinalTokenTransaction.GetMintInput() != nil {
		if req.FinalTokenTransaction.GetMintInput().GetIssuerProvidedTimestamp() == 0 {
			return nil, formatErrorWithTransactionProtoInternal("issuer provided timestamp must be set for mint transaction", req.FinalTokenTransaction, errors.New("issuer provided timestamp must be set for mint transaction"))
		}
		err = ValidateMintSignature(req.FinalTokenTransaction, req.TokenTransactionSignatures)
		if err != nil {
			return nil, fmt.Errorf("invalid token transaction %s: %w", logging.FormatProto("final_token_transaction", req.FinalTokenTransaction), err)
		}
	}
	var outputToSpendEnts []*ent.TokenOutput
	if req.FinalTokenTransaction.GetTransferInput() != nil {
		// Get the leaves to spend from the database.
		outputToSpendEnts, err = ent.FetchAndLockTokenInputs(ctx, req.FinalTokenTransaction.GetTransferInput().GetOutputsToSpend())
		if err != nil {
			return nil, formatErrorWithTransactionProtoInternal("failed to fetch outputs to spend", req.FinalTokenTransaction, err)
		}
		if len(outputToSpendEnts) != len(req.FinalTokenTransaction.GetTransferInput().GetOutputsToSpend()) {
			return nil, formatErrorWithTransactionProtoInternal("failed to fetch all leaves to spend", req.FinalTokenTransaction, fmt.Errorf("failed to fetch all leaves to spend: got %d leaves, expected %d", len(outputToSpendEnts), len(req.FinalTokenTransaction.GetTransferInput().GetOutputsToSpend())))
		}

		err = ValidateTokenTransactionUsingPreviousTransactionData(req.FinalTokenTransaction, req.TokenTransactionSignatures, outputToSpendEnts)
		if err != nil {
			return nil, fmt.Errorf("error validating transfer using previous output data %s: %w", logging.FormatProto("final_token_transaction", req.FinalTokenTransaction), err)
		}
	}
	logger.Info("Final token transaction validated")

	logger.Info("Verifying token transaction with LRC20 node")
	err = h.lrc20Client.VerifySparkTx(ctx, req.FinalTokenTransaction)
	if err != nil {
		return nil, formatErrorWithTransactionProtoInternal("failed to verify token transaction with LRC20 node", req.FinalTokenTransaction, err)
	}
	logger.Info("Token transaction verified with LRC20 node")

	// Save the token transaction, created output ents, and update the outputs to spend.
	_, err = ent.CreateStartedTransactionEntities(ctx, req.FinalTokenTransaction, req.TokenTransactionSignatures, req.KeyshareIds, outputToSpendEnts, req.CoordinatorPublicKey, transactionExpiryTime)
	if err != nil {
		return nil, fmt.Errorf("failed to save token transaction and output ents %s: %w", logging.FormatProto("final_token_transaction", req.FinalTokenTransaction), err)
	}

	return &emptypb.Empty{}, nil
}

// SignAndPersistTokenTransaction performs the core logic for signing a token transaction from coordination.
// It validates the transaction, input signatures, signs the hash, updates the DB, and returns the signature bytes.
func (h InternalTokenTransactionHandler) SignAndPersistTokenTransaction(
	ctx context.Context,
	config *so.Config,
	tokenTransaction *ent.TokenTransaction,
	finalTokenTransactionHash []byte,
	operatorSpecificSignatures []*pb.OperatorSpecificOwnerSignature,
) ([]byte, error) {
	logger := logging.GetLoggerFromContext(ctx)

	if err := validateTokenTransactionForSigning(tokenTransaction); err != nil {
		return nil, formatErrorWithTransactionEnt(err.Error(), tokenTransaction, err)
	}

	if err := validateOperatorSpecificSignatures(config.IdentityPublicKey(), operatorSpecificSignatures, tokenTransaction); err != nil {
		return nil, err
	}

	if tokenTransaction.Status == st.TokenTransactionStatusSigned {
		signature, err := h.regenerateOperatorSignatureForDuplicateRequest(ctx, config, tokenTransaction, finalTokenTransactionHash)
		if err != nil {
			return nil, err
		}
		return signature, nil
	}

	invalidOutputs := validateOutputs(tokenTransaction.Edges.CreatedOutput, st.TokenOutputStatusCreatedStarted)
	if len(invalidOutputs) > 0 {
		return nil, formatErrorWithTransactionEnt(fmt.Sprintf("%s: %s", errInvalidOutputs, strings.Join(invalidOutputs, "; ")), tokenTransaction, nil)
	}

	// If token outputs are being spent, verify the expected status of inputs and check for active freezes.
	// For mints this is not necessary and will be skipped because it does not spend outputs.
	if len(tokenTransaction.Edges.SpentOutput) > 0 {
		invalidOutputs := validateInputs(tokenTransaction.Edges.SpentOutput, st.TokenOutputStatusSpentStarted)
		if len(invalidOutputs) > 0 {
			return nil, formatErrorWithTransactionEnt(fmt.Sprintf("%s: %s", errInvalidInputs, strings.Join(invalidOutputs, "; ")), tokenTransaction, nil)
		}

		// Collect owner public keys for freeze check.
		ownerPublicKeys := make([][]byte, len(tokenTransaction.Edges.SpentOutput))
		// Assumes that all token public keys are the same as the first output. This is asserted when validating
		// in the StartTokenTransaction() step.
		tokenPublicKey := tokenTransaction.Edges.SpentOutput[0].TokenPublicKey
		for i, output := range tokenTransaction.Edges.SpentOutput {
			ownerPublicKeys[i] = output.OwnerPublicKey
		}

		// Bulk query all input ids to ensure none of them are frozen.
		activeFreezes, err := ent.GetActiveFreezes(ctx, ownerPublicKeys, tokenPublicKey)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", errFailedToQueryTokenFreezeStatus, err)
		}

		if len(activeFreezes) > 0 {
			for _, freeze := range activeFreezes {
				logger.Info("Found active freeze", "owner", freeze.OwnerPublicKey, "token", freeze.TokenPublicKey, "freeze_timestamp", freeze.WalletProvidedFreezeTimestamp)
			}
			return nil, fmt.Errorf("at least one input is frozen. Cannot proceed with transaction")
		}
	}

	identityPrivateKey := secp256k1.PrivKeyFromBytes(config.IdentityPrivateKey)
	operatorSignature := ecdsa.Sign(identityPrivateKey, finalTokenTransactionHash)

	// Order the signatures according to their index before updating the DB.
	operatorSpecificSignatureMap := make(map[int][]byte, len(operatorSpecificSignatures))
	for _, sig := range operatorSpecificSignatures {
		inputIndex := int(sig.OwnerSignature.InputIndex)
		operatorSpecificSignatureMap[inputIndex] = sig.OwnerSignature.Signature
	}
	operatorSpecificSignaturesArr := make([][]byte, len(operatorSpecificSignatureMap))
	for i := 0; i < len(operatorSpecificSignatureMap); i++ {
		operatorSpecificSignaturesArr[i] = operatorSpecificSignatureMap[i]
	}
	err := ent.UpdateSignedTransaction(ctx, tokenTransaction, operatorSpecificSignaturesArr, operatorSignature.Serialize())
	if err != nil {
		return nil, formatErrorWithTransactionEnt("failed to update outputs after signing", tokenTransaction, err)
	}

	return operatorSignature.Serialize(), nil
}

func validateTokenTransactionForSigning(tokenTransactionEnt *ent.TokenTransaction) error {
	if tokenTransactionEnt.Status != st.TokenTransactionStatusStarted &&
		tokenTransactionEnt.Status != st.TokenTransactionStatusSigned {
		return fmt.Errorf("signing failed because transaction is not in correct state, expected %s or %s, current status: %s", st.TokenTransactionStatusStarted, st.TokenTransactionStatusSigned, tokenTransactionEnt.Status)
	}
	if !tokenTransactionEnt.ExpiryTime.IsZero() && time.Now().After(tokenTransactionEnt.ExpiryTime) {
		return fmt.Errorf("signing failed because token transaction %s has expired at %s", tokenTransactionEnt.ID, tokenTransactionEnt.ExpiryTime.Format(time.RFC3339))
	}
	return nil
}

// validateOperatorSpecificSignatures validates the signatures in the request against the transaction hash
// and verifies that the number of signatures matches the expected count based on transaction type
func validateOperatorSpecificSignatures(identityPublicKey []byte, operatorSpecificSignatures []*pb.OperatorSpecificOwnerSignature, tokenTransaction *ent.TokenTransaction) error {
	if len(tokenTransaction.Edges.SpentOutput) > 0 {
		return validateTransferOperatorSpecificSignatures(identityPublicKey, operatorSpecificSignatures, tokenTransaction)
	}
	return validateMintOperatorSpecificSignatures(identityPublicKey, operatorSpecificSignatures, tokenTransaction)
}

// validateTransferOperatorSpecificSignatures validates signatures for transfer transactions
func validateTransferOperatorSpecificSignatures(identityPublicKey []byte, operatorSpecificSignatures []*pb.OperatorSpecificOwnerSignature, tokenTransaction *ent.TokenTransaction) error {
	if len(operatorSpecificSignatures) != len(tokenTransaction.Edges.SpentOutput) {
		return formatErrorWithTransactionEnt(
			fmt.Sprintf("expected %d signatures for transfer (one per input), but got %d",
				len(tokenTransaction.Edges.SpentOutput), len(operatorSpecificSignatures)),
			tokenTransaction, nil)
	}
	numInputs := len(tokenTransaction.Edges.SpentOutput)
	signaturesByIndex := make([]*pb.OperatorSpecificOwnerSignature, numInputs)

	// Sort signatures according to index position
	for _, sig := range operatorSpecificSignatures {
		index := int(sig.OwnerSignature.InputIndex)
		if index < 0 || index >= numInputs {
			return formatErrorWithTransactionEnt(
				fmt.Sprintf(errInputIndexOutOfRange, index, numInputs-1),
				tokenTransaction, nil)
		}

		if signaturesByIndex[index] != nil {
			return formatErrorWithTransactionEnt(
				fmt.Sprintf("duplicate signature for input index %d", index),
				tokenTransaction, nil)
		}

		signaturesByIndex[index] = sig
	}

	for i := 0; i < numInputs; i++ {
		if signaturesByIndex[i] == nil {
			return formatErrorWithTransactionEnt(
				fmt.Sprintf("missing signature for input index %d", i),
				tokenTransaction, nil)
		}
	}

	// Sort spent outputs by their index
	spentOutputs := make([]*ent.TokenOutput, numInputs)
	copy(spentOutputs, tokenTransaction.Edges.SpentOutput)
	sort.Slice(spentOutputs, func(i, j int) bool {
		return spentOutputs[i].SpentTransactionInputVout < spentOutputs[j].SpentTransactionInputVout
	})

	// Validate each signature against its corresponding output
	for i, sig := range signaturesByIndex {
		payloadHash, err := utils.HashOperatorSpecificTokenTransactionSignablePayload(sig.Payload)
		if err != nil {
			return fmt.Errorf("%s: %w", errFailedToHashRevocationKeyshares, err)
		}

		if !bytes.Equal(sig.Payload.FinalTokenTransactionHash, tokenTransaction.FinalizedTokenTransactionHash) {
			return fmt.Errorf(errTransactionHashMismatch,
				sig.Payload.FinalTokenTransactionHash, tokenTransaction.FinalizedTokenTransactionHash)
		}

		if !bytes.Equal(sig.Payload.OperatorIdentityPublicKey, identityPublicKey) {
			return fmt.Errorf(errOperatorPublicKeyMismatch,
				sig.Payload.OperatorIdentityPublicKey, identityPublicKey)
		}

		output := spentOutputs[i]
		if err := utils.ValidateOwnershipSignature(
			sig.OwnerSignature.Signature,
			payloadHash,
			output.OwnerPublicKey,
		); err != nil {
			return formatErrorWithTransactionEnt(errInvalidOwnerSignature, tokenTransaction, err)
		}
	}

	return nil
}

// validateMintOperatorSpecificSignatures validates signatures for mint transactions
func validateMintOperatorSpecificSignatures(identityPublicKey []byte, operatorSpecificSignatures []*pb.OperatorSpecificOwnerSignature, tokenTransaction *ent.TokenTransaction) error {
	if len(operatorSpecificSignatures) != 1 {
		return formatErrorWithTransactionEnt(
			fmt.Sprintf("expected exactly 1 signature for mint, but got %d",
				len(operatorSpecificSignatures)),
			tokenTransaction, nil)
	}

	if tokenTransaction.Edges.Mint == nil {
		return formatErrorWithTransactionEnt(
			"mint record not found in db, but expected a mint for this transaction",
			tokenTransaction, nil)
	}

	sig := operatorSpecificSignatures[0]

	// Validate the signature payload
	payloadHash, err := utils.HashOperatorSpecificTokenTransactionSignablePayload(sig.Payload)
	if err != nil {
		return fmt.Errorf("%s: %w", errFailedToHashRevocationKeyshares, err)
	}

	if !bytes.Equal(sig.Payload.FinalTokenTransactionHash, tokenTransaction.FinalizedTokenTransactionHash) {
		return fmt.Errorf(errTransactionHashMismatch,
			sig.Payload.FinalTokenTransactionHash, tokenTransaction.FinalizedTokenTransactionHash)
	}

	if len(sig.Payload.OperatorIdentityPublicKey) > 0 {
		if !bytes.Equal(sig.Payload.OperatorIdentityPublicKey, identityPublicKey) {
			return fmt.Errorf(errOperatorPublicKeyMismatch,
				sig.Payload.OperatorIdentityPublicKey, identityPublicKey)
		}
	}

	// Validate the signature using the issuer public key from the database
	if err := utils.ValidateOwnershipSignature(
		sig.OwnerSignature.Signature,
		payloadHash,
		tokenTransaction.Edges.Mint.IssuerPublicKey,
	); err != nil {
		return formatErrorWithTransactionEnt(errInvalidIssuerSignature, tokenTransaction, err)
	}

	return nil
}

// validateOutputs checks if all created outputs have the expected status
func validateOutputs(outputs []*ent.TokenOutput, expectedStatus st.TokenOutputStatus) []string {
	var invalidOutputs []string
	for i, output := range outputs {
		if output.Status != expectedStatus {
			invalidOutputs = append(invalidOutputs, fmt.Sprintf("output %d has invalid status %s, expected %s",
				i, output.Status, expectedStatus))
		}
	}
	return invalidOutputs
}

// validateInputs checks if all spent outputs have the expected status and aren't withdrawn
func validateInputs(outputs []*ent.TokenOutput, expectedStatus st.TokenOutputStatus) []string {
	var invalidOutputs []string
	for _, output := range outputs {
		if output.Status != expectedStatus {
			invalidOutputs = append(invalidOutputs, fmt.Sprintf("input %x has invalid status %s, expected %s",
				output.ID, output.Status, expectedStatus))
		}
		if output.ConfirmedWithdrawBlockHash != nil {
			invalidOutputs = append(invalidOutputs, fmt.Sprintf("input %x is already withdrawn",
				output.ID))
		}
	}
	return invalidOutputs
}

// regenerateOperatorSignatureForDuplicateRequest handles the case where a transaction has already been signed.
// This allows for simpler wallet SDK logic such that if a Sign() call to one of the SOs failed,
// the wallet SDK can retry with all SOs and get successful responses.
func (h InternalTokenTransactionHandler) regenerateOperatorSignatureForDuplicateRequest(
	ctx context.Context,
	config *so.Config,
	tokenTransaction *ent.TokenTransaction,
	finalTokenTransactionHash []byte,
) ([]byte, error) {
	logWithTransactionEnt(ctx, "Regenerating response for a duplicate SignTokenTransaction() Call", tokenTransaction, slog.LevelDebug)

	var invalidOutputs []string
	isMint := tokenTransaction.Edges.Mint != nil
	expectedCreatedOutputStatus := st.TokenOutputStatusCreatedSigned
	if isMint {
		expectedCreatedOutputStatus = st.TokenOutputStatusCreatedFinalized
	}

	invalidOutputs = validateOutputs(tokenTransaction.Edges.CreatedOutput, expectedCreatedOutputStatus)
	if len(tokenTransaction.Edges.SpentOutput) > 0 {
		invalidOutputs = append(invalidOutputs, validateInputs(tokenTransaction.Edges.SpentOutput, st.TokenOutputStatusSpentSigned)...)
	}
	if len(invalidOutputs) > 0 {
		return nil, formatErrorWithTransactionEnt(
			fmt.Sprintf("%s: %s",
				errInvalidOutputs,
				strings.Join(invalidOutputs, "; ")),
			tokenTransaction, nil)
	}

	if err := utils.ValidateOwnershipSignature(
		tokenTransaction.OperatorSignature,
		finalTokenTransactionHash,
		config.IdentityPublicKey(),
	); err != nil {
		return nil, formatErrorWithTransactionEnt(errStoredOperatorSignatureInvalid, tokenTransaction, err)
	}

	logWithTransactionEnt(ctx, "Returning stored signature in response to repeat Sign() call", tokenTransaction, slog.LevelDebug)
	return tokenTransaction.OperatorSignature, nil
}

func (h InternalTokenTransactionHandler) CancelOrFinalizeExpiredTokenTransaction(
	ctx context.Context,
	config *so.Config,
	lockedTokenTransaction *ent.TokenTransaction,
) error {
	// Verify that the transaction is in a cancellable state locally
	if lockedTokenTransaction.Status != st.TokenTransactionStatusSigned &&
		lockedTokenTransaction.Status != st.TokenTransactionStatusStarted {
		return formatErrorWithTransactionEntInternal(
			fmt.Sprintf(errInvalidTransactionStatus,
				lockedTokenTransaction.Status, fmt.Sprintf("%s or %s", st.TokenTransactionStatusStarted, st.TokenTransactionStatusSigned)),
			lockedTokenTransaction, nil)
	}

	// Verify with the other SOs that the transaction is in a cancellable state.
	// Each SO verifies that:
	// 1. No SO has moved the transaction to a 'Finalized' state.
	// 2. (# of SOs) - threshold have not progressed the transaction to a 'Signed' state.
	// TODO(DL-142): Consider optimizing this query to minimize necessary RPC calls.
	allSelection := helper.OperatorSelection{Option: helper.OperatorSelectionOptionAll}
	responses, err := helper.ExecuteTaskWithAllOperators(ctx, config, &allSelection, func(ctx context.Context, operator *so.SigningOperator) (interface{}, error) {
		conn, err := operator.NewGRPCConnection()
		if err != nil {
			return nil, formatErrorWithTransactionEntInternal(
				fmt.Sprintf(errFailedToConnectToOperatorForCancel, operator.Identifier),
				lockedTokenTransaction, err)
		}
		defer conn.Close()

		client := pb.NewSparkServiceClient(conn)
		internalResp, err := client.QueryTokenTransactions(ctx, &pb.QueryTokenTransactionsRequest{
			TokenTransactionHashes: [][]byte{lockedTokenTransaction.FinalizedTokenTransactionHash},
		})
		if err != nil {
			return nil, formatErrorWithTransactionEntInternal(
				fmt.Sprintf(errFailedToQueryOperatorForCancel, operator.Identifier),
				lockedTokenTransaction, err)
		}
		return internalResp, err
	})
	if err != nil {
		return formatErrorWithTransactionEntInternal(errFailedToExecuteWithAllOperators, lockedTokenTransaction, err)
	}

	// Check if any operator has finalized the transaction
	signedCount := 0
	for _, resp := range responses {
		queryResp, ok := resp.(*pb.QueryTokenTransactionsResponse)
		if !ok || queryResp == nil {
			return formatErrorWithTransactionEntInternal("invalid response from operator", lockedTokenTransaction, nil)
		}

		for _, txWithStatus := range queryResp.TokenTransactionsWithStatus {
			// If the transaction has been finalized by a different operator, it indicates that threshold operators have signed.
			// This could occur if a wallet attempted to finalized but did not successfully complete the request with all SOs.
			// In this case, finalize the transaction with the revocation secrets provided by the operator that finalized the transaction.
			if txWithStatus.Status == pb.TokenTransactionStatus_TOKEN_TRANSACTION_FINALIZED {
				revocationSecrets := make([]*pb.RevocationSecretWithIndex, len(lockedTokenTransaction.Edges.SpentOutput))
				revocationSecretMap := make(map[string]*pb.SpentTokenOutputMetadata)
				if txWithStatus.ConfirmationMetadata == nil {
					return formatErrorWithTransactionEntInternal("missing confirmation metadata", lockedTokenTransaction, nil)
				}
				if len(txWithStatus.ConfirmationMetadata.SpentTokenOutputsMetadata) != len(lockedTokenTransaction.Edges.SpentOutput) {
					return formatErrorWithTransactionEntInternal("confirmation metadata does not match number of spent outputs", lockedTokenTransaction, nil)
				}

				for _, metadata := range txWithStatus.ConfirmationMetadata.SpentTokenOutputsMetadata {
					revocationSecretMap[metadata.OutputId] = metadata
				}

				tokenTransactionProto, err := lockedTokenTransaction.MarshalProto(config)
				if err != nil {
					return formatErrorWithTransactionEntInternal("failed to marshal token transaction", lockedTokenTransaction, err)
				}
				// Match received revocation secrets to their input index saved in the TokenOutput entity using output_id.
				for i, output := range lockedTokenTransaction.Edges.SpentOutput {
					metadata, exists := revocationSecretMap[output.ID.String()]
					if !exists {
						return formatErrorWithTransactionEntInternal(
							fmt.Sprintf("missing revocation secret for output %s", output.ID.String()),
							lockedTokenTransaction, nil)
					}
					revocationSecrets[i] = &pb.RevocationSecretWithIndex{
						InputIndex:       uint32(output.SpentTransactionInputVout),
						RevocationSecret: metadata.RevocationSecret,
					}
				}
				finalizeReq := &pb.FinalizeTokenTransactionRequest{
					FinalTokenTransaction: tokenTransactionProto,
					RevocationSecrets:     revocationSecrets,
					IdentityPublicKey:     nil,
				}

				_, err = h.FinalizeTokenTransactionInternal(ctx, config, finalizeReq)
				if err != nil {
					return formatErrorWithTransactionEntInternal("failed to finalize transaction", lockedTokenTransaction, err)
				}

				return formatErrorWithTransactionEntInternal("transaction has already been finalized by at least one operator, cannot cancel", lockedTokenTransaction, nil)
			}
			if txWithStatus.Status == pb.TokenTransactionStatus_TOKEN_TRANSACTION_SIGNED ||
				// Check for this just in case. Its unlikely, but it is theoretically possible for a race condition where
				// the transaction is signed by the final operator needed for threshold just as the transaction is cancelled by a
				// different operator. In this event, the operators that didn't cancel yet should not cancel to avoid a fully
				// signed transaction being cancelled in all SOs.
				// TODO(DL-140): Better handle this race condition, likely by allowing SIGNED_CANCELLED to transition into FINALIZED
				// if a revocation secret is provided (which proves that all SOs have signed)
				txWithStatus.Status == pb.TokenTransactionStatus_TOKEN_TRANSACTION_SIGNED_CANCELLED {
				signedCount++
			}
		}
	}

	// Check if too many operators have already signed
	operatorCount := len(config.GetSigningOperatorList())
	if signedCount == operatorCount {
		return formatErrorWithTransactionEntInternal(
			fmt.Sprintf("transaction has been signed by %d operators, which exceeds the cancellation threshold of %d",
				signedCount, operatorCount),
			lockedTokenTransaction, nil)
	}

	err = ent.UpdateCancelledTransaction(ctx, lockedTokenTransaction)
	if err != nil {
		return formatErrorWithTransactionEntInternal(fmt.Sprintf(errFailedToUpdateOutputs, "canceling"), lockedTokenTransaction, err)
	}

	return nil
}

func ValidateMintSignature(
	tokenTransaction *pb.TokenTransaction,
	tokenTransactionSignatures *pb.TokenTransactionSignatures,
) error {
	// Although this token transaction is final we pass in 'true' to generate the partial hash.
	partialTokenTransactionHash, err := utils.HashTokenTransactionV0(tokenTransaction, true)
	if err != nil {
		return formatErrorWithTransactionProtoInternal("failed to hash token transaction", tokenTransaction, err)
	}

	err = utils.ValidateOwnershipSignature(tokenTransactionSignatures.GetOwnerSignatures()[0].Signature, partialTokenTransactionHash, tokenTransaction.GetMintInput().GetIssuerPublicKey())
	if err != nil {
		return formatErrorWithTransactionProtoInternal("invalid issuer signature", tokenTransaction, err)
	}

	return nil
}

func (h *InternalTokenTransactionHandler) QueryOwnedTokenOutputsInternal(
	ctx context.Context,
	req *pb.QueryTokenOutputsRequest,
) (*pb.QueryTokenOutputsResponse, error) {
	var network common.Network
	if req.GetNetwork() == pb.Network_UNSPECIFIED {
		network = common.Mainnet
	} else {
		var err error
		network, err = common.NetworkFromProtoNetwork(req.Network)
		if err != nil {
			return nil, fmt.Errorf("failed to convert proto network to common network: %w", err)
		}
	}
	outputs, err := ent.GetOwnedTokenOutputs(ctx, req.OwnerPublicKeys, req.TokenPublicKeys, network)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", errFailedToGetOwnedOutputStats, err)
	}
	ownedTokenOutputs := make([]*pb.OutputWithPreviousTransactionData, 0)
	for _, output := range outputs {
		idStr := output.ID.String()
		ownedTokenOutputs = append(ownedTokenOutputs, &pb.OutputWithPreviousTransactionData{
			Output: &pb.TokenOutput{
				Id:                            &idStr,
				OwnerPublicKey:                output.OwnerPublicKey,
				RevocationCommitment:          output.WithdrawRevocationCommitment,
				WithdrawBondSats:              &output.WithdrawBondSats,
				WithdrawRelativeBlockLocktime: &output.WithdrawRelativeBlockLocktime,
				TokenPublicKey:                output.TokenPublicKey,
				TokenAmount:                   output.TokenAmount,
			},
			PreviousTransactionHash: output.Edges.OutputCreatedTokenTransaction.FinalizedTokenTransactionHash,
			PreviousTransactionVout: uint32(output.CreatedTransactionOutputVout),
		})
	}
	return &pb.QueryTokenOutputsResponse{
		OutputsWithPreviousTransactionData: ownedTokenOutputs,
	}, nil
}

func (h InternalTokenTransactionHandler) FinalizeTokenTransactionInternal(
	ctx context.Context,
	config *so.Config,
	req *pb.FinalizeTokenTransactionRequest,
) (*emptypb.Empty, error) {
	tokenProtoTokenTransaction, err := protoconverter.TokenProtoFromSparkTokenTransaction(req.FinalTokenTransaction)
	if err != nil {
		return nil, fmt.Errorf("failed to convert token transaction to spark token transaction: %w", err)
	}
	tokenTransaction, err := ent.FetchAndLockTokenTransactionData(ctx, tokenProtoTokenTransaction)
	if err != nil {
		return nil, formatErrorWithTransactionEnt(errFailedToFetchTransaction, tokenTransaction, err)
	}

	// Verify that the transaction is in a signed state before finalizing
	if tokenTransaction.Status != st.TokenTransactionStatusSigned {
		return nil, formatErrorWithTransactionEnt(
			fmt.Sprintf(errInvalidTransactionStatus,
				tokenTransaction.Status, st.TokenTransactionStatusSigned),
			tokenTransaction, nil)
	}

	// Verify status of created outputs and spent outputs
	invalidOutputs := validateOutputs(tokenTransaction.Edges.CreatedOutput, st.TokenOutputStatusCreatedSigned)
	if len(tokenTransaction.Edges.SpentOutput) > 0 {
		invalidOutputs = append(invalidOutputs, validateInputs(tokenTransaction.Edges.SpentOutput, st.TokenOutputStatusSpentSigned)...)
	}

	if len(invalidOutputs) > 0 {
		return nil, formatErrorWithTransactionEnt(fmt.Sprintf("%s: %s", errInvalidOutputs, strings.Join(invalidOutputs, "; ")), tokenTransaction, nil)
	}

	if len(tokenTransaction.Edges.SpentOutput) != len(req.RevocationSecrets) {
		return nil, formatErrorWithTransactionEnt(
			fmt.Sprintf("number of revocation keys (%d) does not match number of spent outputs (%d)",
				len(req.RevocationSecrets),
				len(tokenTransaction.Edges.SpentOutput)),
			tokenTransaction, nil)
	}
	revocationSecretMap := make(map[int][]byte)
	for _, revocationSecret := range req.RevocationSecrets {
		revocationSecretMap[int(revocationSecret.InputIndex)] = revocationSecret.RevocationSecret
	}
	// Validate that we have exactly one revocation secret for each input index
	// and that they form a contiguous sequence from 0 to len(tokenTransaction.Edges.SpentOutput)-1
	for i := 0; i < len(tokenTransaction.Edges.SpentOutput); i++ {
		if _, exists := revocationSecretMap[i]; !exists {
			return nil, formatErrorWithTransactionEnt(
				fmt.Sprintf("missing revocation secret for input index %d", i),
				tokenTransaction, nil)
		}
	}

	revocationSecrets := make([]*secp256k1.PrivateKey, len(revocationSecretMap))
	revocationCommitements := make([][]byte, len(revocationSecretMap))

	spentOutputs := make([]*ent.TokenOutput, len(tokenTransaction.Edges.SpentOutput))
	copy(spentOutputs, tokenTransaction.Edges.SpentOutput)
	sort.Slice(spentOutputs, func(i, j int) bool {
		return spentOutputs[i].SpentTransactionInputVout < spentOutputs[j].SpentTransactionInputVout
	})

	// Match each output with its corresponding revocation secret
	for i, output := range spentOutputs {
		index := int(output.SpentTransactionInputVout)
		revocationSecret, exists := revocationSecretMap[index]
		if !exists {
			return nil, formatErrorWithTransactionEnt(
				fmt.Sprintf("missing revocation secret for input at index %d", index),
				tokenTransaction, nil)
		}

		revocationPrivateKey, err := common.PrivateKeyFromBytes(revocationSecret)
		if err != nil {
			return nil, formatErrorWithTransactionEnt(errFailedToParseRevocationPrivateKey, tokenTransaction, err)
		}

		revocationSecrets[i] = revocationPrivateKey
		revocationCommitements[i] = output.WithdrawRevocationCommitment
	}

	err = utils.ValidateRevocationKeys(revocationSecrets, revocationCommitements)
	if err != nil {
		return nil, formatErrorWithTransactionEnt(errFailedToValidateRevocationKeys, tokenTransaction, err)
	}

	identityPrivateKey := secp256k1.PrivKeyFromBytes(config.IdentityPrivateKey)

	err = h.lrc20Client.SendSparkSignature(ctx, h.lrc20Client.BuildLrc20SendSignaturesRequest(
		req.FinalTokenTransaction,
		tokenTransaction.OperatorSignature,
		identityPrivateKey,
		req.RevocationSecrets,
	))
	if err != nil {
		return nil, formatErrorWithTransactionEnt(errFailedToSendToLRC20Node, tokenTransaction, err)
	}

	err = ent.UpdateFinalizedTransaction(ctx, tokenTransaction, req.RevocationSecrets)
	if err != nil {
		return nil, formatErrorWithTransactionEnt(fmt.Sprintf(errFailedToUpdateOutputs, "finalizing"), tokenTransaction, err)
	}

	return &emptypb.Empty{}, nil
}

func ValidateTokenTransactionUsingPreviousTransactionData(
	tokenTransaction *pb.TokenTransaction,
	tokenTransactionSignatures *pb.TokenTransactionSignatures,
	outputToSpendEnts []*ent.TokenOutput,
) error {
	// Validate that all token public keys in outputs to spend match the outputs.
	// Ok to just check against the first output because output token public key uniformity
	// is checked in the main ValidateTokenTransaction() call.
	expectedTokenPubKey := tokenTransaction.TokenOutputs[0].GetTokenPublicKey()
	if expectedTokenPubKey == nil {
		return formatErrorWithTransactionProtoInternal("token public key cannot be nil in outputs", tokenTransaction, fmt.Errorf("token public key cannot be nil in outputs"))
	}
	for i, outputEnt := range outputToSpendEnts {
		if !bytes.Equal(outputEnt.TokenPublicKey, expectedTokenPubKey) {
			return formatErrorWithTransactionProtoInternal("token public key mismatch", tokenTransaction, fmt.Errorf("token public key mismatch for output %d - input outputs must be for the same token public key as the output", i))
		}

		// TODO(DL-104): For now we allow the network to be nil to support old outputs. In the future we should require it to be set.
		if outputEnt.Network != st.Network("") {
			entNetwork, err := outputEnt.Network.MarshalProto()
			if err != nil {
				return formatErrorWithTransactionProtoInternal("failed to marshal network", tokenTransaction, err)
			}
			if entNetwork != tokenTransaction.Network {
				return formatErrorWithTransactionProtoInternal("network mismatch", tokenTransaction, fmt.Errorf("output %d: %d != %d", i, entNetwork, tokenTransaction.Network))
			}
		}
	}
	// Validate token conservation in inputs + outputs.
	totalInputAmount := new(big.Int)
	for _, outputEnt := range outputToSpendEnts {
		inputAmount := new(big.Int).SetBytes(outputEnt.TokenAmount)
		totalInputAmount.Add(totalInputAmount, inputAmount)
	}
	totalOutputAmount := new(big.Int)
	for _, outputLeaf := range tokenTransaction.TokenOutputs {
		outputAmount := new(big.Int).SetBytes(outputLeaf.GetTokenAmount())
		totalOutputAmount.Add(totalOutputAmount, outputAmount)
	}
	if totalInputAmount.Cmp(totalOutputAmount) != 0 {
		return formatErrorWithTransactionProtoInternal("token amount mismatch", tokenTransaction, fmt.Errorf("total input amount %s does not match total output amount %s", totalInputAmount.String(), totalOutputAmount.String()))
	}

	// Validate that the ownership signatures match the ownership public keys in the outputs to spend.
	// Although this token transaction is final we pass in 'true' to generate the partial hash.
	partialTokenTransactionHash, err := utils.HashTokenTransactionV0(tokenTransaction, true)
	if err != nil {
		return fmt.Errorf("failed to hash token transaction: %w", err)
	}

	ownerSignaturesByIndex := make(map[uint32]*pb.SignatureWithIndex)
	for _, sig := range tokenTransactionSignatures.GetOwnerSignatures() {
		if sig == nil {
			return formatErrorWithTransactionProtoInternal("invalid signature", tokenTransaction, fmt.Errorf("ownership signature cannot be nil"))
		}
		ownerSignaturesByIndex[sig.InputIndex] = sig
	}

	if len(tokenTransactionSignatures.GetOwnerSignatures()) != len(tokenTransaction.GetTransferInput().GetOutputsToSpend()) {
		return formatErrorWithTransactionProtoInternal("signature count mismatch", tokenTransaction, fmt.Errorf("number of signatures must match number of outputs to spend"))
	}

	for i := range tokenTransaction.GetTransferInput().GetOutputsToSpend() {
		index := uint32(i)
		ownershipSignature, exists := ownerSignaturesByIndex[index]
		if !exists {
			return formatErrorWithTransactionProtoInternal("missing signature", tokenTransaction, fmt.Errorf("missing owner signature for input index %d, indexes must be contiguous", index))
		}

		// Get the corresponding output entity (they are ordered outside of this block when they are fetched)
		outputEnt := outputToSpendEnts[i]
		if outputEnt == nil {
			return formatErrorWithTransactionProtoInternal("missing output entity", tokenTransaction, fmt.Errorf("could not find output entity for output to spend at index %d", i))
		}

		err = utils.ValidateOwnershipSignature(ownershipSignature.Signature, partialTokenTransactionHash, outputEnt.OwnerPublicKey)
		if err != nil {
			return formatErrorWithTransactionProtoInternal("invalid ownership signature", tokenTransaction, fmt.Errorf("invalid ownership signature for output %d: %w", i, err))
		}
		err := validateOutputIsSpendable(i, outputEnt)
		if err != nil {
			return err
		}
	}

	return nil
}

// validateOutputIsSpendable checks if a output is eligible to be spent by verifying:
// 1. The output has an appropriate status (Created+Finalized or already marked as SpentStarted)
// 2. The output hasn't been withdrawn already
func validateOutputIsSpendable(index int, output *ent.TokenOutput) error {
	if !isSpendableOutputStatus(output.Status) {
		return fmt.Errorf("output %d cannot be spent: invalid status %s (must be CreatedFinalized or SpentStarted)", index, output.Status)
	}

	if output.ConfirmedWithdrawBlockHash != nil {
		return fmt.Errorf("output %d cannot be spent: already withdrawn", index)
	}

	return nil
}

// isSpendableOutputStatus checks if a output's status allows it to be spent.
func isSpendableOutputStatus(status st.TokenOutputStatus) bool {
	return status == st.TokenOutputStatusCreatedFinalized ||
		status == st.TokenOutputStatusSpentStarted
}

func validateFinalTokenTransaction(
	config *so.Config,
	tokenTransaction *pb.TokenTransaction,
	tokenTransactionSignatures *pb.TokenTransactionSignatures,
	expectedRevocationPublicKeys [][]byte,
) error {
	network, err := common.NetworkFromProtoNetwork(tokenTransaction.Network)
	if err != nil {
		return fmt.Errorf("failed to get network from proto network: %w", err)
	}
	expectedBondSats := config.Lrc20Configs[network.String()].WithdrawBondSats
	expectedRelativeBlockLocktime := config.Lrc20Configs[network.String()].WithdrawRelativeBlockLocktime
	sparkOperatorsFromConfig := config.GetSigningOperatorList()
	// Repeat same validations as for the partial token transaction.
	err = utils.ValidatePartialTokenTransaction(tokenTransaction, tokenTransactionSignatures, sparkOperatorsFromConfig, config.SupportedNetworks)
	if err != nil {
		return fmt.Errorf("failed to validate final token transaction: %w", err)
	}

	// Additionally validate the revocation public keys and withdrawal params which were added to make it final.
	for i, output := range tokenTransaction.TokenOutputs {
		if output.GetRevocationCommitment() == nil {
			return fmt.Errorf("revocation public key cannot be nil for output %d", i)
		}
		if !bytes.Equal(output.GetRevocationCommitment(), expectedRevocationPublicKeys[i]) {
			return fmt.Errorf("revocation public key mismatch for output %d", i)
		}
		if output.WithdrawBondSats == nil || output.WithdrawRelativeBlockLocktime == nil {
			return fmt.Errorf("withdrawal params not set for output %d", i)
		}
		if output.GetWithdrawBondSats() != expectedBondSats {
			return fmt.Errorf("withdrawal bond sats mismatch for output %d", i)
		}
		if output.GetWithdrawRelativeBlockLocktime() != expectedRelativeBlockLocktime {
			return fmt.Errorf("withdrawal locktime mismatch for output %d", i)
		}
	}
	return nil
}

func FinalizeTransferTransaction(ctx context.Context, tokenTransaction *ent.TokenTransaction) error {
	if len(tokenTransaction.Edges.SpentOutput) > 0 {
		// Reload the token transaction to get the latest state after signing
		tokenTransaction, err := ent.GetDbFromContext(ctx).TokenTransaction.Query().
			Where(tokentransaction.ID(tokenTransaction.ID)).
			WithCreatedOutput().
			WithSpentOutput(func(q *ent.TokenOutputQuery) {
				// Needed to enable marshalling of the token transaction proto.
				q.WithOutputCreatedTokenTransaction()
			}).
			WithMint().
			Only(ctx)
		if err != nil {
			return fmt.Errorf("failed to reload token transaction: %w", err)
		}
		err = ent.FinalizeTokenTransactionWithoutRevocationKeys(ctx, tokenTransaction)
		if err != nil {
			return fmt.Errorf("failed to finalize transaction: %w", err)
		}
	}
	return nil
}

func formatErrorWithTransactionEntInternal(msg string, tokenTransaction *ent.TokenTransaction, err error) error {
	return fmt.Errorf("%s (uuid: %s, hash: %x): %w",
		msg,
		tokenTransaction.ID.String(),
		tokenTransaction.FinalizedTokenTransactionHash,
		err)
}

func formatErrorWithTransactionProtoInternal(msg string, tokenTransaction *pb.TokenTransaction, err error) error {
	if err != nil {
		return fmt.Errorf("%s (transaction: %s): %w",
			msg,
			tokenTransaction.String(),
			err)
	}
	return fmt.Errorf("%s (transaction: %s)",
		msg,
		tokenTransaction.String())
}
