package handler

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"log/slog"
	"sort"
	"strings"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"github.com/google/uuid"
	"github.com/lightsparkdev/spark/common"
	"github.com/lightsparkdev/spark/common/logging"
	pblrc20 "github.com/lightsparkdev/spark/proto/lrc20"
	sparkpb "github.com/lightsparkdev/spark/proto/spark"
	pbinternal "github.com/lightsparkdev/spark/proto/spark_internal"
	tokenpb "github.com/lightsparkdev/spark/proto/spark_token"
	tokeninternalpb "github.com/lightsparkdev/spark/proto/spark_token_internal"
	"github.com/lightsparkdev/spark/so"
	"github.com/lightsparkdev/spark/so/authz"
	"github.com/lightsparkdev/spark/so/ent"
	st "github.com/lightsparkdev/spark/so/ent/schema/schematype"
	"github.com/lightsparkdev/spark/so/ent/tokenoutput"
	"github.com/lightsparkdev/spark/so/ent/tokentransaction"
	"github.com/lightsparkdev/spark/so/helper"
	"github.com/lightsparkdev/spark/so/lrc20"
	"github.com/lightsparkdev/spark/so/protoconverter"
	"github.com/lightsparkdev/spark/so/utils"
	"google.golang.org/protobuf/types/known/emptypb"
)

const (
	// Error message constants
	errIdentityPublicKeyAuthFailed        = "identity public key authentication failed"
	errInvalidPartialTokenTransaction     = "invalid partial token transaction"
	errFailedToHashPartialTransaction     = "failed to hash partial token transaction"
	errFailedToFetchPartialTransaction    = "failed to fetch partial token transaction data"
	errFailedToFetchTransaction           = "failed to fetch transaction"
	errFailedToGetUnusedKeyshares         = "failed to get unused signing keyshares"
	errNotEnoughUnusedKeyshares           = "not enough unused signing keyshares available"
	errFailedToGetNetworkFromProto        = "failed to get network from proto network"
	errFailedToExecuteWithNonCoordinator  = "failed to execute start token transaction with non-coordinator operators"
	errFailedToExecuteWithCoordinator     = "failed to execute start token transaction with coordinator"
	errFailedToGetKeyshareInfo            = "failed to get keyshare info"
	errFailedToHashFinalTransaction       = "failed to hash final token transaction"
	errFailedToConnectToOperator          = "failed to connect to operator: %s"
	errFailedToExecuteWithOperator        = "failed to execute start token transaction with operator: %s"
	errFailedToGetOperatorList            = "failed to get operator list"
	errFailedToSendToLRC20Node            = "failed to send transaction to LRC20 node"
	errFailedToUpdateOutputs              = "failed to update outputs after %s"
	errFailedToGetKeyshareForOutput       = "failed to get keyshare for output"
	errFailedToQueryTokenFreezeStatus     = "failed to query token freeze status"
	errTransactionNotCoordinatedBySO      = "transaction not coordinated by this SO"
	errFailedToGetOwnedOutputStats        = "failed to get owned output stats"
	errFailedToParseRevocationPrivateKey  = "failed to parse revocation private key"
	errFailedToValidateRevocationKeys     = "failed to validate revocation keys"
	errRevocationKeyMismatch              = "keyshare public key does not match output revocation commitment"
	errInvalidOutputs                     = "found invalid outputs"
	errInvalidInputs                      = "found invalid inputs"
	errFailedToMarshalTokenTransaction    = "failed to marshal token transaction"
	errMultipleActiveFreezes              = "multiple active freezes found for this owner and token which should not happen"
	errNoActiveFreezes                    = "no active freezes found to thaw"
	errAlreadyFrozen                      = "tokens are already frozen for this owner and token"
	errFailedToCreateTokenFreeze          = "failed to create token freeze entity"
	errFailedToUpdateTokenFreeze          = "failed to update token freeze status to thawed"
	errInvalidOutputIDFormat              = "invalid output ID format"
	errFailedToQueryTokenTransactions     = "unable to query token transactions"
	errInvalidOperatorResponse            = "invalid response from operator"
	errTransactionAlreadyFinalized        = "transaction has already been finalized by at least one operator, cannot cancel"
	errTooManyOperatorsSigned             = "transaction has been signed by %d operators, which exceeds the cancellation threshold of %d"
	errInvalidTransactionStatus           = "transaction is in status %s, but must be in %s status to cancel"
	errStoredOperatorSignatureInvalid     = "stored operator signature is invalid"
	errFailedToGetRevocationKeyshares     = "failed to get revocation keyshares for transaction"
	errFailedToConnectToOperatorForCancel = "failed to connect to operator %s"
	errFailedToQueryOperatorForCancel     = "failed to execute query with operator %s"
	errFailedToExecuteWithAllOperators    = "failed to execute query with all operators"
	errInputIndexOutOfRange               = "input index %d out of range (0-%d)"
	errInvalidOwnerSignature              = "invalid owner signature for output"
	errInvalidIssuerSignature             = "invalid issuer signature for mint"
	errFailedToHashRevocationKeyshares    = "failed to hash revocation keyshares payload"
	errTransactionHashMismatch            = "transaction hash in payload (%x) does not match actual transaction hash (%x)"
	errOperatorPublicKeyMismatch          = "operator identity public key in payload (%x) does not match this SO's identity public key (%x)"
)

type operatorSignaturesMap map[string][]byte

// The TokenTransactionHandler is responsible for handling token transaction requests to spend and create outputs.
type TokenTransactionHandler struct {
	authzConfig authz.Config
	soConfig    *so.Config
	db          *ent.Client
	lrc20Client *lrc20.Client
}

// NewTokenTransactionHandler creates a new TokenTransactionHandler.
func NewTokenTransactionHandler(authzConfig authz.Config, soConfig *so.Config, db *ent.Client, lrc20Client *lrc20.Client) *TokenTransactionHandler {
	return &TokenTransactionHandler{
		authzConfig: authzConfig,
		soConfig:    soConfig,
		db:          db,
		lrc20Client: lrc20Client,
	}
}

// StartTokenTransaction verifies the token outputs, reserves the keyshares for the token transaction, and returns metadata about the operators that possess the keyshares.
func (o TokenTransactionHandler) StartTokenTransaction(ctx context.Context, config *so.Config, req *sparkpb.StartTokenTransactionRequest) (*sparkpb.StartTokenTransactionResponse, error) {
	if err := authz.EnforceSessionIdentityPublicKeyMatches(ctx, o.authzConfig, req.IdentityPublicKey); err != nil {
		return nil, formatErrorWithTransactionProto(errIdentityPublicKeyAuthFailed, req.PartialTokenTransaction, err)
	}

	if err := utils.ValidatePartialTokenTransaction(req.PartialTokenTransaction, req.TokenTransactionSignatures, config.GetSigningOperatorList(), config.SupportedNetworks); err != nil {
		return nil, formatErrorWithTransactionProto(errInvalidPartialTokenTransaction, req.PartialTokenTransaction, err)
	}

	partialTokenTransactionHash, err := utils.HashTokenTransactionV0(req.PartialTokenTransaction, true)
	if err != nil {
		return nil, formatErrorWithTransactionProto(errFailedToHashPartialTransaction, req.PartialTokenTransaction, err)
	}

	previouslyCreatedTokenTransaction, err := ent.FetchPartialTokenTransactionData(ctx, partialTokenTransactionHash)
	if err != nil && !ent.IsNotFound(err) {
		return nil, formatErrorWithTransactionProto(errFailedToFetchPartialTransaction, req.PartialTokenTransaction, err)
	}

	// Check that the previous created transaction was found and that it is still in the started state.
	// Also, check that this SO was the coordinator for the transaction. This is necessary because only the coordinator
	// receives direct evidence from each SO individually that a threshold of SOs have validated and saved the transaction.
	if previouslyCreatedTokenTransaction != nil &&
		previouslyCreatedTokenTransaction.Status == st.TokenTransactionStatusStarted &&
		bytes.Equal(previouslyCreatedTokenTransaction.CoordinatorPublicKey, config.IdentityPublicKey()) {
		logWithTransactionEnt(ctx, "Found existing token transaction in started state with matching coordinator",
			previouslyCreatedTokenTransaction, slog.LevelInfo)
		return o.regenerateStartResponseForDuplicateRequest(ctx, config, previouslyCreatedTokenTransaction)
	}
	// Each created output requires a keyshare for revocation key generation.
	numRevocationKeysharesNeeded := len(req.PartialTokenTransaction.TokenOutputs)
	keyshares, err := ent.GetUnusedSigningKeyshares(ctx, o.db, config, numRevocationKeysharesNeeded)
	if err != nil {
		return nil, formatErrorWithTransactionProto(errFailedToGetUnusedKeyshares, req.PartialTokenTransaction, err)
	}

	if len(keyshares) < numRevocationKeysharesNeeded {
		return nil, formatErrorWithTransactionProto(
			errFailedToGetUnusedKeyshares, req.PartialTokenTransaction,
			fmt.Errorf("%s: %d needed, %d available", errNotEnoughUnusedKeyshares, numRevocationKeysharesNeeded, len(keyshares)))
	}

	keyshareIDs := make([]uuid.UUID, len(keyshares))
	keyshareIDStrings := make([]string, len(keyshares))
	for i, keyshare := range keyshares {
		keyshareIDs[i] = keyshare.ID
		keyshareIDStrings[i] = keyshare.ID.String()
	}
	network, err := common.NetworkFromProtoNetwork(req.PartialTokenTransaction.Network)
	if err != nil {
		return nil, formatErrorWithTransactionProto(errFailedToGetNetworkFromProto, req.PartialTokenTransaction, err)
	}

	// Fill revocation commitments and withdrawal bond/locktime for each output.
	finalTokenTransaction := req.PartialTokenTransaction
	for i, output := range finalTokenTransaction.TokenOutputs {
		id, err := uuid.NewV7()
		if err != nil {
			return nil, err
		}
		idStr := id.String()
		output.Id = &idStr
		output.RevocationCommitment = keyshares[i].PublicKey
		withdrawalBondSats := config.Lrc20Configs[network.String()].WithdrawBondSats
		output.WithdrawBondSats = &withdrawalBondSats
		withdrawRelativeBlockLocktime := config.Lrc20Configs[network.String()].WithdrawRelativeBlockLocktime
		output.WithdrawRelativeBlockLocktime = &withdrawRelativeBlockLocktime
	}

	// Save the token transaction object to lock in the revocation commitments for each created output within this transaction.
	// Note that atomicity here is very important to ensure that the unused keyshares queried above are not used by another operation.
	// This property should be help because the coordinator blocks on the other SO responses.
	allExceptSelfSelection := helper.OperatorSelection{Option: helper.OperatorSelectionOptionExcludeSelf}
	_, err = helper.ExecuteTaskWithAllOperators(ctx, config, &allExceptSelfSelection, func(ctx context.Context, operator *so.SigningOperator) (interface{}, error) {
		return callStartTokenTransactionInternal(ctx, operator, finalTokenTransaction, req.TokenTransactionSignatures, keyshareIDStrings, config.IdentityPublicKey())
	})
	if err != nil {
		return nil, formatErrorWithTransactionProto(errFailedToExecuteWithNonCoordinator, req.PartialTokenTransaction, err)
	}

	// Only save in the coordinator SO after receiving confirmation from all other SOs. This ensures that if
	// a follow up call is made that the coordiantor has only saved the data if the initial Start call reached the SO threshold.
	selfOperator := config.SigningOperatorMap[config.Identifier]
	_, err = callStartTokenTransactionInternal(ctx, selfOperator, finalTokenTransaction, req.TokenTransactionSignatures, keyshareIDStrings, config.IdentityPublicKey())
	if err != nil {
		return nil, formatErrorWithTransactionProto(errFailedToExecuteWithCoordinator, req.PartialTokenTransaction, err)
	}

	keyshareInfo, err := getStartTokenTransactionKeyshareInfo(config)
	if keyshareInfo == nil {
		return nil, formatErrorWithTransactionProto(errFailedToGetKeyshareInfo, req.PartialTokenTransaction, err)
	}

	return &sparkpb.StartTokenTransactionResponse{
		FinalTokenTransaction: finalTokenTransaction,
		KeyshareInfo:          keyshareInfo,
	}, nil
}

// callStartTokenTransactionInternal handles calling the StartTokenTransactionInternal RPC on an operator
func callStartTokenTransactionInternal(ctx context.Context, operator *so.SigningOperator,
	finalTokenTransaction *sparkpb.TokenTransaction, tokenTransactionSignatures *sparkpb.TokenTransactionSignatures,
	keyshareIDStrings []string, coordinatorPublicKey []byte,
) (*emptypb.Empty, error) {
	conn, err := operator.NewGRPCConnection()
	if err != nil {
		return nil, formatErrorWithTransactionProto(fmt.Sprintf(errFailedToConnectToOperator, operator.Identifier), finalTokenTransaction, err)
	}
	defer conn.Close()

	client := pbinternal.NewSparkInternalServiceClient(conn)
	internalResp, err := client.StartTokenTransactionInternal(ctx, &pbinternal.StartTokenTransactionInternalRequest{
		KeyshareIds:                keyshareIDStrings,
		FinalTokenTransaction:      finalTokenTransaction,
		TokenTransactionSignatures: tokenTransactionSignatures,
		CoordinatorPublicKey:       coordinatorPublicKey,
	})
	if err != nil {
		return nil, formatErrorWithTransactionProto(fmt.Sprintf(errFailedToExecuteWithOperator, operator.Identifier), finalTokenTransaction, err)
	}
	return internalResp, err
}

func getStartTokenTransactionKeyshareInfo(config *so.Config) (*sparkpb.SigningKeyshare, error) {
	allOperators := helper.OperatorSelection{Option: helper.OperatorSelectionOptionAll}
	operatorList, err := allOperators.OperatorList(config)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", errFailedToGetOperatorList, err)
	}
	operatorIdentifiers := make([]string, len(operatorList))
	for i, operator := range operatorList {
		operatorIdentifiers[i] = operator.Identifier
	}
	return &sparkpb.SigningKeyshare{
		OwnerIdentifiers: operatorIdentifiers,
		// TODO: Unify threshold type (uint32 vs uint64) at all callsites between protos and config.
		Threshold: uint32(config.Threshold),
	}, nil
}

// SignTokenTransaction signs the token transaction with the operators private key.
// If it is a transfer it also fetches this operators keyshare for each spent output and
// returns it to the wallet so it can finalize the transaction.
func (o TokenTransactionHandler) SignTokenTransaction(
	ctx context.Context,
	config *so.Config,
	req *sparkpb.SignTokenTransactionRequest,
) (*sparkpb.SignTokenTransactionResponse, error) {
	logger := logging.GetLoggerFromContext(ctx)

	if err := authz.EnforceSessionIdentityPublicKeyMatches(ctx, o.authzConfig, req.IdentityPublicKey); err != nil {
		return nil, err
	}

	tokenProtoTokenTransaction, err := protoconverter.TokenProtoFromSparkTokenTransaction(req.FinalTokenTransaction)
	if err != nil {
		return nil, fmt.Errorf("failed to convert token transaction to spark token transaction: %w", err)
	}

	finalTokenTransactionHash, err := utils.HashTokenTransaction(tokenProtoTokenTransaction, false)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", errFailedToHashFinalTransaction, err)
	}

	tokenTransaction, err := ent.FetchAndLockTokenTransactionData(ctx, tokenProtoTokenTransaction)
	if err != nil {
		return nil, fmt.Errorf("%s %s: %w", errFailedToFetchTransaction, logging.FormatProto("final_token_transaction", req.FinalTokenTransaction), err)
	}

	internalHandler := NewInternalTokenTransactionHandler(config, o.lrc20Client)
	operatorSignature, err := internalHandler.SignAndPersistTokenTransaction(ctx, config, tokenTransaction, finalTokenTransactionHash, req.OperatorSpecificSignatures)
	if err != nil {
		return nil, err
	}

	if tokenTransaction.Status == st.TokenTransactionStatusSigned {
		revocationKeyshares, err := o.getRevocationKeysharesForTokenTransaction(ctx, tokenTransaction)
		if err != nil {
			return nil, formatErrorWithTransactionEnt(errFailedToGetRevocationKeyshares, tokenTransaction, err)
		}
		return &sparkpb.SignTokenTransactionResponse{
			SparkOperatorSignature: operatorSignature,
			RevocationKeyshares:    revocationKeyshares,
		}, nil
	}

	operatorSignatureData := &pblrc20.SparkOperatorSignatureData{
		SparkOperatorSignature:    operatorSignature,
		OperatorIdentityPublicKey: secp256k1.PrivKeyFromBytes(config.IdentityPrivateKey).PubKey().SerializeCompressed(),
	}

	keyshares := make([]*ent.SigningKeyshare, len(tokenTransaction.Edges.SpentOutput))
	revocationKeyshares := make([]*sparkpb.KeyshareWithIndex, len(tokenTransaction.Edges.SpentOutput))
	for _, output := range tokenTransaction.Edges.SpentOutput {
		keyshare, err := output.QueryRevocationKeyshare().Only(ctx)
		if err != nil {
			logger.Info("Failed to get keyshare for output", "error", err)
			return nil, err
		}
		index := output.SpentTransactionInputVout
		keyshares[index] = keyshare
		revocationKeyshares[index] = &sparkpb.KeyshareWithIndex{
			InputIndex: uint32(index),
			Keyshare:   keyshare.SecretShare,
		}

		// Validate that the keyshare's public key is as expected.
		if !bytes.Equal(keyshare.PublicKey, output.WithdrawRevocationCommitment) {
			return nil, fmt.Errorf(
				"keyshare public key %x does not match output revocation commitment %x",
				keyshare.PublicKey,
				output.WithdrawRevocationCommitment,
			)
		}
	}

	sparkSigReq := &pblrc20.SendSparkSignatureRequest{
		FinalTokenTransaction:      req.FinalTokenTransaction,
		OperatorSpecificSignatures: req.OperatorSpecificSignatures,
		OperatorSignatureData:      operatorSignatureData,
	}
	err = o.lrc20Client.SendSparkSignature(ctx, sparkSigReq)
	if err != nil {
		logger.Error("Failed to send transaction to LRC20 node", "error", err)
		return nil, err
	}

	return &sparkpb.SignTokenTransactionResponse{
		SparkOperatorSignature: operatorSignature,
		RevocationKeyshares:    revocationKeyshares,
	}, nil
}

func (o TokenTransactionHandler) CommitTransaction(ctx context.Context, req *tokenpb.CommitTransactionRequest) (*tokenpb.CommitTransactionResponse, error) {
	if req.FinalTokenTransaction.Network == sparkpb.Network_MAINNET {
		return nil, fmt.Errorf("mainnet transactions are not supported")
	}

	logger := logging.GetLoggerFromContext(ctx)

	if err := authz.EnforceSessionIdentityPublicKeyMatches(ctx, o.authzConfig, req.OwnerIdentityPublicKey); err != nil {
		return nil, fmt.Errorf("identity public key authentication failed: %w", err)
	}

	calculatedHash, err := utils.HashTokenTransaction(req.FinalTokenTransaction, false)
	if err != nil {
		return nil, fmt.Errorf("failed to hash final token transaction: %w", err)
	}
	if !bytes.Equal(calculatedHash, req.FinalTokenTransactionHash) {
		return nil, fmt.Errorf("transaction hash mismatch: expected %x, got %x", calculatedHash, req.FinalTokenTransactionHash)
	}

	tokenTransaction, err := ent.FetchAndLockTokenTransactionData(ctx, req.FinalTokenTransaction)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch transaction: %w", err)
	}

	if err := validateTokenTransactionForSigning(tokenTransaction); err != nil {
		return nil, formatErrorWithTransactionEnt(err.Error(), tokenTransaction, err)
	}

	allOperators := helper.OperatorSelection{Option: helper.OperatorSelectionOptionAll}
	internalSignatures, err := helper.ExecuteTaskWithAllOperators(ctx, o.soConfig, &allOperators,
		func(ctx context.Context, operator *so.SigningOperator) (*tokeninternalpb.SignTokenTransactionFromCoordinationResponse, error) {
			var foundOperatorSignatures *tokenpb.InputTtxoSignaturesPerOperator
			for _, operatorSignatures := range req.InputTtxoSignaturesPerOperator {
				if bytes.Equal(operatorSignatures.OperatorIdentityPublicKey, operator.IdentityPublicKey) {
					foundOperatorSignatures = operatorSignatures
					break
				}
			}
			if foundOperatorSignatures == nil {
				return nil, fmt.Errorf("no signatures found for operator %s", operator.Identifier)
			}

			if operator.Identifier == o.soConfig.Identifier {
				return o.localSignAndCommitTransaction(ctx, foundOperatorSignatures, req.FinalTokenTransactionHash, tokenTransaction)
			}

			conn, err := operator.NewGRPCConnection()
			if err != nil {
				return nil, fmt.Errorf("failed to connect to operator %s: %w", operator.Identifier, err)
			}
			defer conn.Close()
			client := tokeninternalpb.NewSparkTokenInternalServiceClient(conn)
			return client.SignTokenTransactionFromCoordination(ctx, &tokeninternalpb.SignTokenTransactionFromCoordinationRequest{
				FinalTokenTransaction:          req.FinalTokenTransaction,
				FinalTokenTransactionHash:      req.FinalTokenTransactionHash,
				InputTtxoSignaturesPerOperator: foundOperatorSignatures,
				OwnerIdentityPublicKey:         req.OwnerIdentityPublicKey,
			})
		},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to get signatures from operators: %w", err)
	}

	signatures := make(operatorSignaturesMap)
	for operatorID, sig := range internalSignatures {
		signatures[operatorID] = sig.SparkOperatorSignature
	}

	if err := o.sendSignaturesToLRC20Node(ctx, signatures[o.soConfig.Identifier], req); err != nil {
		return nil, fmt.Errorf("failed to send signatures to LRC20 node: %w", err)
	}

	if err := verifyOperatorSignatures(signatures, o.soConfig.SigningOperatorMap, req.FinalTokenTransactionHash); err != nil {
		return nil, fmt.Errorf("failed to verify operator signatures: %w", err)
	}

	logger.Info("Successfully signed and committed token transaction",
		"transaction_hash", req.FinalTokenTransactionHash)

	return &tokenpb.CommitTransactionResponse{}, nil
}

func (o TokenTransactionHandler) sendSignaturesToLRC20Node(ctx context.Context, operatorSignature []byte, req *tokenpb.CommitTransactionRequest) error {
	identityPrivateKey := secp256k1.PrivKeyFromBytes(o.soConfig.IdentityPrivateKey)
	identityPublicKey := o.soConfig.IdentityPublicKey()
	operatorSignatureData := &pblrc20.SparkOperatorSignatureData{
		SparkOperatorSignature:    operatorSignature,
		OperatorIdentityPublicKey: identityPublicKey,
	}

	sparkTokenTransaction, err := protoconverter.SparkTokenTransactionFromTokenProto(req.FinalTokenTransaction)
	if err != nil {
		return fmt.Errorf("failed to convert token transaction to spark token transaction: %w", err)
	}

	var thisOperatorSignatures *tokenpb.InputTtxoSignaturesPerOperator
	for _, operatorSignatures := range req.InputTtxoSignaturesPerOperator {
		if bytes.Equal(operatorSignatures.OperatorIdentityPublicKey, identityPublicKey) {
			thisOperatorSignatures = operatorSignatures
			break
		}
	}
	thisOperatorSpecificSignatures := convertTokenProtoSignaturesToOperatorSpecific(
		thisOperatorSignatures.TtxoSignatures,
		req.FinalTokenTransactionHash,
		identityPrivateKey.PubKey().SerializeCompressed(),
	)
	sparkSigReq := &pblrc20.SendSparkSignatureRequest{
		FinalTokenTransaction:      sparkTokenTransaction,
		OperatorSpecificSignatures: thisOperatorSpecificSignatures,
		OperatorSignatureData:      operatorSignatureData,
	}

	err = o.lrc20Client.SendSparkSignature(ctx, sparkSigReq)
	if err != nil {
		logging.GetLoggerFromContext(ctx).Error("Failed to send transaction to LRC20 node", "error", err)
		return fmt.Errorf("failed to send transaction to LRC20 node: %w", err)
	}
	return nil
}

func (o *TokenTransactionHandler) localSignAndCommitTransaction(
	ctx context.Context,
	foundOperatorSignatures *tokenpb.InputTtxoSignaturesPerOperator,
	finalTokenTransactionHash []byte,
	tokenTransaction *ent.TokenTransaction,
) (*tokeninternalpb.SignTokenTransactionFromCoordinationResponse, error) {
	operatorSpecificSignatures := convertTokenProtoSignaturesToOperatorSpecific(
		foundOperatorSignatures.TtxoSignatures,
		finalTokenTransactionHash,
		o.soConfig.IdentityPublicKey(),
	)
	h := NewInternalTokenTransactionHandler(o.soConfig, nil)
	sigBytes, err := h.SignAndPersistTokenTransaction(ctx, o.soConfig, tokenTransaction, finalTokenTransactionHash, operatorSpecificSignatures)
	if err != nil {
		return nil, err
	}
	// TODO: CNT-330 should only finalize after receiving all revocation keyshares
	if err := FinalizeTransferTransaction(ctx, tokenTransaction); err != nil {
		return nil, fmt.Errorf("failed to finalize transaction: %w", err)
	}
	return &tokeninternalpb.SignTokenTransactionFromCoordinationResponse{
		SparkOperatorSignature: sigBytes,
	}, nil
}

// regenerateStartResponseForDuplicateRequest handles the case where a Start() recall has been received for a
// partial token transaction which has already been started. This allows for simpler wallet SDK logic such that
// if a later SignTokenTransaction() call to one of the SOs failed- the wallet SDK can retry from the beginning
// and retrieve the original final token transaction which was started before signing among all parties.
// This does not allow for retrying a Start call that was incomplete due to a downstream error.  A repeat
// request for the same transaction that was not fully started will generate a fresh final token transaction
// with different revocation keys.
func (o TokenTransactionHandler) regenerateStartResponseForDuplicateRequest(
	ctx context.Context,
	config *so.Config,
	tokenTransaction *ent.TokenTransaction,
) (*sparkpb.StartTokenTransactionResponse, error) {
	logWithTransactionEnt(ctx, "Regenerating response for a duplicate StartTokenTransaction() Call", tokenTransaction, slog.LevelDebug)

	var invalidOutputs []string
	expectedCreatedOutputStatus := st.TokenOutputStatusCreatedStarted

	invalidOutputs = validateOutputs(tokenTransaction.Edges.CreatedOutput, expectedCreatedOutputStatus)
	if len(tokenTransaction.Edges.SpentOutput) > 0 {
		invalidOutputs = append(invalidOutputs, validateInputs(tokenTransaction.Edges.SpentOutput, st.TokenOutputStatusSpentStarted)...)
	}
	if len(invalidOutputs) > 0 {
		return nil, formatErrorWithTransactionEnt(
			fmt.Sprintf("%s: %s",
				errInvalidOutputs,
				strings.Join(invalidOutputs, "; ")),
			tokenTransaction, nil)
	}

	// Reconstruct the token transaction from the ent data.
	transaction, err := tokenTransaction.MarshalProto(config)
	if err != nil {
		return nil, formatErrorWithTransactionEnt(errFailedToMarshalTokenTransaction, tokenTransaction, err)
	}

	keyshareInfo, err := getStartTokenTransactionKeyshareInfo(config)
	if keyshareInfo == nil {
		return nil, formatErrorWithTransactionEnt(errFailedToGetKeyshareInfo, tokenTransaction, err)
	}

	logWithTransactionEnt(ctx, "Returning stored final token transaction in response to repeat start call",
		tokenTransaction, slog.LevelDebug)
	return &sparkpb.StartTokenTransactionResponse{
		FinalTokenTransaction: transaction,
		KeyshareInfo:          keyshareInfo,
	}, nil
}

// FinalizeTokenTransaction takes the revocation private keys for spent outputs and updates their status to finalized.
func (o TokenTransactionHandler) FinalizeTokenTransaction(
	ctx context.Context,
	config *so.Config,
	req *sparkpb.FinalizeTokenTransactionRequest,
) (*emptypb.Empty, error) {
	if err := authz.EnforceSessionIdentityPublicKeyMatches(ctx, o.authzConfig, req.IdentityPublicKey); err != nil {
		return nil, fmt.Errorf("%s: %w", errIdentityPublicKeyAuthFailed, err)
	}

	h := NewInternalTokenTransactionHandler(config, o.lrc20Client)
	return h.FinalizeTokenTransactionInternal(ctx, config, req)
}

// FreezeTokens freezes or unfreezes tokens on the LRC20 node.
func (o TokenTransactionHandler) FreezeTokens(
	ctx context.Context,
	req *sparkpb.FreezeTokensRequest,
) (*sparkpb.FreezeTokensResponse, error) {
	hardcodedMainnet := common.Mainnet
	freezePayloadHash, err := utils.HashFreezeTokensPayload(req.FreezeTokensPayload)
	if err != nil {
		return nil, fmt.Errorf("failed to hash freeze tokens payload: %w", err)
	}

	if err := utils.ValidateOwnershipSignature(
		req.IssuerSignature,
		freezePayloadHash,
		req.FreezeTokensPayload.TokenPublicKey,
	); err != nil {
		return nil, fmt.Errorf("invalid issuer signature to freeze token public key %x: %w", req.FreezeTokensPayload.TokenPublicKey, err)
	}

	// Check for existing freeze.
	activeFreezes, err := ent.GetActiveFreezes(ctx, [][]byte{req.FreezeTokensPayload.OwnerPublicKey}, req.FreezeTokensPayload.TokenPublicKey)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", errFailedToQueryTokenFreezeStatus, err)
	}
	if req.FreezeTokensPayload.ShouldUnfreeze {
		if len(activeFreezes) == 0 {
			return nil, fmt.Errorf("no active freezes found to thaw")
		}
		if len(activeFreezes) > 1 {
			return nil, fmt.Errorf("%s", errMultipleActiveFreezes)
		}
		err = ent.ThawActiveFreeze(ctx, activeFreezes[0].ID, req.FreezeTokensPayload.IssuerProvidedTimestamp)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", errFailedToUpdateTokenFreeze, err)
		}
	} else { // Freeze
		if len(activeFreezes) > 0 {
			return nil, fmt.Errorf("%s", errAlreadyFrozen)
		}
		err = ent.ActivateFreeze(ctx,
			req.FreezeTokensPayload.OwnerPublicKey,
			req.FreezeTokensPayload.TokenPublicKey,
			req.IssuerSignature,
			req.FreezeTokensPayload.IssuerProvidedTimestamp,
		)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", errFailedToCreateTokenFreeze, err)
		}
	}

	// Collect information about the frozen outputs.
	outputIDs, totalAmount, err := ent.GetOwnedTokenOutputStats(ctx, [][]byte{req.FreezeTokensPayload.OwnerPublicKey}, req.FreezeTokensPayload.TokenPublicKey, hardcodedMainnet)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", errFailedToGetOwnedOutputStats, err)
	}

	err = o.FreezeTokensOnLRC20Node(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", errFailedToSendToLRC20Node, err)
	}

	return &sparkpb.FreezeTokensResponse{
		ImpactedOutputIds:   outputIDs,
		ImpactedTokenAmount: totalAmount.Bytes(),
	}, nil
}

// FreezeTokensOnLRC20Node freezes or unfreezes tokens on the LRC20 node.
func (o TokenTransactionHandler) FreezeTokensOnLRC20Node(
	ctx context.Context,
	req *sparkpb.FreezeTokensRequest,
) error {
	return o.lrc20Client.FreezeTokens(ctx, req)
}

// QueryTokenTransactions returns SO provided data about specific token transactions along with their status.
// Allows caller to specify data to be returned related to:
// a) transactions associated with a particular set of output ids
// b) transactions associated with a particular set of transaction hashes
// c) all transactions associated with a particular token public key
func (o TokenTransactionHandler) QueryTokenTransactions(ctx context.Context, config *so.Config, req *sparkpb.QueryTokenTransactionsRequest) (*sparkpb.QueryTokenTransactionsResponse, error) {
	db := ent.GetDbFromContext(ctx)

	// Start with a base query for token transactions
	baseQuery := db.TokenTransaction.Query()

	// Apply filters based on request parameters
	if len(req.OutputIds) > 0 {
		// Convert string IDs to UUIDs
		outputUUIDs := make([]uuid.UUID, 0, len(req.OutputIds))
		for _, idStr := range req.OutputIds {
			id, err := uuid.Parse(idStr)
			if err != nil {
				return nil, fmt.Errorf("invalid output ID format: %w", err)
			}
			outputUUIDs = append(outputUUIDs, id)
		}

		// Find transactions that created or spent these outputs
		baseQuery = baseQuery.Where(
			tokentransaction.Or(
				tokentransaction.HasCreatedOutputWith(tokenoutput.IDIn(outputUUIDs...)),
				tokentransaction.HasSpentOutputWith(tokenoutput.IDIn(outputUUIDs...)),
			),
		)
	}

	if len(req.TokenTransactionHashes) > 0 {
		baseQuery = baseQuery.Where(tokentransaction.FinalizedTokenTransactionHashIn(req.TokenTransactionHashes...))
	}

	if len(req.TokenPublicKeys) > 0 {
		baseQuery = baseQuery.Where(
			tokentransaction.Or(
				tokentransaction.HasCreatedOutputWith(tokenoutput.TokenPublicKeyIn(req.TokenPublicKeys...)),
				tokentransaction.HasSpentOutputWith(tokenoutput.TokenPublicKeyIn(req.TokenPublicKeys...)),
			),
		)
	}

	// Apply sorting, limit and offset
	query := baseQuery.Order(ent.Desc(tokentransaction.FieldUpdateTime))

	if req.Limit > 100 || req.Limit == 0 {
		req.Limit = 100
	}
	query = query.Limit(int(req.Limit))

	if req.Offset > 0 {
		query = query.Offset(int(req.Offset))
	}

	// This join respects the query limitations provided above and should only load the necessary relations.
	query = query.
		WithCreatedOutput().
		WithSpentOutput(func(slq *ent.TokenOutputQuery) {
			slq.WithOutputCreatedTokenTransaction()
		}).WithMint()

	// Execute the query
	transactions, err := query.All(ctx)
	if err != nil {
		return nil, fmt.Errorf("unable to query token transactions: %w", err)
	}

	// Convert to response protos
	transactionsWithStatus := make([]*sparkpb.TokenTransactionWithStatus, 0, len(transactions))
	for _, transaction := range transactions {
		// Determine transaction status based on output statuses.
		status := convertTokenTransactionStatus(transaction.Status)

		// Reconstruct the token transaction from the ent data.
		transactionProto, err := transaction.MarshalProto(config)
		if err != nil {
			return nil, formatErrorWithTransactionEnt(errFailedToMarshalTokenTransaction, transaction, err)
		}
		transactionWithStatus := &sparkpb.TokenTransactionWithStatus{
			TokenTransaction: transactionProto,
			Status:           status,
		}
		if status == sparkpb.TokenTransactionStatus_TOKEN_TRANSACTION_FINALIZED {
			spentTokenOutputsMetadata := make([]*sparkpb.SpentTokenOutputMetadata, 0, len(transaction.Edges.SpentOutput))

			for _, spentOutput := range transaction.Edges.SpentOutput {
				spentTokenOutputsMetadata = append(spentTokenOutputsMetadata, &sparkpb.SpentTokenOutputMetadata{
					OutputId:         spentOutput.ID.String(),
					RevocationSecret: spentOutput.SpentRevocationSecret,
				})
			}
			transactionWithStatus.ConfirmationMetadata = &sparkpb.TokenTransactionConfirmationMetadata{
				SpentTokenOutputsMetadata: spentTokenOutputsMetadata,
			}
		}
		transactionsWithStatus = append(transactionsWithStatus, transactionWithStatus)
	}

	// Calculate next offset
	var nextOffset int64
	if len(transactions) == int(req.Limit) {
		nextOffset = req.Offset + int64(len(transactions))
	} else {
		nextOffset = -1
	}

	return &sparkpb.QueryTokenTransactionsResponse{
		TokenTransactionsWithStatus: transactionsWithStatus,
		Offset:                      nextOffset,
	}, nil
}

func (o TokenTransactionHandler) QueryTokenOutputs(
	ctx context.Context,
	config *so.Config,
	req *sparkpb.QueryTokenOutputsRequest,
) (*sparkpb.QueryTokenOutputsResponse, error) {
	logger := logging.GetLoggerFromContext(ctx)

	allSelection := helper.OperatorSelection{Option: helper.OperatorSelectionOptionAll}
	responses, err := helper.ExecuteTaskWithAllOperators(ctx, config, &allSelection,
		func(ctx context.Context, operator *so.SigningOperator) (map[string]*sparkpb.OutputWithPreviousTransactionData, error) {
			conn, err := operator.NewGRPCConnection()
			if err != nil {
				return nil, fmt.Errorf("failed to connect to operator %s: %w", operator.Identifier, err)
			}
			defer conn.Close()

			client := pbinternal.NewSparkInternalServiceClient(conn)
			availableOutputs, err := client.QueryTokenOutputsInternal(ctx, req)
			if err != nil {
				return nil, fmt.Errorf("failed to query token outputs from operator %s: %w", operator.Identifier, err)
			}
			spendableOutputMap := make(map[string]*sparkpb.OutputWithPreviousTransactionData)
			for _, output := range availableOutputs.OutputsWithPreviousTransactionData {
				spendableOutputMap[*output.Output.Id] = output
			}
			return spendableOutputMap, nil
		},
	)
	if err != nil {
		logger.Info("failed to query token outputs from operators", "error", err)
		return nil, fmt.Errorf("failed to query token outputs from operators: %w", err)
	}

	// Only return token outputs to the wallet that ALL SOs agree are spendable.
	//
	// If a TTXO is partially signed, the spending transaction will be cancelled once it expires to return the TTXO to the wallet.
	spendableOutputs := make([]*sparkpb.OutputWithPreviousTransactionData, 0)
	countSpendableOperatorsForOutputID := make(map[string]int)

	requiredSpendableOperators := len(config.GetSigningOperatorList())
	for _, spendableOutputMap := range responses {
		for outputID, spendableOutput := range spendableOutputMap {
			countSpendableOperatorsForOutputID[outputID]++
			if countSpendableOperatorsForOutputID[outputID] == requiredSpendableOperators {
				spendableOutputs = append(spendableOutputs, spendableOutput)
			}
		}
	}

	for outputID, countSpendableOperators := range countSpendableOperatorsForOutputID {
		if countSpendableOperators < requiredSpendableOperators {
			logger.Warn("token output not spendable in all operators",
				"outputID", outputID,
				"countSpendableOperators", countSpendableOperators,
			)
		}
	}

	return &sparkpb.QueryTokenOutputsResponse{
		OutputsWithPreviousTransactionData: spendableOutputs,
	}, nil
}

// getRevocationKeysharesForTokenTransaction retrieves the revocation keyshares for a token transaction
func (o TokenTransactionHandler) getRevocationKeysharesForTokenTransaction(ctx context.Context, tokenTransaction *ent.TokenTransaction) ([]*sparkpb.KeyshareWithIndex, error) {
	spentOutputs := tokenTransaction.Edges.SpentOutput
	revocationKeyshares := make([]*sparkpb.KeyshareWithIndex, len(spentOutputs))
	for i, output := range spentOutputs {
		keyshare, err := output.QueryRevocationKeyshare().Only(ctx)
		if err != nil {
			return nil, formatErrorWithTransactionEnt(errFailedToGetKeyshareForOutput, tokenTransaction, err)
		}
		// Validate that the keyshare's public key is as expected.
		if !bytes.Equal(keyshare.PublicKey, output.WithdrawRevocationCommitment) {
			return nil, formatErrorWithTransactionEnt(
				fmt.Sprintf("%s: %x does not match %x",
					errRevocationKeyMismatch, keyshare.PublicKey, output.WithdrawRevocationCommitment),
				tokenTransaction, nil)
		}

		revocationKeyshares[i] = &sparkpb.KeyshareWithIndex{
			InputIndex: uint32(output.SpentTransactionInputVout),
			Keyshare:   keyshare.SecretShare,
		}
	}
	// Sort spent output keyshares by their index to ensure a consistent response
	sort.Slice(revocationKeyshares, func(i, j int) bool {
		return revocationKeyshares[i].InputIndex < revocationKeyshares[j].InputIndex
	})

	return revocationKeyshares, nil
}

// convertTokenTransactionStatus converts from st.TokenTransactionStatus to pb.TokenTransactionStatus
func convertTokenTransactionStatus(status st.TokenTransactionStatus) sparkpb.TokenTransactionStatus {
	switch status {
	case st.TokenTransactionStatusStarted:
		return sparkpb.TokenTransactionStatus_TOKEN_TRANSACTION_STARTED
	case st.TokenTransactionStatusStartedCancelled:
		return sparkpb.TokenTransactionStatus_TOKEN_TRANSACTION_STARTED_CANCELLED
	case st.TokenTransactionStatusSigned:
		return sparkpb.TokenTransactionStatus_TOKEN_TRANSACTION_SIGNED
	case st.TokenTransactionStatusSignedCancelled:
		return sparkpb.TokenTransactionStatus_TOKEN_TRANSACTION_SIGNED_CANCELLED
	case st.TokenTransactionStatusFinalized:
		return sparkpb.TokenTransactionStatus_TOKEN_TRANSACTION_FINALIZED
	default:
		return sparkpb.TokenTransactionStatus_TOKEN_TRANSACTION_UNKNOWN
	}
}

func logWithTransactionEnt(ctx context.Context, msg string, tokenTransaction *ent.TokenTransaction, level slog.Level) {
	logger := logging.GetLoggerFromContext(ctx)

	attrs := []any{
		"transaction_uuid", tokenTransaction.ID.String(),
		"transaction_hash", hex.EncodeToString(tokenTransaction.FinalizedTokenTransactionHash),
	}

	logger.Log(ctx, level, msg, attrs...)
}

func formatErrorWithTransactionEnt(msg string, tokenTransaction *ent.TokenTransaction, err error) error {
	return fmt.Errorf("%s (uuid: %s, hash: %x): %w",
		msg,
		tokenTransaction.ID.String(),
		tokenTransaction.FinalizedTokenTransactionHash,
		err)
}

func formatErrorWithTransactionProto(msg string, tokenTransaction *sparkpb.TokenTransaction, err error) error {
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

// verifyOperatorSignatures verifies the signatures from each operator for a token transaction.
func verifyOperatorSignatures(
	signatures map[string][]byte,
	operatorMap map[string]*so.SigningOperator,
	finalTokenTransactionHash []byte,
) error {
	validateOperatorSignature := func(operatorID string, sigBytes []byte) error {
		operator, ok := operatorMap[operatorID]
		if !ok {
			return fmt.Errorf("operator %s not found in operator map", operatorID)
		}

		operatorPubKey, err := secp256k1.ParsePubKey(operator.IdentityPublicKey)
		if err != nil {
			return fmt.Errorf("failed to parse operator public key for operator %s: %w", operatorID, err)
		}

		operatorSig, err := ecdsa.ParseDERSignature(sigBytes)
		if err != nil {
			return fmt.Errorf("failed to parse operator signature for operator %s: %w", operatorID, err)
		}

		if !operatorSig.Verify(finalTokenTransactionHash, operatorPubKey) {
			return fmt.Errorf("invalid signature from operator %s", operatorID)
		}

		return nil
	}

	var errors []string
	for operatorID, sigBytes := range signatures {
		if err := validateOperatorSignature(operatorID, sigBytes); err != nil {
			errors = append(errors, err.Error())
		}
	}

	if len(errors) > 0 {
		return fmt.Errorf("signature verification failed: %s", strings.Join(errors, "; "))
	}

	return nil
}

// convertTokenProtoSignaturesToOperatorSpecific converts token proto signatures to OperatorSpecificOwnerSignature format
func convertTokenProtoSignaturesToOperatorSpecific(
	ttxoSignatures []*tokenpb.SignatureWithIndex,
	finalTokenTransactionHash []byte,
	operatorIdentityPublicKey []byte,
) []*sparkpb.OperatorSpecificOwnerSignature {
	operatorSpecificSignatures := make([]*sparkpb.OperatorSpecificOwnerSignature, 0, len(ttxoSignatures))
	for _, operatorSignatures := range ttxoSignatures {
		operatorSpecificSignatures = append(operatorSpecificSignatures, &sparkpb.OperatorSpecificOwnerSignature{
			OwnerSignature: protoconverter.SparkSignatureWithIndexFromTokenProto(operatorSignatures),
			Payload: &sparkpb.OperatorSpecificTokenTransactionSignablePayload{
				FinalTokenTransactionHash: finalTokenTransactionHash,
				OperatorIdentityPublicKey: operatorIdentityPublicKey,
			},
		})
	}
	return operatorSpecificSignatures
}
