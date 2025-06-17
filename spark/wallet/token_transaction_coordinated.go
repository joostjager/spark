package wallet

import (
	"context"
	"fmt"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/lightsparkdev/spark/common"
	pb "github.com/lightsparkdev/spark/proto/spark"
	pbtoken "github.com/lightsparkdev/spark/proto/spark_token"
	"github.com/lightsparkdev/spark/so/protoconverter"
	"github.com/lightsparkdev/spark/so/utils"
	"google.golang.org/grpc"
)

// StartTransactionCoordinated calls the start_transaction endpoint on the SparkTokenService.
func StartTransactionCoordinated(
	ctx context.Context,
	config *Config,
	req *pbtoken.StartTransactionRequest,
	opts ...grpc.CallOption,
) (*pbtoken.StartTransactionResponse, error) {
	sparkConn, err := common.NewGRPCConnectionWithTestTLS(config.CoodinatorAddress(), nil)
	if err != nil {
		return nil, err
	}
	defer sparkConn.Close()

	client := pbtoken.NewSparkTokenServiceClient(sparkConn)
	return client.StartTransaction(ctx, req, opts...)
}

// CommitTransactionCoordinated calls the commit_transaction endpoint on the SparkTokenService.
func CommitTransactionCoordinated(
	ctx context.Context,
	config *Config,
	req *pbtoken.CommitTransactionRequest,
	opts ...grpc.CallOption,
) (*pbtoken.CommitTransactionResponse, error) {
	sparkConn, err := common.NewGRPCConnectionWithTestTLS(config.CoodinatorAddress(), nil)
	if err != nil {
		return nil, err
	}
	defer sparkConn.Close()

	client := pbtoken.NewSparkTokenServiceClient(sparkConn)
	operatorToken, err := AuthenticateWithConnection(ctx, config, sparkConn)
	if err != nil {
		return nil, fmt.Errorf("failed to authenticate with operator %s: %v", config.CoodinatorIdentifier, err)
	}
	operatorCtx := ContextWithToken(ctx, operatorToken)
	return client.CommitTransaction(operatorCtx, req, opts...)
}

// BroadcastCoordinatedTokenTransfer orchestrates a coordinated token transfer using the new flow:
// TODO CNT-326: Use new tokenpb StartTokenTransaction
// 1. StartTokenTransaction (sparkpb) - creates the final transaction with revocation commitments
// 2. CommitTransaction (tokenpb) - signs and commits the transaction
func BroadcastCoordinatedTokenTransfer(
	ctx context.Context,
	config *Config,
	tokenTransaction *pbtoken.TokenTransaction,
	ownerPrivateKeys []*secp256k1.PrivateKey,
) (*pbtoken.TokenTransaction, error) {
	// Convert from tokenpb to sparkpb for internal processing
	sparkTx, err := protoconverter.SparkTokenTransactionFromTokenProto(tokenTransaction)
	if err != nil {
		return nil, fmt.Errorf("failed to convert token transaction: %w", err)
	}

	// Step 1: Start the transaction using the regular Spark API (sparkpb)
	startResp, _, finalTxHash, err := StartTokenTransaction(
		ctx,
		config,
		sparkTx,
		ownerPrivateKeys,
		nil,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to start token transaction: %w", err)
	}

	// Convert the response back to tokenpb for the coordinated API
	coordinatedTx, err := protoconverter.TokenProtoFromSparkTokenTransaction(startResp.FinalTokenTransaction)
	if err != nil {
		return nil, fmt.Errorf("failed to convert final token transaction: %w", err)
	}

	// Step 2: Sign and commit using the coordinated API (tokenpb)
	operatorSignatures, err := createOperatorSpecificSignatures(
		config,
		ownerPrivateKeys,
		finalTxHash,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create operator-specific signatures: %w", err)
	}

	signReq := &pbtoken.CommitTransactionRequest{
		FinalTokenTransaction:          coordinatedTx,
		FinalTokenTransactionHash:      finalTxHash,
		InputTtxoSignaturesPerOperator: operatorSignatures,
		OwnerIdentityPublicKey:         config.IdentityPublicKey(),
	}

	_, err = CommitTransactionCoordinated(ctx, config, signReq)
	if err != nil {
		return nil, fmt.Errorf("failed to sign and commit transaction: %w", err)
	}

	return coordinatedTx, nil
}

func createOperatorSpecificSignatures(
	config *Config,
	ownerPrivateKeys []*secp256k1.PrivateKey,
	finalTxHash []byte,
) ([]*pbtoken.InputTtxoSignaturesPerOperator, error) {
	var operatorSignatures []*pbtoken.InputTtxoSignaturesPerOperator

	for _, operator := range config.SigningOperators {
		var ttxoSignatures []*pbtoken.SignatureWithIndex

		for i, privKey := range ownerPrivateKeys {
			payload := &pb.OperatorSpecificTokenTransactionSignablePayload{
				FinalTokenTransactionHash: finalTxHash,
				OperatorIdentityPublicKey: operator.IdentityPublicKey,
			}
			payloadHash, err := utils.HashOperatorSpecificTokenTransactionSignablePayload(payload)
			if err != nil {
				return nil, fmt.Errorf("Error while hashing operator-specific payload: %v", err)
			}
			sig, err := createTokenTransactionSignature(config, privKey, payloadHash)
			if err != nil {
				return nil, fmt.Errorf("Error while creating operator-specific signature: %v", err)
			}

			ttxoSignatures = append(ttxoSignatures, &pbtoken.SignatureWithIndex{
				InputIndex: uint32(i),
				Signature:  sig,
			})
		}

		operatorSignatures = append(operatorSignatures, &pbtoken.InputTtxoSignaturesPerOperator{
			TtxoSignatures:            ttxoSignatures,
			OperatorIdentityPublicKey: operator.IdentityPublicKey,
		})
	}

	return operatorSignatures, nil
}
