package grpc

import (
	"context"
	"fmt"

	sparkpb "github.com/lightsparkdev/spark/proto/spark"
	tokeninternalpb "github.com/lightsparkdev/spark/proto/spark_token_internal"
	"github.com/lightsparkdev/spark/so"
	"github.com/lightsparkdev/spark/so/ent"
	"github.com/lightsparkdev/spark/so/handler"
	"github.com/lightsparkdev/spark/so/protoconverter"
)

type SparkTokenInternalServer struct {
	tokeninternalpb.UnimplementedSparkTokenInternalServiceServer
	soConfig *so.Config
	db       *ent.Client
}

func NewSparkTokenInternalServer(soConfig *so.Config, db *ent.Client) *SparkTokenInternalServer {
	return &SparkTokenInternalServer{soConfig: soConfig, db: db}
}

func (s *SparkTokenInternalServer) SignTokenTransactionFromCoordination(
	ctx context.Context,
	req *tokeninternalpb.SignTokenTransactionFromCoordinationRequest,
) (*tokeninternalpb.SignTokenTransactionFromCoordinationResponse, error) {
	tx, err := ent.FetchAndLockTokenTransactionData(ctx, req.FinalTokenTransaction)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch transaction: %w", err)
	}

	// Convert proto signatures to []*sparkpb.OperatorSpecificOwnerSignature
	operatorSpecificSignatures := make([]*sparkpb.OperatorSpecificOwnerSignature, 0)
	for _, sigWithIndex := range req.InputTtxoSignaturesPerOperator.TtxoSignatures {
		operatorSpecificSignatures = append(operatorSpecificSignatures, &sparkpb.OperatorSpecificOwnerSignature{
			OwnerSignature: protoconverter.SparkSignatureWithIndexFromTokenProto(sigWithIndex),
			Payload: &sparkpb.OperatorSpecificTokenTransactionSignablePayload{
				FinalTokenTransactionHash: req.FinalTokenTransactionHash,
				OperatorIdentityPublicKey: req.InputTtxoSignaturesPerOperator.OperatorIdentityPublicKey,
			},
		})
	}

	h := handler.NewInternalTokenTransactionHandler(s.soConfig, nil)
	sigBytes, err := h.SignAndPersistTokenTransaction(ctx, s.soConfig, tx, req.FinalTokenTransactionHash, operatorSpecificSignatures)
	if err != nil {
		return nil, err
	}

	// TODO: CNT-330 should only finalize after receiving all revocation keyshares
	if err := handler.FinalizeTransferTransaction(ctx, tx); err != nil {
		return nil, fmt.Errorf("failed to finalize transaction: %w", err)
	}

	return &tokeninternalpb.SignTokenTransactionFromCoordinationResponse{
		SparkOperatorSignature: sigBytes,
	}, nil
}
