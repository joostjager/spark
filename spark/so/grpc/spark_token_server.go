package grpc

import (
	"bytes"
	"context"
	"time"

	"github.com/google/uuid"
	sparkpb "github.com/lightsparkdev/spark/proto/spark"
	tokenpb "github.com/lightsparkdev/spark/proto/spark_token"
	"github.com/lightsparkdev/spark/so"
	"github.com/lightsparkdev/spark/so/authz"
	"github.com/lightsparkdev/spark/so/ent"
	"github.com/lightsparkdev/spark/so/errors"
	"github.com/lightsparkdev/spark/so/handler"
	"github.com/lightsparkdev/spark/so/lrc20"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type SparkTokenServer struct {
	tokenpb.UnimplementedSparkTokenServiceServer
	authzConfig authz.Config
	soConfig    *so.Config
	db          *ent.Client
	lrc20Client *lrc20.Client
}

func NewSparkTokenServer(authzConfig authz.Config, soConfig *so.Config, db *ent.Client, lrc20Client *lrc20.Client) *SparkTokenServer {
	return &SparkTokenServer{
		authzConfig: authzConfig,
		soConfig:    soConfig,
		db:          db,
		lrc20Client: lrc20Client,
	}
}

func (s *SparkTokenServer) StartTransaction(
	_ context.Context,
	req *tokenpb.StartTransactionRequest,
) (*tokenpb.StartTransactionResponse, error) {
	ownerIdentifiers := make([]string, 0, len(s.soConfig.SigningOperatorMap))
	for id := range s.soConfig.SigningOperatorMap {
		ownerIdentifiers = append(ownerIdentifiers, id)
	}

	tx := &tokenpb.TokenTransaction{
		TokenInputs: &tokenpb.TokenTransaction_MintInput{
			MintInput: &tokenpb.TokenMintInput{
				IssuerPublicKey:         s.soConfig.IdentityPublicKey(),
				IssuerProvidedTimestamp: uint64(time.Now().Unix()),
			},
		},
		TokenOutputs: []*tokenpb.TokenOutput{
			{
				Id:                            stringPtr(uuid.New().String()),
				OwnerPublicKey:                s.soConfig.IdentityPublicKey(),
				RevocationCommitment:          bytes.Repeat([]byte{0}, 33),
				WithdrawBondSats:              uint64Ptr(10000),
				WithdrawRelativeBlockLocktime: uint64Ptr(1000),
				TokenPublicKey:                s.soConfig.IdentityPublicKey(),
				TokenAmount:                   []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
			},
		},
		SparkOperatorIdentityPublicKeys: [][]byte{
			s.soConfig.SigningOperatorMap["0000000000000000000000000000000000000000000000000000000000000001"].IdentityPublicKey,
			s.soConfig.SigningOperatorMap["0000000000000000000000000000000000000000000000000000000000000002"].IdentityPublicKey,
		},
		ExpiryTime: timestamppb.New(time.Now().Add(time.Duration(req.ValidityDurationSeconds) * time.Second)),
		Network:    sparkpb.Network_MAINNET,
	}

	return &tokenpb.StartTransactionResponse{
		FinalTokenTransaction: tx,
		KeyshareInfo: &sparkpb.SigningKeyshare{
			OwnerIdentifiers: ownerIdentifiers,
			Threshold:        uint32(s.soConfig.Threshold),
			PublicKey:        s.soConfig.IdentityPublicKey(),
		},
	}, nil
}

func stringPtr(s string) *string { return &s }
func uint64Ptr(u uint64) *uint64 { return &u }

// This RPC is called by the client to initiate the coordinated signing process.
func (s *SparkTokenServer) CommitTransaction(
	ctx context.Context,
	req *tokenpb.CommitTransactionRequest,
) (*tokenpb.CommitTransactionResponse, error) {
	handler := handler.NewTokenTransactionHandler(s.authzConfig, s.soConfig, s.db, s.lrc20Client)
	return errors.WrapWithGRPCError(handler.CommitTransaction(ctx, req))
}
