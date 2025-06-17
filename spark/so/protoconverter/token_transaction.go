package protoconverter

import (
	"fmt"

	pb "github.com/lightsparkdev/spark/proto/spark"
	tokenpb "github.com/lightsparkdev/spark/proto/spark_token"
)

// SparkTokenTransactionFromTokenProto converts a spark_token.TokenTransaction to a spark.TokenTransaction.
func SparkTokenTransactionFromTokenProto(tokenTx *tokenpb.TokenTransaction) (*pb.TokenTransaction, error) {
	if tokenTx == nil {
		return nil, fmt.Errorf("input token transaction cannot be nil")
	}

	tokenOutputs := make([]*pb.TokenOutput, len(tokenTx.TokenOutputs))
	for i, o := range tokenTx.TokenOutputs {
		tokenOutputs[i] = &pb.TokenOutput{
			Id:                            o.Id,
			OwnerPublicKey:                o.OwnerPublicKey,
			RevocationCommitment:          o.RevocationCommitment,
			WithdrawBondSats:              o.WithdrawBondSats,
			WithdrawRelativeBlockLocktime: o.WithdrawRelativeBlockLocktime,
			TokenPublicKey:                o.TokenPublicKey,
			TokenAmount:                   o.TokenAmount,
		}
	}

	transaction := &pb.TokenTransaction{
		TokenOutputs:                    tokenOutputs,
		SparkOperatorIdentityPublicKeys: tokenTx.SparkOperatorIdentityPublicKeys,
		Network:                         tokenTx.Network,
		// Note: ExpiryTime and Version fields are omitted as they do not exist in pb.TokenTransaction.
	}

	switch x := tokenTx.TokenInputs.(type) {
	case *tokenpb.TokenTransaction_MintInput:
		if x.MintInput == nil {
			return nil, fmt.Errorf("mint_input is nil")
		}
		transaction.TokenInputs = &pb.TokenTransaction_MintInput{
			MintInput: &pb.TokenMintInput{
				IssuerPublicKey:         x.MintInput.IssuerPublicKey,
				IssuerProvidedTimestamp: x.MintInput.IssuerProvidedTimestamp,
			},
		}
	case *tokenpb.TokenTransaction_TransferInput:
		if x.TransferInput == nil {
			return nil, fmt.Errorf("transfer_input is nil")
		}
		outputsToSpend := make([]*pb.TokenOutputToSpend, len(x.TransferInput.OutputsToSpend))
		for i, o := range x.TransferInput.OutputsToSpend {
			outputsToSpend[i] = &pb.TokenOutputToSpend{
				PrevTokenTransactionHash: o.PrevTokenTransactionHash,
				PrevTokenTransactionVout: o.PrevTokenTransactionVout,
			}
		}
		transaction.TokenInputs = &pb.TokenTransaction_TransferInput{
			TransferInput: &pb.TokenTransferInput{
				OutputsToSpend: outputsToSpend,
			},
		}
	default:
		return nil, fmt.Errorf("unknown token_inputs type")
	}

	return transaction, nil
}

// TokenProtoFromSparkTokenTransaction converts a spark TokenTransaction proto to a spark_token TokenTransaction proto.
func TokenProtoFromSparkTokenTransaction(sparkTx *pb.TokenTransaction) (*tokenpb.TokenTransaction, error) {
	if sparkTx == nil {
		return nil, fmt.Errorf("input spark token transaction cannot be nil")
	}

	tokenOutputs := make([]*tokenpb.TokenOutput, len(sparkTx.TokenOutputs))
	for i, o := range sparkTx.TokenOutputs {
		tokenOutputs[i] = &tokenpb.TokenOutput{
			Id:                            o.Id,
			OwnerPublicKey:                o.OwnerPublicKey,
			RevocationCommitment:          o.RevocationCommitment,
			WithdrawBondSats:              o.WithdrawBondSats,
			WithdrawRelativeBlockLocktime: o.WithdrawRelativeBlockLocktime,
			TokenPublicKey:                o.TokenPublicKey,
			TokenAmount:                   o.TokenAmount,
		}
	}

	tokenTx := &tokenpb.TokenTransaction{
		TokenOutputs:                    tokenOutputs,
		SparkOperatorIdentityPublicKeys: sparkTx.SparkOperatorIdentityPublicKeys,
		Network:                         sparkTx.Network,
	}

	switch x := sparkTx.TokenInputs.(type) {
	case *pb.TokenTransaction_MintInput:
		if x.MintInput == nil {
			return nil, fmt.Errorf("mint_input is nil")
		}
		tokenTx.TokenInputs = &tokenpb.TokenTransaction_MintInput{
			MintInput: &tokenpb.TokenMintInput{
				IssuerPublicKey:         x.MintInput.IssuerPublicKey,
				IssuerProvidedTimestamp: x.MintInput.IssuerProvidedTimestamp,
			},
		}
	case *pb.TokenTransaction_TransferInput:
		if x.TransferInput == nil {
			return nil, fmt.Errorf("transfer_input is nil")
		}
		outputsToSpend := make([]*tokenpb.TokenOutputToSpend, len(x.TransferInput.OutputsToSpend))
		for i, o := range x.TransferInput.OutputsToSpend {
			outputsToSpend[i] = &tokenpb.TokenOutputToSpend{
				PrevTokenTransactionHash: o.PrevTokenTransactionHash,
				PrevTokenTransactionVout: o.PrevTokenTransactionVout,
			}
		}
		tokenTx.TokenInputs = &tokenpb.TokenTransaction_TransferInput{
			TransferInput: &tokenpb.TokenTransferInput{
				OutputsToSpend: outputsToSpend,
			},
		}
	default:
		return nil, fmt.Errorf("unknown token_inputs type")
	}

	return tokenTx, nil
}
