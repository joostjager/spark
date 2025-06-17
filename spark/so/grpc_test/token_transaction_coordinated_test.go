package grpctest

import (
	"bytes"
	"context"
	"math/big"
	"testing"
	"time"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/google/uuid"
	"github.com/lightsparkdev/spark/common"
	sparkpb "github.com/lightsparkdev/spark/proto/spark"
	tokenpb "github.com/lightsparkdev/spark/proto/spark_token"
	"github.com/lightsparkdev/spark/so/dkg"
	"github.com/lightsparkdev/spark/so/protoconverter"
	"github.com/lightsparkdev/spark/so/utils"
	testutil "github.com/lightsparkdev/spark/test_util"
	"github.com/lightsparkdev/spark/wallet"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"
)

var signatureTypeTestCases = []struct {
	name                 string
	useSchnorrSignatures bool
}{
	{
		name:                 "ECDSA signatures",
		useSchnorrSignatures: false,
	},
	{
		name:                 "Schnorr signatures",
		useSchnorrSignatures: true,
	},
}

func stringPtr(s string) *string { return &s }
func uint64Ptr(u uint64) *uint64 { return &u }

func TestStartTransactionCoordinatedDummyEndpoint(t *testing.T) {
	config, err := testutil.TestWalletConfig()
	require.NoError(t, err)

	req := &tokenpb.StartTransactionRequest{
		IdentityPublicKey: config.IdentityPublicKey(),
		PartialTokenTransaction: &tokenpb.TokenTransaction{
			TokenInputs: &tokenpb.TokenTransaction_MintInput{
				MintInput: &tokenpb.TokenMintInput{
					IssuerPublicKey:         config.IdentityPublicKey(),
					IssuerProvidedTimestamp: uint64(time.Now().Unix()),
				},
			},
			TokenOutputs: []*tokenpb.TokenOutput{
				{
					Id:                            stringPtr(uuid.New().String()),
					OwnerPublicKey:                config.IdentityPublicKey(),
					RevocationCommitment:          bytes.Repeat([]byte{0}, 33),
					WithdrawBondSats:              uint64Ptr(10000),
					WithdrawRelativeBlockLocktime: uint64Ptr(1000),
					TokenPublicKey:                config.IdentityPublicKey(),
					TokenAmount:                   []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
				},
			},
			SparkOperatorIdentityPublicKeys: [][]byte{
				config.SigningOperators["0000000000000000000000000000000000000000000000000000000000000001"].IdentityPublicKey,
				config.SigningOperators["0000000000000000000000000000000000000000000000000000000000000002"].IdentityPublicKey,
			},
			ExpiryTime: timestamppb.New(time.Now().Add(60 * time.Second)),
			Network:    sparkpb.Network_REGTEST,
		},
		PartialTokenTransactionOwnerSignatures: []*tokenpb.SignatureWithIndex{
			{
				Signature:  bytes.Repeat([]byte{0}, 64),
				InputIndex: 0,
			},
		},
		ValidityDurationSeconds: 60,
	}

	resp, err := wallet.StartTransactionCoordinated(context.Background(), config, req)
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.NotNil(t, resp.FinalTokenTransaction)
	require.NotNil(t, resp.KeyshareInfo)
}

func TestStartTransactionCoordinatedMainnetFails(t *testing.T) {
	config, err := testutil.TestWalletConfigWithIdentityKey(*staticLocalIssuerKey.IdentityPrivateKey())
	require.NoError(t, err, "failed to create wallet config")

	tokenPrivKey := config.IdentityPrivateKey
	tokenIdentityPubKeyBytes := tokenPrivKey.PubKey().SerializeCompressed()

	issueTokenTransaction, _, _, err := createTestTokenMintTransactionTokenPb(config, tokenIdentityPubKeyBytes)
	require.NoError(t, err, "failed to create test token issuance transaction")

	issueTokenTransaction.Network = sparkpb.Network_MAINNET

	_, err = wallet.BroadcastCoordinatedTokenTransfer(
		context.Background(), config, issueTokenTransaction,
		[]*secp256k1.PrivateKey{&tokenPrivKey},
	)
	require.Error(t, err, "Mainnet transactions should fail")
}

func TestCoordinatedTokenMint(t *testing.T) {
	for _, tc := range signatureTypeTestCases {
		t.Run(tc.name, func(t *testing.T) {
			config, err := testutil.TestWalletConfigWithIdentityKey(*staticLocalIssuerKey.IdentityPrivateKey())
			require.NoError(t, err, "failed to create wallet config")

			tokenPrivKey := config.IdentityPrivateKey
			tokenIdentityPubKeyBytes := tokenPrivKey.PubKey().SerializeCompressed()

			issueTokenTransaction, userOutput1PrivKey, userOutput2PrivKey, err := createTestTokenMintTransactionTokenPb(config, tokenIdentityPubKeyBytes)
			require.NoError(t, err, "failed to create test token issuance transaction")

			finalIssueTokenTransaction, err := wallet.BroadcastCoordinatedTokenTransfer(
				context.Background(), config, issueTokenTransaction,
				[]*secp256k1.PrivateKey{&tokenPrivKey},
			)
			require.NoError(t, err, "failed to broadcast issuance token transaction")

			require.Equal(t, 2, len(finalIssueTokenTransaction.TokenOutputs), "expected 2 created outputs in mint transaction")
			userOneConfig, err := testutil.TestWalletConfigWithIdentityKey(*userOutput1PrivKey)
			require.NoError(t, err, "failed to create user one wallet config")

			userTwoConfig, err := testutil.TestWalletConfigWithIdentityKey(*userOutput2PrivKey)
			require.NoError(t, err, "failed to create user two wallet config")

			userOneBalance, err := wallet.QueryTokenOutputs(
				context.Background(),
				userOneConfig,
				[]wallet.SerializedPublicKey{userOneConfig.IdentityPublicKey()},
				[]wallet.SerializedPublicKey{tokenIdentityPubKeyBytes},
			)
			require.NoError(t, err, "failed to query user one token outputs")

			userTwoBalance, err := wallet.QueryTokenOutputs(
				context.Background(),
				userTwoConfig,
				[]wallet.SerializedPublicKey{userTwoConfig.IdentityPublicKey()},
				[]wallet.SerializedPublicKey{tokenIdentityPubKeyBytes},
			)
			require.NoError(t, err, "failed to query user two token outputs")

			require.Equal(t, 1, len(userOneBalance.OutputsWithPreviousTransactionData), "expected one output for user one")
			userOneAmount := bytesToBigInt(userOneBalance.OutputsWithPreviousTransactionData[0].Output.TokenAmount)
			require.Equal(t, uint64ToBigInt(TestIssueOutput1Amount), userOneAmount, "user one should have the first mint output amount")

			require.Equal(t, 1, len(userTwoBalance.OutputsWithPreviousTransactionData), "expected one output for user two")
			userTwoAmount := bytesToBigInt(userTwoBalance.OutputsWithPreviousTransactionData[0].Output.TokenAmount)
			require.Equal(t, uint64ToBigInt(TestIssueOutput2Amount), userTwoAmount, "user two should have the second mint output amount")
		})
	}
}

// TestCoordinatedTokenMintAndTransferTokens tests the full coordinated flow with mint and transfer
func TestCoordinatedTokenMintAndTransferTokens(t *testing.T) {
	for _, tc := range signatureTypeTestCases {
		t.Run(tc.name, func(t *testing.T) {
			config, err := testutil.TestWalletConfigWithIdentityKey(*staticLocalIssuerKey.IdentityPrivateKey())
			require.NoError(t, err, "failed to create wallet config")
			config.UseTokenTransactionSchnorrSignatures = tc.useSchnorrSignatures

			tokenPrivKey := config.IdentityPrivateKey
			tokenIdentityPubKeyBytes := tokenPrivKey.PubKey().SerializeCompressed()
			issueTokenTransaction, userOutput1PrivKey, userOutput2PrivKey, err := createTestTokenMintTransactionTokenPb(config, tokenIdentityPubKeyBytes)
			require.NoError(t, err, "failed to create test token issuance transaction")

			finalIssueTokenTransaction, err := wallet.BroadcastCoordinatedTokenTransfer(
				context.Background(), config, issueTokenTransaction,
				[]*secp256k1.PrivateKey{&tokenPrivKey},
			)
			require.NoError(t, err, "failed to broadcast issuance token transaction")

			for i, output := range finalIssueTokenTransaction.TokenOutputs {
				if output.GetWithdrawBondSats() != WithdrawalBondSatsInConfig {
					t.Errorf("output %d: expected withdrawal bond sats 10000, got %d", i, output.GetWithdrawBondSats())
				}
				if output.GetWithdrawRelativeBlockLocktime() != uint64(WithdrawalRelativeBlockLocktimeInConfig) {
					t.Errorf("output %d: expected withdrawal relative block locktime 1000, got %d", i, output.GetWithdrawRelativeBlockLocktime())
				}
			}

			finalIssueTokenTransactionHash, err := utils.HashTokenTransaction(finalIssueTokenTransaction, false)
			require.NoError(t, err, "failed to hash final issuance token transaction")

			transferTokenTransaction, userOutput3PrivKey, err := createTestTokenTransferTransactionTokenPb(config,
				finalIssueTokenTransactionHash,
				tokenIdentityPubKeyBytes,
			)
			require.NoError(t, err, "failed to create test token transfer transaction")
			userOutput3PubKeyBytes := userOutput3PrivKey.PubKey().SerializeCompressed()

			transferTokenTransactionResponse, err := wallet.BroadcastCoordinatedTokenTransfer(
				context.Background(), config, transferTokenTransaction,
				[]*secp256k1.PrivateKey{userOutput1PrivKey, userOutput2PrivKey},
			)
			require.NoError(t, err, "failed to broadcast transfer token transaction")

			require.Equal(t, 1, len(transferTokenTransactionResponse.TokenOutputs), "expected 1 created output in transfer transaction")
			transferAmount := new(big.Int).SetBytes(transferTokenTransactionResponse.TokenOutputs[0].TokenAmount)
			expectedTransferAmount := new(big.Int).SetBytes(int64ToUint128Bytes(0, TestTransferOutput1Amount))
			require.Equal(t, 0, transferAmount.Cmp(expectedTransferAmount), "transfer amount does not match expected")
			require.True(t, bytes.Equal(transferTokenTransactionResponse.TokenOutputs[0].OwnerPublicKey, userOutput3PubKeyBytes), "transfer created output owner public key does not match expected")

			tokenOutputsResponse, err := wallet.QueryTokenOutputs(
				context.Background(),
				config,
				[]wallet.SerializedPublicKey{userOutput3PubKeyBytes},
				[]wallet.SerializedPublicKey{tokenIdentityPubKeyBytes},
			)
			require.NoError(t, err, "failed to get owned token outputs")
			require.Equal(t, 1, len(tokenOutputsResponse.OutputsWithPreviousTransactionData), "expected 1 output after transfer transaction")
			require.Equal(t, expectedTransferAmount, new(big.Int).SetBytes(tokenOutputsResponse.OutputsWithPreviousTransactionData[0].Output.TokenAmount), "expected correct amount after transfer transaction")
		})
	}
}

func TestCoordinatedTokenMintAndTransferTokensTooManyOutputsFails(t *testing.T) {
	for _, tc := range signatureTypeTestCases {
		t.Run(tc.name, func(t *testing.T) {
			config, err := testutil.TestWalletConfigWithIdentityKey(*staticLocalIssuerKey.IdentityPrivateKey())
			require.NoError(t, err, "failed to create wallet config")
			config.UseTokenTransactionSchnorrSignatures = tc.useSchnorrSignatures

			tokenPrivKey := config.IdentityPrivateKey
			tokenIdentityPubKeyBytes := tokenPrivKey.PubKey().SerializeCompressed()

			tooBigIssuanceTransaction, _, err := createTestTokenMintTransactionWithMultipleTokenOutputsTokenPb(config,
				tokenIdentityPubKeyBytes, utils.MaxInputOrOutputTokenTransactionOutputs+1)
			require.NoError(t, err, "failed to create test token issuance transaction")

			_, err = wallet.BroadcastCoordinatedTokenTransfer(
				context.Background(), config, tooBigIssuanceTransaction,
				[]*secp256k1.PrivateKey{&tokenPrivKey},
			)
			require.Error(t, err, "expected error when broadcasting issuance transaction with more than utils.MaxInputOrOutputTokenTransactionOutputs=%d outputs", utils.MaxInputOrOutputTokenTransactionOutputs)
		})
	}
}

// TestCoordinatedTokenMintAndTransferTokensLotsOfOutputs tests the coordinated flow with many outputs
func TestCoordinatedTokenMintAndTransferTokensWithTooManyInputsFails(t *testing.T) {
	config, err := testutil.TestConfig()
	if err != nil {
		t.Fatal(err)
	}

	// This test uses a lot of DKG keys, so let's generate them first
	for i := 0; i < 3; i++ {
		err = dkg.GenerateKeys(context.Background(), config, 1000)
		if err != nil {
			t.Fatal(err)
		}
	}

	for _, tc := range signatureTypeTestCases {
		t.Run(tc.name, func(t *testing.T) {
			config, err := testutil.TestWalletConfigWithIdentityKey(*staticLocalIssuerKey.IdentityPrivateKey())
			require.NoError(t, err, "failed to create wallet config")
			config.UseTokenTransactionSchnorrSignatures = tc.useSchnorrSignatures

			tokenPrivKey := config.IdentityPrivateKey
			tokenIdentityPubKeyBytes := tokenPrivKey.PubKey().SerializeCompressed()

			// Create first issuance transaction with MAX outputs
			issueTokenTransactionFirstBatch, userOutputPrivKeysFirstBatch, err := createTestTokenMintTransactionWithMultipleTokenOutputsTokenPb(config,
				tokenIdentityPubKeyBytes, utils.MaxInputOrOutputTokenTransactionOutputs)
			require.NoError(t, err, "failed to create test token issuance transaction")

			finalIssueTokenTransactionFirstBatch, err := wallet.BroadcastCoordinatedTokenTransfer(
				context.Background(), config, issueTokenTransactionFirstBatch,
				[]*secp256k1.PrivateKey{&tokenPrivKey},
			)
			require.NoError(t, err, "failed to broadcast issuance token transaction")

			// Create second issuance transaction with MAX outputs
			issueTokenTransactionSecondBatch, userOutputPrivKeysSecondBatch, err := createTestTokenMintTransactionWithMultipleTokenOutputsTokenPb(config,
				tokenIdentityPubKeyBytes, utils.MaxInputOrOutputTokenTransactionOutputs)
			require.NoError(t, err, "failed to create test token issuance transaction")

			finalIssueTokenTransactionSecondBatch, err := wallet.BroadcastCoordinatedTokenTransfer(
				context.Background(), config, issueTokenTransactionSecondBatch,
				[]*secp256k1.PrivateKey{&tokenPrivKey},
			)
			require.NoError(t, err, "failed to broadcast issuance token transaction")

			finalIssueTokenTransactionHashFirstBatch, err := utils.HashTokenTransaction(finalIssueTokenTransactionFirstBatch, false)
			require.NoError(t, err, "failed to hash first issuance token transaction")

			finalIssueTokenTransactionHashSecondBatch, err := utils.HashTokenTransaction(finalIssueTokenTransactionSecondBatch, false)
			require.NoError(t, err, "failed to hash second issuance token transaction")

			// Create consolidation transaction
			consolidatedOutputPrivKey, err := secp256k1.GeneratePrivateKey()
			require.NoError(t, err, "failed to generate private key")

			consolidatedOutputPubKeyBytes := consolidatedOutputPrivKey.PubKey().SerializeCompressed()

			// Create a transfer transaction that consolidates all outputs with too many inputs.
			outputsToSpendTooMany := make([]*tokenpb.TokenOutputToSpend, 2*utils.MaxInputOrOutputTokenTransactionOutputs)
			for i := 0; i < utils.MaxInputOrOutputTokenTransactionOutputs; i++ {
				outputsToSpendTooMany[i] = &tokenpb.TokenOutputToSpend{
					PrevTokenTransactionHash: finalIssueTokenTransactionHashFirstBatch,
					PrevTokenTransactionVout: uint32(i),
				}
			}
			for i := 0; i < utils.MaxInputOrOutputTokenTransactionOutputs; i++ {
				outputsToSpendTooMany[utils.MaxInputOrOutputTokenTransactionOutputs+i] = &tokenpb.TokenOutputToSpend{
					PrevTokenTransactionHash: finalIssueTokenTransactionHashSecondBatch,
					PrevTokenTransactionVout: uint32(i),
				}
			}

			tooManyTransaction := &tokenpb.TokenTransaction{
				TokenInputs: &tokenpb.TokenTransaction_TransferInput{
					TransferInput: &tokenpb.TokenTransferInput{
						OutputsToSpend: outputsToSpendTooMany,
					},
				},
				TokenOutputs: []*tokenpb.TokenOutput{
					{
						OwnerPublicKey: consolidatedOutputPubKeyBytes,
						TokenPublicKey: tokenIdentityPubKeyBytes,
						TokenAmount:    int64ToUint128Bytes(0, TestIssueMultiplePerOutputAmount*ManyOutputsCount),
					},
				},
				Network:                         config.ProtoNetwork(),
				SparkOperatorIdentityPublicKeys: getSigningOperatorPublicKeys(config),
			}

			allUserOutputPrivKeys := append(userOutputPrivKeysFirstBatch, userOutputPrivKeysSecondBatch...)

			// Broadcast the consolidation transaction
			_, err = wallet.BroadcastCoordinatedTokenTransfer(
				context.Background(), config, tooManyTransaction,
				allUserOutputPrivKeys,
			)
			require.Error(t, err, "expected error when broadcasting transfer transaction with more than utils.MaxInputOrOutputTokenTransactionOutputs=%d inputs", utils.MaxInputOrOutputTokenTransactionOutputs)
		})
	}
}

func TestCoordinatedTokenMintAndTransferMaxInputsSucceeds(t *testing.T) {
	config, err := testutil.TestConfig()
	if err != nil {
		t.Fatal(err)
	}

	// This test uses a lot of DKG keys, so let's generate them first
	for i := 0; i < 3; i++ {
		err = dkg.GenerateKeys(context.Background(), config, 1000)
		if err != nil {
			t.Fatal(err)
		}
	}

	for _, tc := range signatureTypeTestCases {
		t.Run(tc.name, func(t *testing.T) {
			config, err := testutil.TestWalletConfigWithIdentityKey(*staticLocalIssuerKey.IdentityPrivateKey())
			require.NoError(t, err, "failed to create wallet config")
			config.UseTokenTransactionSchnorrSignatures = tc.useSchnorrSignatures

			tokenPrivKey := config.IdentityPrivateKey
			tokenIdentityPubKeyBytes := tokenPrivKey.PubKey().SerializeCompressed()

			issueTokenTransaction, userOutputPrivKeys, err := createTestTokenMintTransactionWithMultipleTokenOutputsTokenPb(config,
				tokenIdentityPubKeyBytes, utils.MaxInputOrOutputTokenTransactionOutputs)
			require.NoError(t, err, "failed to create test token issuance transaction")

			finalIssueTokenTransaction, err := wallet.BroadcastCoordinatedTokenTransfer(
				context.Background(), config, issueTokenTransaction,
				[]*secp256k1.PrivateKey{&tokenPrivKey},
			)
			require.NoError(t, err, "failed to broadcast issuance token transaction")

			finalIssueTokenTransactionHash, err := utils.HashTokenTransaction(finalIssueTokenTransaction, false)
			require.NoError(t, err, "failed to hash first issuance token transaction")

			consolidatedOutputPrivKey, err := secp256k1.GeneratePrivateKey()
			require.NoError(t, err, "failed to generate private key")

			consolidatedOutputPubKeyBytes := consolidatedOutputPrivKey.PubKey().SerializeCompressed()

			outputsToSpend := make([]*tokenpb.TokenOutputToSpend, utils.MaxInputOrOutputTokenTransactionOutputs)
			for i := 0; i < utils.MaxInputOrOutputTokenTransactionOutputs; i++ {
				outputsToSpend[i] = &tokenpb.TokenOutputToSpend{
					PrevTokenTransactionHash: finalIssueTokenTransactionHash,
					PrevTokenTransactionVout: uint32(i),
				}
			}
			consolidateTransaction := &tokenpb.TokenTransaction{
				TokenInputs: &tokenpb.TokenTransaction_TransferInput{
					TransferInput: &tokenpb.TokenTransferInput{
						OutputsToSpend: outputsToSpend,
					},
				},
				TokenOutputs: []*tokenpb.TokenOutput{
					{
						OwnerPublicKey: consolidatedOutputPubKeyBytes,
						TokenPublicKey: tokenIdentityPubKeyBytes,
						TokenAmount:    int64ToUint128Bytes(0, TestIssueMultiplePerOutputAmount*utils.MaxInputOrOutputTokenTransactionOutputs),
					},
				},
				Network:                         config.ProtoNetwork(),
				SparkOperatorIdentityPublicKeys: getSigningOperatorPublicKeys(config),
			}

			_, err = wallet.BroadcastCoordinatedTokenTransfer(
				context.Background(), config, consolidateTransaction,
				userOutputPrivKeys,
			)
			require.NoError(t, err, "failed to broadcast consolidation transaction")

			tokenOutputsResponse, err := wallet.QueryTokenOutputs(
				context.Background(),
				config,
				[]wallet.SerializedPublicKey{consolidatedOutputPubKeyBytes},
				[]wallet.SerializedPublicKey{tokenIdentityPubKeyBytes},
			)
			require.NoError(t, err, "failed to get owned token outputs")

			require.Equal(t, 1, len(tokenOutputsResponse.OutputsWithPreviousTransactionData), "expected 1 consolidated output")
		})
	}
}

// TestCoordinatedFreezeAndUnfreezeTokens tests the coordinated freeze/unfreeze functionality
func TestCoordinatedFreezeAndUnfreezeTokens(t *testing.T) {
	for _, tc := range signatureTypeTestCases {
		t.Run(tc.name, func(t *testing.T) {
			skipIfGithubActions(t)
			config, err := testutil.TestWalletConfigWithIdentityKey(*staticLocalIssuerKey.IdentityPrivateKey())
			require.NoError(t, err, "failed to create wallet config")
			config.UseTokenTransactionSchnorrSignatures = tc.useSchnorrSignatures

			tokenPrivKey := config.IdentityPrivateKey
			tokenIdentityPubKeyBytes := tokenPrivKey.PubKey().SerializeCompressed()
			issueTokenTransaction, userOutput1PrivKey, userOutput2PrivKey, err := createTestTokenMintTransactionTokenPb(config, tokenIdentityPubKeyBytes)
			require.NoError(t, err, "failed to create test token issuance transaction")

			// Broadcast the token transaction
			finalIssueTokenTransaction, err := wallet.BroadcastCoordinatedTokenTransfer(
				context.Background(), config, issueTokenTransaction,
				[]*secp256k1.PrivateKey{&tokenPrivKey},
			)
			require.NoError(t, err, "failed to broadcast issuance token transaction")

			for i, output := range finalIssueTokenTransaction.TokenOutputs {
				if output.GetWithdrawBondSats() != WithdrawalBondSatsInConfig {
					t.Errorf("output %d: expected withdrawal bond sats %d, got %d", i, uint64(WithdrawalBondSatsInConfig), output.GetWithdrawBondSats())
				}
				if output.GetWithdrawRelativeBlockLocktime() != uint64(WithdrawalRelativeBlockLocktimeInConfig) {
					t.Errorf("output %d: expected withdrawal relative block locktime %d, got %d", i, uint64(WithdrawalRelativeBlockLocktimeInConfig), output.GetWithdrawRelativeBlockLocktime())
				}
			}

			// Call FreezeTokens to freeze the created output
			freezeResponse, err := wallet.FreezeTokens(
				context.Background(),
				config,
				finalIssueTokenTransaction.TokenOutputs[0].OwnerPublicKey, // owner public key of the output to freeze
				tokenIdentityPubKeyBytes,                                  // token public key
				false,                                                     // unfreeze
			)
			require.NoError(t, err, "failed to freeze tokens")

			// Convert frozen amount bytes to big.Int for comparison
			frozenAmount := new(big.Int).SetBytes(freezeResponse.ImpactedTokenAmount)

			// Calculate total amount from transaction created outputs
			expectedAmount := new(big.Int).SetBytes(int64ToUint128Bytes(0, TestIssueOutput1Amount))
			expectedOutputID := finalIssueTokenTransaction.TokenOutputs[0].Id

			require.Equal(t, 0, frozenAmount.Cmp(expectedAmount),
				"frozen amount %s does not match expected amount %s", frozenAmount.String(), expectedAmount.String())
			require.Equal(t, 1, len(freezeResponse.ImpactedOutputIds), "expected 1 impacted output ID")
			require.Equal(t, *expectedOutputID, freezeResponse.ImpactedOutputIds[0],
				"frozen output ID %s does not match expected output ID %s", freezeResponse.ImpactedOutputIds[0], *expectedOutputID)

			finalIssueTokenTransactionHash, err := utils.HashTokenTransaction(finalIssueTokenTransaction, false)
			require.NoError(t, err, "failed to hash final transfer token transaction")

			// Create transfer transaction
			transferTokenTransaction, _, err := createTestTokenTransferTransaction(config,
				finalIssueTokenTransactionHash,
				tokenIdentityPubKeyBytes,
			)
			require.NoError(t, err, "failed to create test token transfer transaction")

			// Convert to tokenpb for the coordinated API
			tokenTransferTokenTransaction, err := protoconverter.TokenProtoFromSparkTokenTransaction(transferTokenTransaction)
			require.NoError(t, err, "failed to convert transfer token transaction")

			// Broadcast the token transaction (should fail due to frozen tokens)
			transferFrozenTokenTransactionResponse, err := wallet.BroadcastCoordinatedTokenTransfer(
				context.Background(), config, tokenTransferTokenTransaction,
				[]*secp256k1.PrivateKey{userOutput1PrivKey, userOutput2PrivKey},
			)
			require.Error(t, err, "expected error when transferring frozen tokens")
			require.Nil(t, transferFrozenTokenTransactionResponse, "expected nil response when transferring frozen tokens")

			// Call FreezeTokens to thaw the created output
			unfreezeResponse, err := wallet.FreezeTokens(
				context.Background(),
				config,
				finalIssueTokenTransaction.TokenOutputs[0].OwnerPublicKey, // owner public key of the output to freeze
				tokenIdentityPubKeyBytes,
				true, // unfreeze
			)
			require.NoError(t, err, "failed to unfreeze tokens")

			// Convert frozen amount bytes to big.Int for comparison
			thawedAmount := new(big.Int).SetBytes(unfreezeResponse.ImpactedTokenAmount)

			require.Equal(t, 0, thawedAmount.Cmp(expectedAmount),
				"thawed amount %s does not match expected amount %s", thawedAmount.String(), expectedAmount.String())
			require.Equal(t, 1, len(unfreezeResponse.ImpactedOutputIds), "expected 1 impacted output ID")
			require.Equal(t, *expectedOutputID, unfreezeResponse.ImpactedOutputIds[0],
				"thawed output ID %s does not match expected output ID %s", unfreezeResponse.ImpactedOutputIds[0], *expectedOutputID)

			// Broadcast the token transaction (should succeed now that tokens are thawed)
			transferTokenTransactionResponse, err := wallet.BroadcastCoordinatedTokenTransfer(
				context.Background(), config, tokenTransferTokenTransaction,
				[]*secp256k1.PrivateKey{userOutput1PrivKey, userOutput2PrivKey},
			)
			require.NoError(t, err, "failed to broadcast thawed token transaction")
			require.NotNil(t, transferTokenTransactionResponse, "expected non-nil response when transferring thawed tokens")
		})
	}
}

// TestCoordinatedBroadcastTokenTransactionWithInvalidPrevTxHash tests validation with invalid transaction hashes
func TestCoordinatedBroadcastTokenTransactionWithInvalidPrevTxHash(t *testing.T) {
	for _, tc := range signatureTypeTestCases {
		t.Run(tc.name, func(t *testing.T) {
			config, err := testutil.TestWalletConfigWithIdentityKey(*staticLocalIssuerKey.IdentityPrivateKey())
			require.NoError(t, err, "failed to create wallet config")
			config.UseTokenTransactionSchnorrSignatures = tc.useSchnorrSignatures

			tokenPrivKey := config.IdentityPrivateKey
			tokenIdentityPubKeyBytes := tokenPrivKey.PubKey().SerializeCompressed()
			issueTokenTransaction, userOutput1PrivKey, userOutput2PrivKey, err := createTestTokenMintTransactionTokenPb(config, tokenIdentityPubKeyBytes)
			require.NoError(t, err, "failed to create test token issuance transaction")

			finalIssueTokenTransaction, err := wallet.BroadcastCoordinatedTokenTransfer(
				context.Background(), config, issueTokenTransaction,
				[]*secp256k1.PrivateKey{&tokenPrivKey},
			)
			require.NoError(t, err, "failed to broadcast issuance token transaction")

			finalIssueTokenTransactionHash, err := utils.HashTokenTransaction(finalIssueTokenTransaction, false)
			require.NoError(t, err, "failed to hash final issuance token transaction")

			// Corrupt the transaction hash by adding a byte
			corruptedHash := append(finalIssueTokenTransactionHash, 0xFF)

			// Create transfer transaction with corrupted hash
			transferTokenTransaction := &tokenpb.TokenTransaction{
				TokenInputs: &tokenpb.TokenTransaction_TransferInput{
					TransferInput: &tokenpb.TokenTransferInput{
						OutputsToSpend: []*tokenpb.TokenOutputToSpend{
							{
								PrevTokenTransactionHash: corruptedHash, // Corrupted hash
								PrevTokenTransactionVout: 0,
							},
							{
								PrevTokenTransactionHash: finalIssueTokenTransactionHash,
								PrevTokenTransactionVout: 1,
							},
						},
					},
				},
				TokenOutputs: []*tokenpb.TokenOutput{
					{
						OwnerPublicKey: userOutput1PrivKey.PubKey().SerializeCompressed(),
						TokenPublicKey: tokenIdentityPubKeyBytes,
						TokenAmount:    int64ToUint128Bytes(0, TestTransferOutput1Amount),
					},
				},
				Network:                         config.ProtoNetwork(),
				SparkOperatorIdentityPublicKeys: getSigningOperatorPublicKeys(config),
			}

			// Attempt to broadcast the transfer transaction with corrupted hash
			// This should fail validation
			_, err = wallet.BroadcastCoordinatedTokenTransfer(
				context.Background(), config, transferTokenTransaction,
				[]*secp256k1.PrivateKey{userOutput1PrivKey, userOutput2PrivKey},
			)

			require.Error(t, err, "expected transaction with invalid hash to be rejected")
		})
	}
}

// TestCoordinatedBroadcastTokenTransactionUnspecifiedNetwork tests validation with unspecified network
func TestCoordinatedBroadcastTokenTransactionUnspecifiedNetwork(t *testing.T) {
	for _, tc := range signatureTypeTestCases {
		t.Run(tc.name, func(t *testing.T) {
			config, err := testutil.TestWalletConfigWithIdentityKey(*staticLocalIssuerKey.IdentityPrivateKey())
			require.NoError(t, err, "failed to create wallet config")
			config.UseTokenTransactionSchnorrSignatures = tc.useSchnorrSignatures

			tokenPrivKey := config.IdentityPrivateKey
			tokenIdentityPubKeyBytes := tokenPrivKey.PubKey().SerializeCompressed()
			issueTokenTransaction, _, _, err := createTestTokenMintTransactionTokenPb(config, tokenIdentityPubKeyBytes)
			require.NoError(t, err, "failed to create test token issuance transaction")
			issueTokenTransaction.Network = sparkpb.Network_UNSPECIFIED

			_, err = wallet.BroadcastCoordinatedTokenTransfer(
				context.Background(), config, issueTokenTransaction,
				[]*secp256k1.PrivateKey{&tokenPrivKey},
			)

			require.Error(t, err, "expected transaction without a network to be rejected")
		})
	}
}

// TestCoordinatedQueryTokenOutputsByNetworkReturnsNoneForMismatchedNetwork tests network filtering
func TestCoordinatedQueryTokenOutputsByNetworkReturnsNoneForMismatchedNetwork(t *testing.T) {
	for _, tc := range signatureTypeTestCases {
		t.Run(tc.name, func(t *testing.T) {
			config, err := testutil.TestWalletConfigWithIdentityKey(*staticLocalIssuerKey.IdentityPrivateKey())
			require.NoError(t, err, "failed to create wallet config")
			config.UseTokenTransactionSchnorrSignatures = tc.useSchnorrSignatures

			tokenPrivKey := config.IdentityPrivateKey
			tokenIdentityPubkeyBytes := tokenPrivKey.PubKey().SerializeCompressed()

			issueTokenTransaction, userOutput1PrivKey, _, err := createTestTokenMintTransactionTokenPb(config, tokenIdentityPubkeyBytes)
			require.NoError(t, err, "failed to create test token issuance transaction")

			_, err = wallet.BroadcastCoordinatedTokenTransfer(
				context.Background(), config, issueTokenTransaction,
				[]*secp256k1.PrivateKey{&tokenPrivKey},
			)
			require.NoError(t, err, "failed to broadcast issuance token transaction")

			userOneConfig, err := testutil.TestWalletConfigWithIdentityKey(*userOutput1PrivKey)
			require.NoError(t, err, "failed to create test user one wallet config")

			correctNetworkResponse, err := wallet.QueryTokenOutputs(
				context.Background(),
				userOneConfig,
				[]wallet.SerializedPublicKey{userOutput1PrivKey.PubKey().SerializeCompressed()},
				[]wallet.SerializedPublicKey{tokenIdentityPubkeyBytes},
			)
			require.NoError(t, err, "failed to query token outputs")
			require.Equal(t, 1, len(correctNetworkResponse.OutputsWithPreviousTransactionData), "expected one outputs when using the correct network")

			wrongNetworkConfig := userOneConfig
			wrongNetworkConfig.Network = common.Mainnet

			wrongNetworkResponse, err := wallet.QueryTokenOutputs(
				context.Background(),
				wrongNetworkConfig,
				[]wallet.SerializedPublicKey{userOutput1PrivKey.PubKey().SerializeCompressed()},
				[]wallet.SerializedPublicKey{tokenIdentityPubkeyBytes},
			)
			require.NoError(t, err, "failed to query token outputs")
			require.Equal(t, 0, len(wrongNetworkResponse.OutputsWithPreviousTransactionData), "expected no outputs when using a different network")
		})
	}
}

func createTestTokenMintTransactionTokenPb(config *wallet.Config,
	tokenIdentityPubKeyBytes []byte,
) (*tokenpb.TokenTransaction, *secp256k1.PrivateKey, *secp256k1.PrivateKey, error) {
	issueTokenTransaction, userOutput1PrivKey, userOutput2PrivKey, err := createTestTokenMintTransaction(config, tokenIdentityPubKeyBytes)
	if err != nil {
		return nil, nil, nil, err
	}

	coordinatedIssueTx, err := protoconverter.TokenProtoFromSparkTokenTransaction(issueTokenTransaction)
	if err != nil {
		return nil, nil, nil, err
	}

	return coordinatedIssueTx, userOutput1PrivKey, userOutput2PrivKey, nil
}

func createTestTokenMintTransactionWithMultipleTokenOutputsTokenPb(config *wallet.Config,
	tokenIdentityPubKeyBytes []byte, numOutputs int,
) (*tokenpb.TokenTransaction, []*secp256k1.PrivateKey, error) {
	issueTokenTransaction, userOutputPrivKeys, err := createTestTokenMintTransactionWithMultipleTokenOutputs(config, tokenIdentityPubKeyBytes, numOutputs)
	if err != nil {
		return nil, nil, err
	}

	coordinatedIssueTx, err := protoconverter.TokenProtoFromSparkTokenTransaction(issueTokenTransaction)
	if err != nil {
		return nil, nil, err
	}

	return coordinatedIssueTx, userOutputPrivKeys, nil
}

func createTestTokenTransferTransactionTokenPb(
	config *wallet.Config,
	finalIssueTokenTransactionHash []byte,
	tokenIdentityPubKeyBytes []byte,
) (*tokenpb.TokenTransaction, *secp256k1.PrivateKey, error) {
	transferTokenTransaction, userOutputPrivKey, err := createTestTokenTransferTransaction(config, finalIssueTokenTransactionHash, tokenIdentityPubKeyBytes)
	if err != nil {
		return nil, nil, err
	}

	coordinatedTransferTx, err := protoconverter.TokenProtoFromSparkTokenTransaction(transferTokenTransaction)
	if err != nil {
		return nil, nil, err
	}

	return coordinatedTransferTx, userOutputPrivKey, nil
}
