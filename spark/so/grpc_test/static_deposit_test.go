package grpctest

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"testing"
	"time"

	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"github.com/google/uuid"
	"github.com/lightsparkdev/spark/common"
	pb "github.com/lightsparkdev/spark/proto/spark"
	pbinternal "github.com/lightsparkdev/spark/proto/spark_internal"
	st "github.com/lightsparkdev/spark/so/ent/schema/schematype"
	"github.com/lightsparkdev/spark/so/ent/utxo"
	"github.com/lightsparkdev/spark/so/ent/utxoswap"
	"github.com/lightsparkdev/spark/so/handler"
	testutil "github.com/lightsparkdev/spark/test_util"
	"github.com/lightsparkdev/spark/wallet"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateUtxoIsNotSpent(t *testing.T) {
	skipIfGithubActions(t)
	bitcoinClient, err := testutil.NewRegtestClient()
	testutil.OnErrFatal(t, err)

	// Test with faucet transaction
	coin, err := faucet.Fund()
	testutil.OnErrFatal(t, err)
	txidString := hex.EncodeToString(coin.OutPoint.Hash[:])
	txIDBytes, err := hex.DecodeString(txidString)
	testutil.OnErrFatal(t, err)
	err = handler.ValidateUtxoIsNotSpent(bitcoinClient, txIDBytes, 0)
	if err != nil {
		t.Fatalf("utxo is spent: %v, txid: %s", err, txidString)
	}

	// Spend the faucet transaction and test with a new one
	randomKey, err := secp256k1.GeneratePrivateKey()
	assert.NoError(t, err)
	randomPubKey := randomKey.PubKey()
	randomAddress, err := common.P2TRRawAddressFromPublicKey(randomPubKey.SerializeCompressed(), common.Regtest)
	assert.NoError(t, err)

	pkScript, err := txscript.PayToAddrScript(randomAddress)
	testutil.OnErrFatal(t, err)
	txOut := wire.NewTxOut(10_000, pkScript)
	unsignedDepositTx := testutil.CreateTestTransaction([]*wire.TxIn{wire.NewTxIn(coin.OutPoint, nil, [][]byte{})}, []*wire.TxOut{txOut})
	signedDepositTx, err := testutil.SignFaucetCoin(unsignedDepositTx, coin.TxOut, coin.Key)
	testutil.OnErrFatal(t, err)
	newTxID, err := bitcoinClient.SendRawTransaction(signedDepositTx, true)
	testutil.OnErrFatal(t, err)

	// Make sure the deposit tx gets enough confirmations
	randomKey, err = secp256k1.GeneratePrivateKey()
	assert.NoError(t, err)
	randomPubKey = randomKey.PubKey()
	randomAddress, err = common.P2TRRawAddressFromPublicKey(randomPubKey.SerializeCompressed(), common.Regtest)
	assert.NoError(t, err)
	_, err = bitcoinClient.GenerateToAddress(1, randomAddress, nil)
	assert.NoError(t, err)

	// faucet coin is spent
	err = handler.ValidateUtxoIsNotSpent(bitcoinClient, txIDBytes, 0)
	assert.Error(t, err)

	// deposit tx is not spent
	err = handler.ValidateUtxoIsNotSpent(bitcoinClient, newTxID[:], 0)
	assert.NoError(t, err)
}

func TestStaticDepositSSP(t *testing.T) {
	bitcoinClient, err := testutil.NewRegtestClient()
	testutil.OnErrFatal(t, err)

	coin, err := faucet.Fund()
	testutil.OnErrFatal(t, err)

	// *********************************************************************************
	// Initiate Users
	// *********************************************************************************
	// 1. Initiate Alice
	aliceConfig, err := testutil.TestWalletConfig()
	testutil.OnErrFatal(t, err)

	aliceLeafPrivKey, err := secp256k1.GeneratePrivateKey()
	testutil.OnErrFatal(t, err)
	_, err = testutil.CreateNewTree(aliceConfig, faucet, aliceLeafPrivKey, 100_000)
	testutil.OnErrFatal(t, err)

	aliceConn, err := common.NewGRPCConnectionWithTestTLS(aliceConfig.CoodinatorAddress(), nil)
	testutil.OnErrFatal(t, err)
	defer aliceConn.Close()

	aliceConnectionToken, err := wallet.AuthenticateWithConnection(context.Background(), aliceConfig, aliceConn)
	testutil.OnErrFatal(t, err)
	aliceCtx := wallet.ContextWithToken(context.Background(), aliceConnectionToken)

	// 2. Initiate SSP
	sspConfig, err := testutil.TestWalletConfig()
	testutil.OnErrFatal(t, err)

	sspLeafPrivKey, err := secp256k1.GeneratePrivateKey()
	testutil.OnErrFatal(t, err)
	sspRootNode, err := testutil.CreateNewTree(sspConfig, faucet, sspLeafPrivKey, 90_000)
	testutil.OnErrFatal(t, err)

	sspConn, err := common.NewGRPCConnectionWithTestTLS(sspConfig.CoodinatorAddress(), nil)
	testutil.OnErrFatal(t, err)
	defer sspConn.Close()

	sspConnectionToken, err := wallet.AuthenticateWithConnection(context.Background(), sspConfig, sspConn)
	testutil.OnErrFatal(t, err)
	sspCtx := wallet.ContextWithToken(context.Background(), sspConnectionToken)

	// *********************************************************************************
	// Generate a new static deposit address for Alice
	// *********************************************************************************

	// Generate a new private key for Alice. In a real Wallet that key would be derived from
	// a Signing key using derivation schema
	aliceDepositPrivKey, err := secp256k1.GeneratePrivateKey()
	testutil.OnErrFatal(t, err)
	aliceDepositPubKey := aliceDepositPrivKey.PubKey()
	aliceDepositPubKeyBytes := aliceDepositPubKey.SerializeCompressed()

	leafID := uuid.New().String()

	depositResp, err := wallet.GenerateDepositAddress(
		aliceCtx,
		aliceConfig,
		aliceDepositPubKeyBytes,
		&leafID,
		true,
	)
	testutil.OnErrFatal(t, err)
	time.Sleep(100 * time.Millisecond)

	// *********************************************************************************
	// Create Test Deposit TX from Alice
	// *********************************************************************************
	depositAmount := uint64(100_000)
	quoteAmount := uint64(90_000)

	randomKey, err := secp256k1.GeneratePrivateKey()
	assert.NoError(t, err)
	randomPubKey := randomKey.PubKey()
	randomAddress, err := common.P2TRRawAddressFromPublicKey(randomPubKey.SerializeCompressed(), common.Regtest)
	assert.NoError(t, err)

	unsignedDepositTx, err := testutil.CreateTestDepositTransactionManyOutputs(
		coin.OutPoint,
		[]string{randomAddress.String(), depositResp.DepositAddress.Address},
		int64(depositAmount),
	)
	testutil.OnErrFatal(t, err)
	vout := 1
	if unsignedDepositTx.TxOut[vout].Value != int64(depositAmount) {
		t.Fatalf("deposit tx output value is not equal to the deposit amount")
	}
	signedDepositTx, err := testutil.SignFaucetCoin(unsignedDepositTx, coin.TxOut, coin.Key)
	testutil.OnErrFatal(t, err)
	_, err = bitcoinClient.SendRawTransaction(signedDepositTx, true)
	testutil.OnErrFatal(t, err)

	// Make sure the deposit tx gets enough confirmations
	// Confirm extra buffer to scan more blocks than needed
	// So that we don't race the chain watcher in this test
	_, err = bitcoinClient.GenerateToAddress(6, randomAddress, nil)
	assert.NoError(t, err)
	time.Sleep(10000 * time.Millisecond)

	// *********************************************************************************
	// Create request signatures
	// *********************************************************************************
	// SSP signature committing to a fixed amount quote.
	// Can be obtained from a call for a quote to SSP.
	sspSignature, err := createSspFixedQuoteSignature(
		signedDepositTx.TxHash().String(),
		uint32(vout),
		common.Regtest,
		quoteAmount,
		&sspConfig.IdentityPrivateKey,
	)
	testutil.OnErrFatal(t, err)

	// User signature authorizing the SSP to claim the deposit
	// in return for a transfer of a fixed amount
	userSignature, err := createUserSignature(
		signedDepositTx.TxHash().String(),
		uint32(vout),
		common.Regtest,
		pb.UtxoSwapRequestType_Fixed,
		quoteAmount,
		sspSignature,
		&aliceConfig.IdentityPrivateKey,
	)
	testutil.OnErrFatal(t, err)
	// *********************************************************************************
	// Create a Transfer from SSP to Alice
	// *********************************************************************************
	newLeafPrivKey, err := secp256k1.GeneratePrivateKey()
	testutil.OnErrFatal(t, err)

	transferNode := wallet.LeafKeyTweak{
		Leaf:              sspRootNode,
		SigningPrivKey:    sspLeafPrivKey.Serialize(),
		NewSigningPrivKey: newLeafPrivKey.Serialize(),
	}
	leavesToTransfer := [1]wallet.LeafKeyTweak{transferNode}

	// *********************************************************************************
	// Create spend tx from Alice's deposit to SSP L1 Wallet Address
	// *********************************************************************************
	depositOutPoint := &wire.OutPoint{Hash: signedDepositTx.TxHash(), Index: uint32(vout)}
	spendTx := wire.NewMsgTx(2)
	spendTx.AddTxIn(&wire.TxIn{
		PreviousOutPoint: *depositOutPoint,
		SignatureScript:  nil,
		Witness:          nil,
		Sequence:         wire.MaxTxInSequenceNum,
	})
	spendPkScript, err := common.P2TRScriptFromPubKey(sspConfig.IdentityPrivateKey.PubKey())
	testutil.OnErrFatal(t, err)
	spendTx.AddTxOut(wire.NewTxOut(int64(quoteAmount), spendPkScript))

	// *********************************************************************************
	// Get signing commitments to use for frost signing
	// *********************************************************************************
	nodeIDs := make([]string, len(leavesToTransfer))
	for i, leaf := range leavesToTransfer {
		nodeIDs[i] = leaf.Leaf.Id
	}

	// *********************************************************************************
	// Claim Static Deposit
	// *********************************************************************************
	signedSpendTx, transfer, err := wallet.ClaimStaticDeposit(
		sspCtx,
		sspConfig,
		common.Regtest,
		leavesToTransfer[:],
		spendTx,
		pb.UtxoSwapRequestType_Fixed,
		aliceDepositPrivKey,
		userSignature,
		sspSignature,
		aliceConfig.IdentityPrivateKey.PubKey(),
		sspConn,
		signedDepositTx.TxOut[vout],
	)
	testutil.OnErrFatal(t, err)

	config, err := testutil.TestConfig()
	require.NoError(t, err)
	_, db, err := testutil.TestContext(config)
	require.NoError(t, err)
	schemaNetwork, err := common.SchemaNetworkFromProtoNetwork(pb.Network_REGTEST)
	testutil.OnErrFatal(t, err)

	utxos, err := db.Utxo.Query().
		Where(utxo.NetworkEQ(schemaNetwork)).
		All(aliceCtx)
	require.NoError(t, err)
	for _, utxo := range utxos {
		fmt.Println(hex.EncodeToString(utxo.Txid))
	}

	depositTxID, err := hex.DecodeString(spendTx.TxIn[0].PreviousOutPoint.Hash.String())
	require.NoError(t, err)
	targetUtxo, err := db.Utxo.Query().
		Where(utxo.NetworkEQ(schemaNetwork)).
		Where(utxo.Txid(depositTxID)).
		Where(utxo.Vout(depositOutPoint.Index)).
		Only(aliceCtx)
	require.NoError(t, err)

	utxoSwap, err := db.UtxoSwap.Query().Where(utxoswap.HasUtxoWith(utxo.IDEQ(targetUtxo.ID))).Only(aliceCtx)
	require.NoError(t, err)
	assert.Equal(t, utxoSwap.Status, st.UtxoSwapStatusCompleted)
	dbTransferSspToAlice, err := utxoSwap.QueryTransfer().Only(aliceCtx)
	require.NoError(t, err)
	assert.Equal(t, dbTransferSspToAlice.Status, st.TransferStatusSenderKeyTweaked)

	_, err = common.SerializeTx(signedSpendTx)
	testutil.OnErrFatal(t, err)

	// Sign, broadcast, and mine spend tx
	_, err = bitcoinClient.SendRawTransaction(signedSpendTx, true)
	assert.NoError(t, err)

	require.Equal(t, transfer.Status, pb.TransferStatus_TRANSFER_STATUS_SENDER_KEY_TWEAKED)

	// Claim transfer
	pendingTransfer, err := wallet.QueryPendingTransfers(aliceCtx, aliceConfig)
	require.NoError(t, err, "failed to query pending transfers")
	require.Equal(t, 1, len(pendingTransfer.Transfers))
	receiverTransfer := pendingTransfer.Transfers[0]
	require.Equal(t, receiverTransfer.Id, receiverTransfer.Id)
	require.Equal(t, receiverTransfer.Type, pb.TransferType_UTXO_SWAP)

	finalLeafPrivKey, err := secp256k1.GeneratePrivateKey()
	require.NoError(t, err)
	claimingNode := wallet.LeafKeyTweak{
		Leaf:              receiverTransfer.Leaves[0].Leaf,
		SigningPrivKey:    newLeafPrivKey.Serialize(),
		NewSigningPrivKey: finalLeafPrivKey.Serialize(),
	}
	leavesToClaim := [1]wallet.LeafKeyTweak{claimingNode}
	res, err := wallet.ClaimTransfer(
		aliceCtx,
		receiverTransfer,
		aliceConfig,
		leavesToClaim[:],
	)
	require.NoError(t, err, "failed to ClaimTransfer")
	require.Equal(t, res[0].Id, transferNode.Leaf.Id)

	// *********************************************************************************
	// Claiming a Static Deposit again should return the same result
	// *********************************************************************************
	sparkClient := pb.NewSparkServiceClient(sspConn)
	depositTxID, err = hex.DecodeString(spendTx.TxIn[0].PreviousOutPoint.Hash.String())
	testutil.OnErrFatal(t, err)
	swapResponse, err := sparkClient.InitiateUtxoSwap(sspCtx, &pb.InitiateUtxoSwapRequest{
		OnChainUtxo: &pb.UTXO{
			Txid:    depositTxID,
			Vout:    uint32(vout),
			Network: pb.Network_REGTEST,
		},
		RequestType:   pb.UtxoSwapRequestType_Fixed,
		Amount:        &pb.InitiateUtxoSwapRequest_CreditAmountSats{CreditAmountSats: quoteAmount},
		UserSignature: userSignature,
		SspSignature:  sspSignature,
		Transfer: &pb.StartTransferRequest{
			TransferId:                transfer.Id,
			OwnerIdentityPublicKey:    sspConfig.IdentityPublicKey(),
			ReceiverIdentityPublicKey: aliceConfig.IdentityPublicKey(),
			ExpiryTime:                nil,
			TransferPackage:           nil,
		},
		SpendTxSigningJob: nil,
	})

	require.NoError(t, err)
	require.Equal(t, transfer.Id, swapResponse.Transfer.Id)

	// *********************************************************************************
	// A call to rollback should fail
	// *********************************************************************************
	sparkInternalClient := pbinternal.NewSparkInternalServiceClient(sspConn)
	rollbackUtxoSwapRequestMessageHash, err := handler.CreateUtxoSwapStatement(
		handler.UtxoSwapStatementTypeRollback,
		hex.EncodeToString(depositOutPoint.Hash[:]),
		depositOutPoint.Index,
		common.Regtest,
	)
	testutil.OnErrFatal(t, err)
	rollbackUtxoSwapRequestSignature := ecdsa.Sign(&sspConfig.IdentityPrivateKey, rollbackUtxoSwapRequestMessageHash)

	_, err = sparkInternalClient.RollbackUtxoSwap(sspCtx, &pbinternal.RollbackUtxoSwapRequest{
		OnChainUtxo: &pb.UTXO{
			Txid:    depositOutPoint.Hash[:],
			Vout:    depositOutPoint.Index,
			Network: pb.Network_REGTEST,
		},
		Signature:            rollbackUtxoSwapRequestSignature.Serialize(),
		CoordinatorPublicKey: aliceConfig.IdentityPublicKey(),
	})
	assert.Error(t, err)
}

func TestStaticDepositUserRefund(t *testing.T) {
	bitcoinClient, err := testutil.NewRegtestClient()
	testutil.OnErrFatal(t, err)

	coin, err := faucet.Fund()
	testutil.OnErrFatal(t, err)

	// *********************************************************************************
	// Initiate Users
	// *********************************************************************************
	// 1. Initiate Alice
	aliceConfig, err := testutil.TestWalletConfig()
	testutil.OnErrFatal(t, err)

	aliceLeafPrivKey, err := secp256k1.GeneratePrivateKey()
	testutil.OnErrFatal(t, err)
	_, err = testutil.CreateNewTree(aliceConfig, faucet, aliceLeafPrivKey, 100_000)
	testutil.OnErrFatal(t, err)

	aliceConn, err := common.NewGRPCConnectionWithTestTLS(aliceConfig.CoodinatorAddress(), nil)
	testutil.OnErrFatal(t, err)
	defer aliceConn.Close()

	aliceConnectionToken, err := wallet.AuthenticateWithConnection(context.Background(), aliceConfig, aliceConn)
	testutil.OnErrFatal(t, err)
	aliceCtx := wallet.ContextWithToken(context.Background(), aliceConnectionToken)

	// *********************************************************************************
	// Generate a new static deposit address for Alice
	// *********************************************************************************

	// Generate a new private key for Alice. In a real Wallet that key would be derived from
	// a Signing key using derivation schema
	aliceDepositPrivKey, err := secp256k1.GeneratePrivateKey()
	testutil.OnErrFatal(t, err)
	aliceDepositPubKey := aliceDepositPrivKey.PubKey()
	aliceDepositPubKeyBytes := aliceDepositPubKey.SerializeCompressed()

	leafID := uuid.New().String()

	depositResp, err := wallet.GenerateDepositAddress(
		aliceCtx,
		aliceConfig,
		aliceDepositPubKeyBytes,
		&leafID,
		true,
	)
	testutil.OnErrFatal(t, err)
	time.Sleep(100 * time.Millisecond)

	// *********************************************************************************
	// Create Test Deposit TX from Alice
	// *********************************************************************************
	depositAmount := uint64(100_000)
	quoteAmount := uint64(90_000)

	randomKey, err := secp256k1.GeneratePrivateKey()
	assert.NoError(t, err)
	randomPubKey := randomKey.PubKey()
	randomAddress, err := common.P2TRRawAddressFromPublicKey(randomPubKey.SerializeCompressed(), common.Regtest)
	assert.NoError(t, err)

	unsignedDepositTx, err := testutil.CreateTestDepositTransactionManyOutputs(
		coin.OutPoint,
		[]string{randomAddress.String(), depositResp.DepositAddress.Address},
		int64(depositAmount),
	)
	testutil.OnErrFatal(t, err)
	vout := 1
	if unsignedDepositTx.TxOut[vout].Value != int64(depositAmount) {
		t.Fatalf("deposit tx output value is not equal to the deposit amount")
	}
	signedDepositTx, err := testutil.SignFaucetCoin(unsignedDepositTx, coin.TxOut, coin.Key)
	testutil.OnErrFatal(t, err)
	_, err = bitcoinClient.SendRawTransaction(signedDepositTx, true)
	testutil.OnErrFatal(t, err)

	// Make sure the deposit tx gets enough confirmations
	// Confirm extra buffer to scan more blocks than needed
	// So that we don't race the chain watcher in this test
	_, err = bitcoinClient.GenerateToAddress(6, randomAddress, nil)
	assert.NoError(t, err)
	time.Sleep(10000 * time.Millisecond)

	// *********************************************************************************
	// Create spend tx from Alice's deposit to an Alice wallet address
	// *********************************************************************************
	depositOutPoint := &wire.OutPoint{Hash: signedDepositTx.TxHash(), Index: uint32(vout)}
	spendTx := wire.NewMsgTx(2)
	spendTx.AddTxIn(&wire.TxIn{
		PreviousOutPoint: *depositOutPoint,
		SignatureScript:  nil,
		Witness:          nil,
		Sequence:         wire.MaxTxInSequenceNum,
	})
	spendPkScript, err := common.P2TRScriptFromPubKey(aliceConfig.IdentityPrivateKey.PubKey())
	testutil.OnErrFatal(t, err)
	spendTx.AddTxOut(wire.NewTxOut(int64(quoteAmount), spendPkScript))

	// *********************************************************************************
	// Create request signature
	// *********************************************************************************
	spendTxSighash, err := common.SigHashFromTx(
		spendTx,
		0,
		signedDepositTx.TxOut[vout],
	)
	testutil.OnErrFatal(t, err)
	userSignature, err := createUserSignature(
		signedDepositTx.TxHash().String(),
		uint32(vout),
		common.Regtest,
		pb.UtxoSwapRequestType_Refund,
		quoteAmount,
		spendTxSighash[:],
		&aliceConfig.IdentityPrivateKey,
	)
	testutil.OnErrFatal(t, err)

	// *********************************************************************************
	// Refund Static Deposit
	// *********************************************************************************
	signedSpendTx, err := wallet.RefundStaticDeposit(
		aliceCtx,
		aliceConfig,
		common.Regtest,
		spendTx,
		aliceDepositPrivKey,
		userSignature,
		aliceConfig.IdentityPrivateKey.PubKey(),
		signedDepositTx.TxOut[vout],
		aliceConn,
	)
	testutil.OnErrFatal(t, err)

	spendTxBytes, err := common.SerializeTx(signedSpendTx)
	testutil.OnErrFatal(t, err)
	assert.True(t, len(spendTxBytes) > 0)

	// Sign, broadcast, and mine spend tx
	txid, err := bitcoinClient.SendRawTransaction(signedSpendTx, true)
	assert.NoError(t, err)
	assert.Equal(t, len(txid), 32)

	// *********************************************************************************
	// Refunding a Static Deposit again should fail
	// *********************************************************************************
	_, err = wallet.RefundStaticDeposit(
		aliceCtx,
		aliceConfig,
		common.Regtest,
		spendTx,
		aliceDepositPrivKey,
		userSignature,
		aliceConfig.IdentityPrivateKey.PubKey(),
		signedDepositTx.TxOut[vout],
		aliceConn,
	)
	assert.Error(t, err)

	// *********************************************************************************
	// A call to rollback should fail
	// *********************************************************************************
	sparkInternalClient := pbinternal.NewSparkInternalServiceClient(aliceConn)
	rollbackUtxoSwapRequestMessageHash, err := handler.CreateUtxoSwapStatement(
		handler.UtxoSwapStatementTypeRollback,
		hex.EncodeToString(depositOutPoint.Hash[:]),
		depositOutPoint.Index,
		common.Regtest,
	)
	testutil.OnErrFatal(t, err)
	rollbackUtxoSwapRequestSignature := ecdsa.Sign(&aliceConfig.IdentityPrivateKey, rollbackUtxoSwapRequestMessageHash)

	_, err = sparkInternalClient.RollbackUtxoSwap(aliceCtx, &pbinternal.RollbackUtxoSwapRequest{
		OnChainUtxo: &pb.UTXO{
			Txid:    depositOutPoint.Hash[:],
			Vout:    depositOutPoint.Index,
			Network: pb.Network_REGTEST,
		},
		Signature:            rollbackUtxoSwapRequestSignature.Serialize(),
		CoordinatorPublicKey: aliceConfig.IdentityPublicKey(),
	})
	assert.Error(t, err)
}

func createUserSignature(
	transactionID string,
	outputIndex uint32,
	network common.Network,
	requestType pb.UtxoSwapRequestType,
	creditAmountSats uint64,
	sspSignature []byte,
	identityPrivateKey *secp256k1.PrivateKey,
) ([]byte, error) {
	hash, err := handler.CreateUserStatement(
		transactionID,
		outputIndex,
		network,
		requestType,
		creditAmountSats,
		sspSignature,
	)
	if err != nil {
		return nil, err
	}

	// Sign the hash of the payload using ECDSA
	signature := ecdsa.Sign(identityPrivateKey, hash[:])

	return signature.Serialize(), nil
}

func createSspFixedQuoteSignature(
	transactionID string,
	outputIndex uint32,
	network common.Network,
	creditAmountSats uint64,
	identityPrivateKey *secp256k1.PrivateKey,
) ([]byte, error) {
	// Create a buffer to hold all the data
	var payload bytes.Buffer

	// Add network value as UTF-8 bytes
	_, err := payload.WriteString(network.String())
	if err != nil {
		return nil, err
	}

	// Add transaction ID as UTF-8 bytes
	_, err = payload.WriteString(transactionID)
	if err != nil {
		return nil, err
	}

	// Add output index as 4-byte unsigned integer (little-endian)
	err = binary.Write(&payload, binary.LittleEndian, outputIndex)
	if err != nil {
		return nil, err
	}

	// Request type fixed amount
	err = binary.Write(&payload, binary.LittleEndian, uint8(0))
	if err != nil {
		return nil, err
	}

	// Add credit amount as 8-byte unsigned integer (little-endian)
	err = binary.Write(&payload, binary.LittleEndian, uint64(creditAmountSats))
	if err != nil {
		return nil, err
	}

	// Hash the payload with SHA-256
	hash := sha256.Sum256(payload.Bytes())

	// Sign the hash of the payload using ECDSA
	signature := ecdsa.Sign(identityPrivateKey, hash[:])

	return signature.Serialize(), nil
}
