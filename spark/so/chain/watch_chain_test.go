package chain

import (
	"bytes"
	"context"
	"log/slog"
	"os"
	"testing"

	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/rpcclient"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightsparkdev/spark/common"
	"github.com/lightsparkdev/spark/so"
	"github.com/lightsparkdev/spark/so/ent/enttest"
	"github.com/lightsparkdev/spark/so/ent/schema/schematype"
	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/lightsparkdev/spark/so/lrc20"
)

func TestProcessTransactions(t *testing.T) {
	// Create test network params
	params := &chaincfg.TestNet3Params

	tests := []struct {
		name           string
		txs            []wire.MsgTx
		expectedAddrs  int
		expectedTxids  int
		expectedError  bool
		checkAddresses func(t *testing.T, addresses []string, utxoMap map[string][]AddressDepositUtxo)
	}{
		{
			name:          "empty transactions",
			txs:           []wire.MsgTx{},
			expectedAddrs: 0,
			expectedTxids: 0,
			expectedError: false,
			checkAddresses: func(t *testing.T, addresses []string, utxoMap map[string][]AddressDepositUtxo) {
				assert.Empty(t, addresses)
				assert.Empty(t, utxoMap)
			},
		},
		{
			name: "single transaction with one output",
			txs: func() []wire.MsgTx {
				tx := wire.MsgTx{}
				// Create a simple P2PKH output script (OP_DUP OP_HASH160 <pubkeyhash> OP_EQUALVERIFY OP_CHECKSIG)
				script := []byte{
					txscript.OP_DUP,
					txscript.OP_HASH160,
					0x14, // 20 bytes
					0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
					0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13,
					txscript.OP_EQUALVERIFY,
					txscript.OP_CHECKSIG,
				}
				tx.AddTxOut(wire.NewTxOut(1000, script))
				return []wire.MsgTx{tx}
			}(),
			expectedAddrs: 1,
			expectedTxids: 1,
			expectedError: false,
			checkAddresses: func(t *testing.T, addresses []string, utxoMap map[string][]AddressDepositUtxo) {
				assert.Len(t, addresses, 1)
				assert.Len(t, utxoMap, 1)
				utxos, exists := utxoMap[addresses[0]]
				assert.True(t, exists)
				assert.Equal(t, uint64(1000), utxos[0].amount)
				assert.Equal(t, uint32(0), utxos[0].idx)
			},
		},
		{
			name: "multiple transactions with multiple outputs",
			txs: func() []wire.MsgTx {
				tx1 := wire.MsgTx{}
				tx2 := wire.MsgTx{}

				// Create two different P2PKH output scripts
				script1 := []byte{
					txscript.OP_DUP,
					txscript.OP_HASH160,
					0x14, // 20 bytes
					0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
					0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13,
					txscript.OP_EQUALVERIFY,
					txscript.OP_CHECKSIG,
				}
				script2 := []byte{
					txscript.OP_DUP,
					txscript.OP_HASH160,
					0x14, // 20 bytes
					0x13, 0x12, 0x11, 0x10, 0x0f, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a,
					0x09, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00,
					txscript.OP_EQUALVERIFY,
					txscript.OP_CHECKSIG,
				}

				tx1.AddTxOut(wire.NewTxOut(1000, script1))
				tx1.AddTxOut(wire.NewTxOut(2000, script2))
				tx2.AddTxOut(wire.NewTxOut(3000, script1))

				return []wire.MsgTx{tx1, tx2}
			}(),
			expectedAddrs: 2, // Two unique addresses
			expectedTxids: 2, // Two transactions
			expectedError: false,
			checkAddresses: func(t *testing.T, addresses []string, utxoMap map[string][]AddressDepositUtxo) {
				assert.Len(t, addresses, 2)
				assert.Len(t, utxoMap, 2)
				foundSingleUtxoAddress := false
				foundMultipleUtxoAddress := false
				for _, utxos := range utxoMap {
					if len(utxos) == 2 {
						foundMultipleUtxoAddress = true
					} else if len(utxos) == 1 {
						foundSingleUtxoAddress = true
					}
				}
				assert.True(t, foundSingleUtxoAddress)
				assert.True(t, foundMultipleUtxoAddress)
			},
		},
		{
			name: "multiple transactions to the same address",
			txs: func() []wire.MsgTx {
				tx1 := wire.MsgTx{}
				tx2 := wire.MsgTx{}

				// Create two different P2PKH output scripts
				script1 := []byte{
					txscript.OP_DUP,
					txscript.OP_HASH160,
					0x14, // 20 bytes
					0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
					0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13,
					txscript.OP_EQUALVERIFY,
					txscript.OP_CHECKSIG,
				}

				tx1.AddTxOut(wire.NewTxOut(1000, script1))
				tx2.AddTxOut(wire.NewTxOut(3000, script1))

				return []wire.MsgTx{tx1, tx2}
			}(),
			expectedAddrs: 1, // One unique address
			expectedTxids: 2, // Two transactions
			expectedError: false,
			checkAddresses: func(t *testing.T, addresses []string, utxoMap map[string][]AddressDepositUtxo) {
				assert.Len(t, addresses, 1)
				assert.Len(t, utxoMap, 1)
				assert.Len(t, utxoMap[addresses[0]], 2)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			confirmedTxHashSet, creditedAddresses, addressToUtxoMap, err := processTransactions(tt.txs, params)

			if tt.expectedError {
				assert.Error(t, err)
				return
			}

			assert.NoError(t, err)
			assert.Len(t, confirmedTxHashSet, tt.expectedTxids)
			tt.checkAddresses(t, creditedAddresses, addressToUtxoMap)
		})
	}
}

func TestParseTokenAnnouncement(t *testing.T) {
	tests := []struct {
		name          string
		script        []byte
		expected      *tokenAnnouncement
		expectedError bool
	}{
		{
			name:          "empty script",
			script:        []byte{},
			expected:      nil,
			expectedError: false,
		},
		{
			name:          "not OP_RETURN",
			script:        []byte{txscript.OP_DUP, txscript.OP_HASH160},
			expected:      nil,
			expectedError: false,
		},
		{
			name:          "OP_RETURN but too short",
			script:        []byte{txscript.OP_RETURN},
			expected:      nil,
			expectedError: false,
		},
		{
			name:          "OP_RETURN with invalid kind",
			script:        []byte{txscript.OP_RETURN, 1, 1},
			expected:      nil,
			expectedError: false,
		},
		{
			name: "valid token announcement",
			script: func() []byte {
				script := make([]byte, 0)
				// Add OP_RETURN
				script = append(script, txscript.OP_RETURN)
				// Add LRC20 prefix
				script = append(script, []byte(announcementPrefix)...)
				// Add kind [0, 0]
				script = append(script, creationAnnouncementKind[:]...)
				// Add token pubkey (32 bytes)
				tokenPubkey := make([]byte, 32)
				for i := range tokenPubkey {
					tokenPubkey[i] = byte(i)
				}
				script = append(script, tokenPubkey...)
				// Add name length (1) and name (3 bytes)
				script = append(script, 3)
				script = append(script, []byte("ABC")...)
				// Add symbol length (1) and symbol (3 bytes)
				script = append(script, 3)
				script = append(script, []byte("XYZ")...)
				// Add decimal (1)
				script = append(script, 8)
				// Add max supply (16 bytes)
				maxSupply := make([]byte, 16)
				for i := range maxSupply {
					maxSupply[i] = byte(i)
				}
				script = append(script, maxSupply...)
				// Add is_freezable (1)
				script = append(script, 1)
				return script
			}(),
			expected: &tokenAnnouncement{
				IssuerPubKey: func() []byte {
					b := make([]byte, 32)
					for i := range b {
						b[i] = byte(i)
					}
					return b
				}(),
				Name:    "ABC",
				Symbol:  "XYZ",
				Decimal: 8,
				MaxSupply: func() []byte {
					b := make([]byte, 16)
					for i := range b {
						b[i] = byte(i)
					}
					return b
				}(),
				IsFreezable: true,
			},
			expectedError: false,
		},
		{
			name: "invalid decimals (too large)",
			script: func() []byte {
				script := make([]byte, 0)
				script = append(script, txscript.OP_RETURN)
				script = append(script, []byte(announcementPrefix)...)
				script = append(script, creationAnnouncementKind[:]...)
				script = append(script, make([]byte, 32)...)
				script = append(script, 3)
				script = append(script, []byte("ABC")...)
				script = append(script, 3)
				script = append(script, []byte("XYZ")...)
				script = append(script, 19) // Invalid decimals
				script = append(script, make([]byte, 16)...)
				script = append(script, 1)
				return script
			}(),
			expected:      nil,
			expectedError: true,
		},
		{
			name: "invalid name length (too short)",
			script: func() []byte {
				script := make([]byte, 0)
				script = append(script, txscript.OP_RETURN)
				script = append(script, []byte(announcementPrefix)...)
				script = append(script, creationAnnouncementKind[:]...)
				script = append(script, make([]byte, 32)...)
				script = append(script, 2) // Invalid name length
				script = append(script, []byte("AB")...)
				script = append(script, 3)
				script = append(script, []byte("XYZ")...)
				script = append(script, 8)
				script = append(script, make([]byte, 16)...)
				script = append(script, 1)
				return script
			}(),
			expected:      nil,
			expectedError: true,
		},
		{
			name: "invalid name length (too long)",
			script: func() []byte {
				script := make([]byte, 0)
				script = append(script, txscript.OP_RETURN)
				script = append(script, []byte(announcementPrefix)...)
				script = append(script, creationAnnouncementKind[:]...)
				script = append(script, make([]byte, 32)...)
				script = append(script, 18) // Invalid name length
				script = append(script, []byte("123456789012345678")...)
				script = append(script, 3)
				script = append(script, []byte("XYZ")...)
				script = append(script, 8)
				script = append(script, make([]byte, 16)...)
				script = append(script, 1)
				return script
			}(),
			expected:      nil,
			expectedError: true,
		},
		{
			name: "invalid symbol length (too short)",
			script: func() []byte {
				script := make([]byte, 0)
				script = append(script, txscript.OP_RETURN)
				script = append(script, []byte(announcementPrefix)...)
				script = append(script, creationAnnouncementKind[:]...)
				script = append(script, make([]byte, 32)...)
				script = append(script, 3)
				script = append(script, []byte("ABC")...)
				script = append(script, 2) // Invalid symbol length
				script = append(script, []byte("XY")...)
				script = append(script, 8)
				script = append(script, make([]byte, 16)...)
				script = append(script, 1)
				return script
			}(),
			expected:      nil,
			expectedError: true,
		},
		{
			name: "invalid symbol length (too long)",
			script: func() []byte {
				script := make([]byte, 0)
				script = append(script, txscript.OP_RETURN)
				script = append(script, []byte(announcementPrefix)...)
				script = append(script, creationAnnouncementKind[:]...)
				script = append(script, make([]byte, 32)...)
				script = append(script, 3)
				script = append(script, []byte("ABC")...)
				script = append(script, 7) // Invalid symbol length
				script = append(script, []byte("1234567")...)
				script = append(script, 8)
				script = append(script, make([]byte, 16)...)
				script = append(script, 1)
				return script
			}(),
			expected:      nil,
			expectedError: true,
		},
		{
			name: "invalid max supply length",
			script: func() []byte {
				script := make([]byte, 0)
				script = append(script, txscript.OP_RETURN)
				script = append(script, []byte(announcementPrefix)...)
				script = append(script, creationAnnouncementKind[:]...)
				script = append(script, make([]byte, 32)...) // pubkey
				script = append(script, 3)
				script = append(script, []byte("ABC")...)
				script = append(script, 3)
				script = append(script, []byte("XYZ")...)
				script = append(script, 8)
				script = append(script, make([]byte, 15)...) // 15 bytes for max supply
				script = append(script, 1)
				return script
			}(),
			expected:      nil,
			expectedError: true,
		},
		{
			name: "missing is_freezable",
			script: func() []byte {
				script := make([]byte, 0)
				script = append(script, txscript.OP_RETURN)
				script = append(script, []byte(announcementPrefix)...)
				script = append(script, creationAnnouncementKind[:]...)
				script = append(script, make([]byte, 32)...) // pubkey
				script = append(script, 3)
				script = append(script, []byte("ABC")...)
				script = append(script, 3)
				script = append(script, []byte("XYZ")...)
				script = append(script, 8)
				script = append(script, make([]byte, 16)...) // 16 bytes for max supply
				return script
			}(),
			expected:      nil,
			expectedError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := parseTokenAnnouncement(tt.script)

			if tt.expectedError {
				assert.Error(t, err)
				return
			}

			assert.NoError(t, err)
			if tt.expected == nil {
				assert.Nil(t, result)
				return
			}

			assert.NotNil(t, result)
			assert.Equal(t, tt.expected.IssuerPubKey, result.IssuerPubKey)
			assert.Equal(t, tt.expected.Name, result.Name)
			assert.Equal(t, tt.expected.Symbol, result.Symbol)
			assert.Equal(t, tt.expected.Decimal, result.Decimal)
			assert.Equal(t, tt.expected.MaxSupply, result.MaxSupply)
			assert.Equal(t, tt.expected.IsFreezable, result.IsFreezable)
		})
	}
}

func TestHandleBlock_MixedTransactions(t *testing.T) {
	client := enttest.Open(t, "sqlite3", "file:ent?mode=memory&cache=shared&_fk=1")
	defer client.Close()
	ctx := context.Background()
	dbTx, err := client.Tx(ctx)
	require.NoError(t, err)
	defer func() { _ = dbTx.Rollback() }()

	// A refund transaction that will be used to refund the tree node
	refundTx := wire.MsgTx{Version: 1, TxIn: []*wire.TxIn{{}}, TxOut: []*wire.TxOut{{Value: 1000}}}
	var buf bytes.Buffer
	err = refundTx.Serialize(&buf)
	require.NoError(t, err)
	rawRefundTx := buf.Bytes()

	// A transaction to create the treenode's output.
	nodeCreatingTx := wire.MsgTx{Version: 1, TxIn: []*wire.TxIn{{}}, TxOut: []*wire.TxOut{{Value: 1000}}}
	var nodeTxBuf bytes.Buffer
	err = nodeCreatingTx.Serialize(&nodeTxBuf)
	require.NoError(t, err)
	rawNodeTx := nodeTxBuf.Bytes()

	// The node needs a dummy tree to satisfy foreign key constraints.
	tree, err := dbTx.Tree.Create().
		SetStatus(schematype.TreeStatusPending).
		SetBaseTxid([]byte("dummytxid")).
		SetOwnerIdentityPubkey([]byte("owner")).
		SetNetwork(common.SchemaNetwork(common.Testnet)).
		SetVout(0).
		Save(ctx)
	require.NoError(t, err)

	signingKey, err := dbTx.SigningKeyshare.Create().
		SetPublicKey([]byte("keyshare")).
		SetSecretShare([]byte("secret")).
		SetMinSigners(1).
		SetPublicShares(map[string][]byte{}).
		SetStatus(schematype.KeyshareStatusAvailable).
		SetCoordinatorIndex(0).
		Save(ctx)
	require.NoError(t, err)

	treeNode, err := dbTx.TreeNode.Create().
		SetRawRefundTx(rawRefundTx).
		SetStatus(schematype.TreeNodeStatusOnChain).
		SetNodeConfirmationHeight(100).
		SetOwnerIdentityPubkey([]byte("owner")).
		SetRawTx(rawNodeTx).
		SetTree(tree).
		SetValue(1000).
		SetVerifyingPubkey([]byte("verifying")).
		SetOwnerSigningPubkey([]byte("owner")).
		SetVout(0).
		SetSigningKeyshare(signingKey).
		Save(ctx)
	require.NoError(t, err)

	// A valid token announcement
	validIssuerPubKey := make([]byte, 32)
	validIssuerPubKey[0] = 0x01
	validScript := func() []byte {
		s := []byte{txscript.OP_RETURN}
		s = append(s, []byte(announcementPrefix)...)
		s = append(s, creationAnnouncementKind[:]...)
		s = append(s, validIssuerPubKey...)
		s = append(s, 3)
		s = append(s, []byte("VLD")...)
		s = append(s, 3)
		s = append(s, []byte("VLD")...)
		s = append(s, 8)
		s = append(s, make([]byte, 16)...)
		s = append(s, 1)
		return s
	}()
	validTokenTx := wire.MsgTx{TxOut: []*wire.TxOut{{Value: 0, PkScript: validScript}}}

	// A second valid token announcement with the same issuer pubkey (should be rejected as duplicate)
	duplicateScript := func() []byte {
		s := []byte{txscript.OP_RETURN}
		s = append(s, []byte(announcementPrefix)...)
		s = append(s, creationAnnouncementKind[:]...)
		s = append(s, validIssuerPubKey...) // Same issuer pubkey
		s = append(s, 4)
		s = append(s, []byte("DUP1")...)
		s = append(s, 4)
		s = append(s, []byte("DUP1")...)
		s = append(s, 6)
		s = append(s, make([]byte, 16)...)
		s = append(s, 0)
		return s
	}()
	duplicateTokenTx := wire.MsgTx{TxOut: []*wire.TxOut{{Value: 0, PkScript: duplicateScript}}}

	// An invalid token announcement script that should cause a parsing error
	invalidScript := func() []byte {
		s := []byte{txscript.OP_RETURN}
		s = append(s, []byte(announcementPrefix)...)
		s = append(s, creationAnnouncementKind[:]...)
		s = append(s, make([]byte, 32)...)
		s = append(s, 1) // Invalid name length
		return s
	}()
	invalidTokenTx := wire.MsgTx{TxOut: []*wire.TxOut{{Value: 0, PkScript: invalidScript}}}

	// A script that isn't a token announcement at all
	nonAnnouncementScript := []byte{txscript.OP_DUP, txscript.OP_HASH160}
	nonAnnouncementTx := wire.MsgTx{TxOut: []*wire.TxOut{{Value: 1000, PkScript: nonAnnouncementScript}}}

	txs := []wire.MsgTx{validTokenTx, duplicateTokenTx, invalidTokenTx, nonAnnouncementTx, refundTx}

	// Disable LRC20 RPCs because we are only interested in testing SO logic.
	config := so.Config{
		Lrc20Configs: map[string]so.Lrc20Config{
			common.Testnet.String(): {
				DisableRpcs: true,
			},
		},
		SupportedNetworks: []common.Network{common.Testnet},
	}
	lrc20Client, err := lrc20.NewClient(&config, slog.New(slog.NewTextHandler(os.Stdout, nil)))
	require.NoError(t, err)
	connCfg := &rpcclient.ConnConfig{DisableTLS: true, HTTPPostMode: true}

	bitcoinClient, err := rpcclient.New(connCfg, nil)
	require.NoError(t, err)
	blockHeight := int64(101)
	blockHash := chainhash.Hash{}
	err = handleBlock(ctx, lrc20Client, dbTx, bitcoinClient, txs, blockHeight, &blockHash, common.Testnet)
	require.NoError(t, err)

	// Commit the transaction before querying
	err = dbTx.Commit()
	require.NoError(t, err)

	// Check that the tree node was refunded
	updatedNode, err := client.TreeNode.Get(ctx, treeNode.ID)
	require.NoError(t, err)
	assert.Equal(t, schematype.TreeNodeStatusExited, updatedNode.Status)
	assert.Equal(t, uint64(blockHeight), updatedNode.RefundConfirmationHeight)

	// Check that only the valid token was created
	tokens, err := client.TokenCreate.Query().All(ctx)
	require.NoError(t, err)
	assert.Len(t, tokens, 1)
	assert.True(t, bytes.Equal(validIssuerPubKey, tokens[0].IssuerPublicKey))
}
