package chain

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightsparkdev/spark/common"
	"github.com/lightsparkdev/spark/common/logging"
	"github.com/lightsparkdev/spark/so/ent"
	"github.com/lightsparkdev/spark/so/ent/tokencreate"
	"github.com/lightsparkdev/spark/so/lrc20"
)

// tokenAnnouncement represents a parsed token announcement from the blockchain
type tokenAnnouncement struct {
	IssuerPubKey []byte
	Name         string
	Symbol       string
	Decimal      uint8
	MaxSupply    []byte
	IsFreezable  bool
}

const (
	// announcementPrefix is the constant prefix to differentiate lrc20 announcements from other protocols
	announcementPrefix = "LRC20"
	// announcementPrefixSizeBytes is the length of the announcement prefix in bytes
	announcementPrefixSizeBytes = 5
	// announcementKindSizeBytes is the length of the announcement kind in bytes
	announcementKindSizeBytes = 2
	// announcementHeaderMinimalLength is the minimal length of the announcement in bytes
	// Includes OP_RETURN (1) + prefix (5 bytes) + kind (2 bytes)
	announcementHeaderMinimalLength = 1 + announcementPrefixSizeBytes + announcementKindSizeBytes
	// minNameSizeBytes is the minimum size of the name in bytes
	minNameSizeBytes = 3
	// maxNameSizeBytes is the maximum size of the name in bytes
	maxNameSizeBytes = 17
	// minSymbolSizeBytes is the minimum size of the symbol in bytes
	minSymbolSizeBytes = 3
	// maxSymbolSizeBytes is the maximum size of the symbol in bytes
	maxSymbolSizeBytes = 6
	// tokenPubKeySizeBytes is the size of the token pubkey in bytes
	tokenPubKeySizeBytes = 32
	// nameLengthSizeBytes is the size of the name length in bytes
	nameLengthSizeBytes = 1
	// symbolLengthSizeBytes is the size of the symbol length in bytes
	symbolLengthSizeBytes = 1
	// decimalSizeBytes is the size of the decimal in bytes
	decimalSizeBytes = 1
	// maxSupplySizeBytes is the size of the max supply in bytes
	maxSupplySizeBytes = 16
	// isFreezableSizeBytes is the size of the is_freezable flag in bytes
	isFreezableSizeBytes = 1
	// maxDecimals is the maximum value for the decimals field
	maxDecimals = 18
	// minTokenPubkeyAnnouncementSize is the minimum size of the announcement in bytes
	// Matches Rust: ANNOUNCEMENT_MINIMAL_LENGTH + SCHNORR_PUBLIC_KEY_SIZE + 1 + MIN_NAME_SIZE + 1 + MIN_SYMBOL_SIZE + 1 + 16 + 1
	minTokenPubkeyAnnouncementSize = announcementHeaderMinimalLength + tokenPubKeySizeBytes + nameLengthSizeBytes + minNameSizeBytes + symbolLengthSizeBytes + minSymbolSizeBytes + decimalSizeBytes + maxSupplySizeBytes + isFreezableSizeBytes
)

// creationAnnouncementKind indicates this Announcement is for token creation
var creationAnnouncementKind = [2]byte{0, 0}

func parseTokenAnnouncement(script []byte) (*tokenAnnouncement, error) {
	if len(script) < 1 || script[0] != txscript.OP_RETURN {
		// Not an OP_RETURN script
		return nil, nil
	}
	if len(script[1:]) < announcementPrefixSizeBytes || !bytes.Equal(script[1:announcementPrefixSizeBytes+1], []byte(announcementPrefix)) {
		// Not an LRC20 announcement
		return nil, nil
	}
	announceData := script[1+announcementPrefixSizeBytes:]

	if len(announceData) < announcementKindSizeBytes || !bytes.Equal(announceData[:announcementKindSizeBytes], creationAnnouncementKind[:]) {
		// Not a token creation announcement
		return nil, nil
	}

	if len(script) < minTokenPubkeyAnnouncementSize {
		return nil, fmt.Errorf("token announcement too short: got %d bytes, need at least %d bytes",
			len(script), minTokenPubkeyAnnouncementSize)
	}

	// Format: [token_pubkey(32)] + [name_len(1)] + [name(variable)] + [symbol_len(1)] + [symbol(variable)] + [decimal(1)] + [max_supply(16)] + [is_freezable(1)]
	offset := announcementKindSizeBytes // Start at beginning of announceData after kind bytes
	issuerPubkey := announceData[offset : offset+tokenPubKeySizeBytes]
	offset += tokenPubKeySizeBytes
	nameLen := int(announceData[offset])
	offset++
	if nameLen < minNameSizeBytes || nameLen > maxNameSizeBytes {
		return nil, fmt.Errorf("invalid name length: %d (must be between %d and %d characters)", nameLen, minNameSizeBytes, maxNameSizeBytes)
	}
	name := string(announceData[offset : offset+nameLen])
	offset += nameLen
	symbolLen := int(announceData[offset])
	offset++
	if symbolLen < minSymbolSizeBytes || symbolLen > maxSymbolSizeBytes {
		return nil, fmt.Errorf("invalid symbol length: %d (must be between %d and %d characters)", symbolLen, minSymbolSizeBytes, maxSymbolSizeBytes)
	}
	symbol := string(announceData[offset : offset+symbolLen])
	offset += symbolLen
	decimal := announceData[offset]
	offset++
	if decimal > maxDecimals {
		return nil, fmt.Errorf("invalid decimals: %d. can't be > %d", decimal, maxDecimals)
	}
	maxSupply := announceData[offset : offset+maxSupplySizeBytes]
	offset += maxSupplySizeBytes
	isFreezable := announceData[offset] != 0

	return &tokenAnnouncement{
		IssuerPubKey: issuerPubkey,
		Name:         name,
		Symbol:       symbol,
		Decimal:      decimal,
		MaxSupply:    maxSupply,
		IsFreezable:  isFreezable,
	}, nil
}

// handleTokenAnnouncements processes any token announcements in the block
func handleTokenAnnouncements(ctx context.Context, dbTx *ent.Tx, txs []wire.MsgTx, network common.Network) error {
	logger := logging.GetLoggerFromContext(ctx)

	for _, tx := range txs {
		txid := tx.TxHash().String()
		for _, txOut := range tx.TxOut {
			announcement, err := parseTokenAnnouncement(txOut.PkScript)
			if err != nil {
				logger.Debug("Failed to parse token announcement", "error", err, "txid", txid)
				continue
			}
			if announcement == nil {
				continue // Not a token announcement
			}

			exists, err := dbTx.TokenCreate.Query().
				Where(
					tokencreate.IssuerPublicKeyEQ(announcement.IssuerPubKey),
					tokencreate.NetworkEQ(common.SchemaNetwork(network)),
				).
				Exist(ctx)
			if err != nil {
				logger.Error("Failed to query for existing token", "error", err, "txid", txid)
				continue
			}
			if exists {
				logger.Info("Token with this issuer public key already exists.  Ignoring the announcement.",
					"token_pubkey", hex.EncodeToString(announcement.IssuerPubKey),
					"network", network.String(),
					"txid", txid)
				continue
			}

			_, err = dbTx.TokenCreate.Create().
				SetIssuerPublicKey(announcement.IssuerPubKey).
				SetTokenName(announcement.Name).
				SetTokenTicker(announcement.Symbol).
				SetDecimals(uint32(announcement.Decimal)).
				SetMaxSupply(announcement.MaxSupply).
				SetIsFreezable(announcement.IsFreezable).
				SetNetwork(common.SchemaNetwork(network)).
				// Tokens created on L1 use an empty 32 byte array for creation entity.
				SetCreationEntityPublicKey(make([]byte, 32)).
				Save(ctx)
			if err != nil {
				logger.Error("Failed to create token entity", "error", err, "txid", txid)
				continue
			}

			logger.Info("Created new lrc-20 token from l1 announcement",
				"name", announcement.Name,
				"symbol", announcement.Symbol,
				"token_pubkey", hex.EncodeToString(announcement.IssuerPubKey),
				"txid", txid)
		}
	}
	return nil
}

func handleTokenUpdatesForBlock(
	ctx context.Context,
	lrc20Client *lrc20.Client,
	dbTx *ent.Tx,
	txs []wire.MsgTx,
	blockHeight int64,
	blockHash *chainhash.Hash,
	network common.Network,
) error {
	logger := logging.GetLoggerFromContext(ctx)
	if err := handleTokenAnnouncements(ctx, dbTx, txs, network); err != nil {
		logger.Error("Failed to handle token announcements", "error", err)
	}

	logger.Info("Checking for withdrawn token leaves in block", "height", blockHeight)

	// Use the lrc20 client to sync withdrawn leaves - it will handle all the processing internally
	err := lrc20Client.MarkWithdrawnTokenOutputs(ctx, network, dbTx, blockHash)
	if err != nil {
		logger.Error("Failed to sync withdrawn leaves", "error", err)
		return err
	}
	return nil
}
