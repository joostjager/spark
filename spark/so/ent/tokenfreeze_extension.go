package ent

import (
	"context"

	"github.com/google/uuid"
	"github.com/lightsparkdev/spark/common/logging"
	st "github.com/lightsparkdev/spark/so/ent/schema/schematype"
	"github.com/lightsparkdev/spark/so/ent/tokenfreeze"
)

func GetActiveFreezes(ctx context.Context, ownerPublicKeys [][]byte, tokenPublicKey []byte) ([]*TokenFreeze, error) {
	logger := logging.GetLoggerFromContext(ctx)

	activeFreezes, err := GetDbFromContext(ctx).TokenFreeze.Query().
		Where(
			// Order matters here to leverage the index.
			tokenfreeze.OwnerPublicKeyIn(ownerPublicKeys...),
			tokenfreeze.TokenPublicKeyEQ(tokenPublicKey),
			tokenfreeze.StatusEQ(st.TokenFreezeStatusFrozen),
		).All(ctx)
	if err != nil {
		logger.Error("Failed to fetch active freezes", "error", err)
		return nil, err
	}
	return activeFreezes, nil
}

func ThawActiveFreeze(ctx context.Context, activeFreezeID uuid.UUID, timestamp uint64) error {
	logger := logging.GetLoggerFromContext(ctx)

	_, err := GetDbFromContext(ctx).TokenFreeze.Update().
		Where(
			tokenfreeze.IDEQ(activeFreezeID),
		).
		SetStatus(st.TokenFreezeStatusThawed).
		SetWalletProvidedThawTimestamp(timestamp).
		Save(ctx)
	if err != nil {
		logger.Error("Failed to thaw active freeze", "error", err)
		return err
	}
	return nil
}

func ActivateFreeze(ctx context.Context, ownerPublicKey []byte, tokenPublicKey []byte, issuerSignature []byte, timestamp uint64) error {
	logger := logging.GetLoggerFromContext(ctx)

	_, err := GetDbFromContext(ctx).TokenFreeze.Create().
		SetStatus(st.TokenFreezeStatusFrozen).
		SetOwnerPublicKey(ownerPublicKey).
		SetTokenPublicKey(tokenPublicKey).
		SetWalletProvidedFreezeTimestamp(timestamp).
		SetIssuerSignature(issuerSignature).
		Save(ctx)
	if err != nil {
		logger.Error("Failed to activate freeze", "error", err)
		return err
	}
	return nil
}
