package handler

import (
	"context"

	"github.com/google/uuid"
	pbinternal "github.com/lightsparkdev/spark/proto/spark_internal"
	"github.com/lightsparkdev/spark/so"
	"github.com/lightsparkdev/spark/so/ent"
	st "github.com/lightsparkdev/spark/so/ent/schema/schematype"
)

// InternalRefreshTimelockHandler is the refresh timelock handler for so internal.
type InternalRefreshTimelockHandler struct {
	config *so.Config
}

// NewInternalRefreshTimelockHandler creates a new InternalRefreshTimelockHandler.
func NewInternalRefreshTimelockHandler(config *so.Config) *InternalRefreshTimelockHandler {
	return &InternalRefreshTimelockHandler{
		config: config,
	}
}

// FinalizeRefreshTimelock finalizes a refresh timelock.
// Just save the new txs in the DB.
func (h *InternalRefreshTimelockHandler) FinalizeRefreshTimelock(ctx context.Context, req *pbinternal.FinalizeRefreshTimelockRequest) error {
	db := ent.GetDbFromContext(ctx)

	for _, node := range req.Nodes {
		nodeID, err := uuid.Parse(node.Id)
		if err != nil {
			return err
		}
		dbNode, err := db.TreeNode.Get(ctx, nodeID)
		if err != nil {
			return err
		}
		_, err = dbNode.Update().
			SetRawTx(node.RawTx).
			SetRawRefundTx(node.RawRefundTx).
			SetStatus(st.TreeNodeStatusAvailable).
			Save(ctx)
		if err != nil {
			return err
		}
	}

	return nil
}
