package handler

import (
	"bytes"
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/lightsparkdev/spark/common/logging"
	pbgossip "github.com/lightsparkdev/spark/proto/gossip"
	pb "github.com/lightsparkdev/spark/proto/spark"
	pbssp "github.com/lightsparkdev/spark/proto/spark_ssp_internal"
	spark_ssp "github.com/lightsparkdev/spark/proto/spark_ssp_internal"
	"github.com/lightsparkdev/spark/so"
	"github.com/lightsparkdev/spark/so/authz"
	"github.com/lightsparkdev/spark/so/ent"
	st "github.com/lightsparkdev/spark/so/ent/schema/schematype"
	"github.com/lightsparkdev/spark/so/ent/transfer"
	enttreenode "github.com/lightsparkdev/spark/so/ent/treenode"
	"github.com/lightsparkdev/spark/so/helper"
)

type SspRequestHandler struct {
	config *so.Config
}

func NewSspRequestHandler(config *so.Config) *SspRequestHandler {
	return &SspRequestHandler{config: config}
}

func (h *SspRequestHandler) QueryLostNodes(ctx context.Context, req *pbssp.QueryLostNodesRequest) (*pbssp.QueryLostNodesResponse, error) {
	// TOOD yunyu: allow only ssp
	db := ent.GetDbFromContext(ctx)

	query := db.TreeNode.Query().Where(enttreenode.StatusEQ(st.TreeNodeStatusLost))
	if req.GetOwnerIdentityPubkey() != nil {
		query = query.Where(enttreenode.OwnerIdentityPubkeyEQ(req.OwnerIdentityPubkey))
	}
	nodes, err := query.All(ctx)
	if err != nil {
		return nil, err
	}

	protoNodes := make([]*pb.TreeNode, 0)
	for _, node := range nodes {
		protoNode, err := node.MarshalSparkProto(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal node %s: %w", node.ID, err)
		}
		protoNodes = append(protoNodes, protoNode)
	}

	return &pbssp.QueryLostNodesResponse{
		Nodes: protoNodes,
	}, nil
}

func (h *SspRequestHandler) MagicSwap(ctx context.Context, req *pbssp.MagicSwapRequest) (*pbssp.MagicSwapResponse, error) {
	if err := authz.EnforceSessionIdentityPublicKeyMatches(ctx, h.config, req.OwnerIdentityPublicKey); err != nil {
		return nil, err
	}
	ctx, _ = logging.WithIdentityPubkey(ctx, req.OwnerIdentityPublicKey)

	if err := h.validateMagicSwapInput(ctx, req); err != nil {
		return nil, err
	}

	counterLeafSwapResponse, err := NewTransferHandler(h.config).CounterLeafSwap(ctx, &pb.CounterLeafSwapRequest{
		Transfer: &pb.StartTransferRequest{
			TransferId:                req.TransferId,
			OwnerIdentityPublicKey:    req.OwnerIdentityPublicKey,
			ReceiverIdentityPublicKey: req.ReceiverIdentityPublicKey,
			TransferPackage:           req.TransferPackage,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to perform counter leaf swap: %w", err)
	}

	swapTransfer, err := h.transferSwapLeaves(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to transfer swap leaves: %w", err)
	}
	swapTransferProto, err := swapTransfer.MarshalProto(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal swap transfer: %w", err)
	}

	return &pbssp.MagicSwapResponse{
		SwapTransfer:        swapTransferProto,
		CounterSwapTransfer: counterLeafSwapResponse.Transfer,
	}, nil
}

func (h *SspRequestHandler) transferSwapLeaves(ctx context.Context, req *pbssp.MagicSwapRequest) (*ent.Transfer, error) {
	transferID, err := uuid.NewV7()
	if err != nil {
		return nil, fmt.Errorf("failed to generate swap transfer id: %v", err)
	}

	selection := helper.OperatorSelection{Option: helper.OperatorSelectionOptionExcludeSelf}
	operatorList, err := selection.OperatorList(h.config)
	if err != nil {
		return nil, fmt.Errorf("unable to get operator list: %w", err)
	}
	participants := make([]string, len(operatorList))
	for i, operator := range operatorList {
		participants[i] = operator.Identifier
	}
	_, err = NewSendGossipHandler(h.config).CreateAndSendGossipMessage(ctx, &pbgossip.GossipMessage{
		Message: &pbgossip.GossipMessage_MagicSwap{
			MagicSwap: &pbgossip.GossipMessageMagicSwap{
				TransferId:        transferID.String(),
				SwapLeafIds:       req.SwapLeafIds,
				SenderPublicKey:   req.ReceiverIdentityPublicKey,
				ReceiverPublicKey: req.OwnerIdentityPublicKey,
			},
		},
	}, participants)
	if err != nil {
		return nil, fmt.Errorf("unable to create and send gossip message: %w", err)
	}

	return ent.GetDbFromContext(ctx).Transfer.Get(ctx, transferID)
}

func (h *SspRequestHandler) validateMagicSwapInput(ctx context.Context, req *pbssp.MagicSwapRequest) error {
	db := ent.GetDbFromContext(ctx)
	swapLeafIDs := make([]uuid.UUID, 0, len(req.SwapLeafIds))
	for _, leafID := range req.SwapLeafIds {
		id, err := uuid.Parse(leafID)
		if err != nil {
			return fmt.Errorf("invalid swap leaf ID %s: %w", leafID, err)
		}
		swapLeafIDs = append(swapLeafIDs, id)
	}
	swapLeaves, err := db.TreeNode.Query().Where(enttreenode.IDIn(swapLeafIDs...)).ForUpdate().All(ctx)
	if err != nil || len(swapLeaves) != len(swapLeafIDs) {
		return fmt.Errorf("failed to query swap leaves: %w", err)
	}

	// Validate that all swap leaves are available, on the same network and belong to the receiver
	var swapNetwork *st.Network
	swapAmount := uint64(0)
	for _, leaf := range swapLeaves {
		if leaf.Status != st.TreeNodeStatusAvailable && leaf.Status != st.TreeNodeStatusLost {
			return fmt.Errorf("swap leaf %s is not eligible for swap", leaf.ID)
		}
		if !bytes.Equal(leaf.OwnerIdentityPubkey, req.ReceiverIdentityPublicKey) {
			return fmt.Errorf("swap leaf %s does not belong to receiver %s", leaf.ID, req.ReceiverIdentityPublicKey)
		}
		tree, err := leaf.QueryTree().Only((ctx))
		if err != nil {
			return fmt.Errorf("failed to query tree for swap leaf %s: %w", leaf.ID, err)
		}
		if swapNetwork == nil {
			swapNetwork = &tree.Network
		} else if *swapNetwork != tree.Network {
			return fmt.Errorf("all swap leaves must be on the same network")
		}
		swapAmount += leaf.Value
	}

	counterSwapLeafIDs := make([]uuid.UUID, 0, len(req.TransferPackage.LeavesToSend))
	for _, signingJob := range req.TransferPackage.LeavesToSend {
		id, err := uuid.Parse(signingJob.LeafId)
		if err != nil {
			return fmt.Errorf("invalid counter swap leaf ID %s: %w", signingJob.LeafId, err)
		}
		counterSwapLeafIDs = append(counterSwapLeafIDs, id)
	}
	counterSwapLeaves, err := db.TreeNode.Query().Where(enttreenode.IDIn(counterSwapLeafIDs...)).All(ctx)
	if err != nil || len(counterSwapLeaves) != len(counterSwapLeafIDs) {
		return fmt.Errorf("failed to query counter leaves: %w", err)
	}

	// Validate that all counter swap leaves are available, belong to the sender, and are on the same network as swap leaves
	counterSwapAmount := uint64(0)
	for _, leaf := range counterSwapLeaves {
		if leaf.Status != st.TreeNodeStatusAvailable {
			return fmt.Errorf("counter swap leaf %s is not available", leaf.ID)
		}
		if !bytes.Equal(leaf.OwnerIdentityPubkey, req.OwnerIdentityPublicKey) {
			return fmt.Errorf("leaf %s does not belong to sender %s", leaf.ID, req.OwnerIdentityPublicKey)
		}
		tree, err := leaf.QueryTree().Only((ctx))
		if err != nil {
			return fmt.Errorf("failed to query tree for counter swap leaf %s: %w", leaf.ID, err)
		}
		if *swapNetwork != tree.Network {
			return fmt.Errorf("counter swap leaves and swap leaves must be on the same network")
		}
		counterSwapAmount += leaf.Value
	}

	// Validate total swap amount matches total counter swap amount
	if swapAmount != counterSwapAmount {
		return fmt.Errorf("swap amount %d does not match counter swap amount %d", swapAmount, counterSwapAmount)
	}

	return nil
}

func (h *SspRequestHandler) GetStuckTransfers(ctx context.Context, req *pbssp.GetStuckTransfersRequest) (*pbssp.GetStuckTransfersResponse, error) {
	logger := logging.GetLoggerFromContext(ctx)

	before := time.Now().Add(-24 * time.Hour)
	if req.Before != nil {
		before = req.Before.AsTime()
	}

	if before.After(time.Now().Add(-24 * time.Hour)) {
		return nil, fmt.Errorf("before time must be at least 24 hours before current time")
	}

	limit := 100
	if req.Limit != 0 && req.Limit <= 1000 {
		limit = int(req.Limit)
	}

	offset := 0
	if req.Offset != 0 {
		offset = int(req.Offset)
	}

	logger.Info(fmt.Sprintf("Fetching stuck transfers before %s with limit %d and offset %d", before, limit, offset))

	db := ent.GetDbFromContext(ctx)
	transfers, err := db.Transfer.Query().Where(
		transfer.And(
			transfer.StatusNotIn(st.TransferStatusReturned, st.TransferStatusCompleted),
			transfer.CreateTimeLT(before)),
	).Limit(limit).Offset(offset).All(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to query stuck transfers: %w", err)
	}

	logger.Info(fmt.Sprintf("Found %d stuck transfers", len(transfers)))

	protoStuckTransfers := make([]*spark_ssp.StuckTransfer, 0, len(transfers))
	for _, transfer := range transfers {
		stuckTransfer, err := h.marshalStuckTransfer(ctx, transfer)
		if err != nil {
			return nil, err
		}

		protoStuckTransfers = append(protoStuckTransfers, stuckTransfer)
	}

	nextOffset := -1
	if len(transfers) == limit {
		nextOffset = offset + len(transfers)
	}

	return &pbssp.GetStuckTransfersResponse{
		Transfers: protoStuckTransfers,
		Offset:    int64(nextOffset),
	}, nil
}

func (h *SspRequestHandler) QueryStuckTransfer(ctx context.Context, req *pbssp.QueryStuckTransferRequest) (*pbssp.QueryStuckTransferResponse, error) {
	logger := logging.GetLoggerFromContext(ctx)
	logger.Info(fmt.Sprintf("Querying transfer with ID: %s", req.Id))

	transferID, err := uuid.Parse(req.Id)
	if err != nil {
		return nil, fmt.Errorf("Invalid transfer ID %s: %w", req.Id, err)
	}

	db := ent.GetDbFromContext(ctx)

	transfer, err := db.Transfer.Get(ctx, transferID)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, fmt.Errorf("transfer with ID %s not found", req.Id)
		}
		return nil, fmt.Errorf("failed to query transfer %s: %w", req.Id, err)
	}

	if transfer.Status == st.TransferStatusCompleted || transfer.Status == st.TransferStatusReturned {
		// This transfer isn't actually stuck, so return an error.
		return nil, fmt.Errorf("transfer %s is already completed or returned", req.Id)
	}

	stuckTransfer, err := h.marshalStuckTransfer(ctx, transfer)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal transfer %s: %w", req.Id, err)
	}

	return &pbssp.QueryStuckTransferResponse{
		Transfer: stuckTransfer,
	}, nil
}

func (h *SspRequestHandler) CancelStuckTransfer(ctx context.Context, req *pbssp.CancelStuckTransferRequest) (*pbssp.CancelStuckTransferResponse, error) {
	logger := logging.GetLoggerFromContext(ctx)
	logger.Info(fmt.Sprintf("Canceling stuck transfer with ID: %s", req.Id))

	transferID, err := uuid.Parse(req.Id)
	if err != nil {
		return nil, fmt.Errorf("invalid transfer ID %s: %w", req.Id, err)
	}

	ownerIdentityPublicKey := req.OwnerIdentityPublicKey
	if ownerIdentityPublicKey == nil {
		return nil, fmt.Errorf("owner_identity_public_key must not be nil")
	}

	db := ent.GetDbFromContext(ctx)
	transfer, err := db.Transfer.Query().ForUpdate().Where(transfer.IDEQ(transferID)).Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, fmt.Errorf("transfer with ID %s not found", req.Id)
		}
		return nil, fmt.Errorf("failed to query transfer %s: %w", req.Id, err)
	}

	if transfer.Status == st.TransferStatusCompleted || transfer.Status == st.TransferStatusReturned {
		logger.Warn("Transfer is already completed or returned, not going to update the status.", "transfer_id", transfer.ID)
	} else {
		var newStatus st.TransferStatus
		if bytes.Equal(transfer.SenderIdentityPubkey, ownerIdentityPublicKey) {
			newStatus = st.TransferStatusReturned
		} else if bytes.Equal(transfer.ReceiverIdentityPubkey, ownerIdentityPublicKey) {
			newStatus = st.TransferStatusCompleted
		} else {
			return nil, fmt.Errorf("the provided owner_identity_public_key (%x) does not match either sender or receiver of the transfer", req.OwnerIdentityPublicKey)
		}

		// Update the transfer status to returned or completed based on the owner identity public key
		transfer, err = transfer.Update().SetStatus(newStatus).Save(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to update transfer %s status to %s: %w", req.Id, newStatus, err)
		}
	}

	// Update all of the transfer leaves to LOST
	transferLeaves, err := transfer.QueryTransferLeaves().All(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to query transfer leaves for transfer %s: %w", req.Id, err)
	}

	for _, transferLeaf := range transferLeaves {
		leaf, err := transferLeaf.QueryLeaf().ForUpdate().Only(ctx)
		if err != nil {
			if ent.IsNotFound(err) {
				return nil, fmt.Errorf("transfer leaf %s not found for transfer %s", transferLeaf.ID, req.Id)
			}
			return nil, fmt.Errorf("failed to query transfer leaf %s for transfer %s: %w", transferLeaf.ID, req.Id, err)
		}

		if !(leaf.Status == st.TreeNodeStatusTransferLocked || leaf.Status == st.TreeNodeStatusLost) {
			// If the leaf is not transfer locked or already lost, we are probably in a bad situation, so return an error.
			return nil, fmt.Errorf("transfer leaf %s for transfer %s is not in a valid state to be canceled", transferLeaf.ID, req.Id)
		}

		_, err = leaf.Update().SetStatus(st.TreeNodeStatusLost).Save(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to update transfer leaf %s status to LOST for transfer %s: %w", transferLeaf.ID, req.Id, err)
		}
	}

	// Now that we have done all the updates, return the updated transfer. This should re-fetch all of
	// the leaves that are now marked as LOST.
	transferProto, err := transfer.MarshalProto(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal updated transfer %s: %w", req.Id, err)
	}

	return &pbssp.CancelStuckTransferResponse{
		Transfer: transferProto,
	}, nil
}

func (h *SspRequestHandler) marshalStuckTransfer(ctx context.Context, transfer *ent.Transfer) (*pbssp.StuckTransfer, error) {
	protoTransfer, err := transfer.MarshalProto(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal transfer %s: %w", transfer.ID, err)
	}

	leaves, err := transfer.QueryTransferLeaves().QueryLeaf().All(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to query transfer leaves for transfer %s: %w", transfer.ID, err)
	}

	protoSigningPublicKeyshares := make(map[string]*spark_ssp.SigningKeysharePublicShares)
	for _, leaf := range leaves {
		signingKeyshare, err := leaf.QuerySigningKeyshare().Only(ctx)
		if err != nil {
			if ent.IsNotFound(err) {
				return nil, fmt.Errorf("signing keyshare not found for leaf %s in transfer %s", leaf.ID, transfer.ID)
			}
			return nil, fmt.Errorf("failed to query signing keyshare for leaf %s in transfer %s: %w", leaf.ID, transfer.ID, err)
		}

		protoSigningPublicKeyshares[leaf.ID.String()] = &spark_ssp.SigningKeysharePublicShares{
			PublicShares: signingKeyshare.PublicShares,
		}
	}

	return &spark_ssp.StuckTransfer{
		Transfer:                    protoTransfer,
		SigningKeysharePublicShares: protoSigningPublicKeyshares,
	}, nil
}
