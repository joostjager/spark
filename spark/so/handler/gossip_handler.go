package handler

import (
	"context"
	"fmt"

	"github.com/lightsparkdev/spark/common/logging"
	pbgossip "github.com/lightsparkdev/spark/proto/gossip"
	"github.com/lightsparkdev/spark/so"
)

type GossipHandler struct {
	config *so.Config
}

func NewGossipHandler(config *so.Config) *GossipHandler {
	return &GossipHandler{config: config}
}

func (h *GossipHandler) HandleGossipMessage(ctx context.Context, gossipMessage *pbgossip.GossipMessage, forCoordinator bool) error {
	logger := logging.GetLoggerFromContext(ctx)
	logger.Info("handling gossip message", "gossip_id", gossipMessage.MessageId)
	switch gossipMessage.Message.(type) {
	case *pbgossip.GossipMessage_CancelTransfer:
		cancelTransfer := gossipMessage.GetCancelTransfer()
		h.handleCancelTransferGossipMessage(ctx, cancelTransfer)
	case *pbgossip.GossipMessage_MagicSwap:
		magicSwap := gossipMessage.GetMagicSwap()
		h.handleMagicSwapGossipMessage(ctx, magicSwap)
	case *pbgossip.GossipMessage_SettleSenderKeyTweak:
		settleSenderKeyTweak := gossipMessage.GetSettleSenderKeyTweak()
		h.handleSettleSenderKeyTweakGossipMessage(ctx, settleSenderKeyTweak, forCoordinator)
	case *pbgossip.GossipMessage_RollbackTransfer:
		rollbackTransfer := gossipMessage.GetRollbackTransfer()
		h.handleRollbackTransfer(ctx, rollbackTransfer)
	default:
		return fmt.Errorf("unsupported gossip message type: %T", gossipMessage.Message)
	}
	return nil
}

func (h *GossipHandler) handleCancelTransferGossipMessage(ctx context.Context, cancelTransfer *pbgossip.GossipMessageCancelTransfer) {
	transferHandler := NewBaseTransferHandler(h.config)
	err := transferHandler.CancelTransferInternal(ctx, cancelTransfer.TransferId)
	if err != nil {
		// If there's an error, it's still considered the message is delivered successfully.
		logger := logging.GetLoggerFromContext(ctx)
		logger.Error("failed to cancel transfer", "error", err, "transfer_id", cancelTransfer.TransferId)
	}
}

func (h *GossipHandler) handleMagicSwapGossipMessage(ctx context.Context, magicSwap *pbgossip.GossipMessageMagicSwap) {
	transferHandler := NewTransferHandler(h.config)
	_, err := transferHandler.TransferMagicSwapLeaves(ctx, magicSwap.TransferId, magicSwap.SwapLeafIds, magicSwap.SenderPublicKey, magicSwap.ReceiverPublicKey)
	if err != nil {
		// If there's an error, it's still considered the message is delivered successfully.
		logger := logging.GetLoggerFromContext(ctx)
		logger.Error("failed to create magic swap transfer", "error", err, "transfer_id", magicSwap.TransferId)
	}
}

func (h *GossipHandler) handleSettleSenderKeyTweakGossipMessage(ctx context.Context, settleSenderKeyTweak *pbgossip.GossipMessageSettleSenderKeyTweak, forCoordinator bool) {
	transferHandler := NewBaseTransferHandler(h.config)
	_, err := transferHandler.CommitSenderKeyTweaks(ctx, settleSenderKeyTweak.TransferId, settleSenderKeyTweak.SenderKeyTweakProofs, forCoordinator)
	if err != nil {
		// If there's an error, it's still considered the message is delivered successfully.
		logger := logging.GetLoggerFromContext(ctx)
		logger.Error("failed to settle sender key tweak", "error", err, "transfer_id", settleSenderKeyTweak.TransferId)
	}
}

func (h *GossipHandler) handleRollbackTransfer(ctx context.Context, req *pbgossip.GossipMessageRollbackTransfer) {
	logger := logging.GetLoggerFromContext(ctx)
	logger.Info("Handling rollback transfer gossip message", "transfer_id", req.TransferId)

	baseHandler := NewBaseTransferHandler(h.config)
	err := baseHandler.RollbackTransfer(ctx, req.TransferId)
	if err != nil {
		logger.Error("Failed to rollback transfer", "error", err, "transfer_id", req.TransferId)
	}
}
