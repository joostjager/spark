package watchtower

import (
	"context"
	"encoding/hex"
	"fmt"
	"log/slog"

	"github.com/btcsuite/btcd/btcjson"
	"github.com/btcsuite/btcd/rpcclient"
	"github.com/lightsparkdev/spark/common"
	"github.com/lightsparkdev/spark/so/ent"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

var (
	meter = otel.Meter("watchtower")

	// Metrics
	nodeTxBroadcastCounter   metric.Int64Counter
	refundTxBroadcastCounter metric.Int64Counter
)

func init() {
	var err error

	nodeTxBroadcastCounter, err = meter.Int64Counter(
		"watchtower.node_tx.broadcast_total",
		metric.WithDescription("Total number of node transactions broadcast by watchtower"),
	)
	if err != nil {
		slog.Error("Failed to create node tx broadcast counter", "error", err)
	}

	refundTxBroadcastCounter, err = meter.Int64Counter(
		"watchtower.refund_tx.broadcast_total",
		metric.WithDescription("Total number of refund transactions broadcast by watchtower"),
	)
	if err != nil {
		slog.Error("Failed to create refund tx broadcast counter", "error", err)
	}
}

// BroadcastTransaction broadcasts a transaction to the network
func BroadcastTransaction(ctx context.Context, bitcoinClient *rpcclient.Client, nodeID string, txBytes []byte) error {
	tx, err := common.TxFromRawTxBytes(txBytes)
	if err != nil {
		return fmt.Errorf("failed to parse transaction: %v", err)
	}

	// TODO: Broadcast Direct Refund TX.
	slog.InfoContext(ctx, "Attempting to broadcast transaction", "tx", tx)
	txHash, err := bitcoinClient.SendRawTransaction(tx, false)
	if err != nil {
		if rpcErr, ok := err.(*btcjson.RPCError); ok && rpcErr.Code == -27 {
			// This means another SO has already broadcasted the tx
			slog.InfoContext(ctx, "Transaction already in mempool", "node_id", nodeID)
			return nil
		}

		return fmt.Errorf("failed to broadcast transaction: %v", err)
	}

	slog.InfoContext(ctx, "Successfully broadcast transaction", "tx_hash", hex.EncodeToString(txHash[:]))
	return nil
}

// CheckExpiredTimeLocks checks for TXs with expired time locks and broadcasts them if needed.
func CheckExpiredTimeLocks(ctx context.Context, bitcoinClient *rpcclient.Client, node *ent.TreeNode, blockHeight int64, network common.Network) error {
	if node.NodeConfirmationHeight == 0 {
		nodeTx, err := common.TxFromRawTxBytes(node.RawTx)
		if err != nil {
			return fmt.Errorf("failed to parse node tx: %v", err)
		}
		// Check if node TX has a timelock and has parent
		if nodeTx.TxIn[0].Sequence <= 0xFFFFFFFE {
			// Check if parent is confirmed and timelock has expired
			parent, err := node.QueryParent().Only(ctx)
			if err != nil {
				return fmt.Errorf("failed to query parent: %v", err)
			}
			if parent.NodeConfirmationHeight > 0 {
				timelockExpiryHeight := uint64(nodeTx.TxIn[0].Sequence&0xFFFF) + parent.NodeConfirmationHeight
				if timelockExpiryHeight <= uint64(blockHeight) {
					if err := BroadcastTransaction(ctx, bitcoinClient, node.ID.String(), node.RawTx); err != nil {
						// Record node tx broadcast failure
						if nodeTxBroadcastCounter != nil {
							nodeTxBroadcastCounter.Add(ctx, 1, metric.WithAttributes(
								attribute.String("network", network.String()),
								attribute.String("result", "failure"),
							))
						}
						slog.InfoContext(ctx, "Failed to broadcast node tx", "error", err)
						return fmt.Errorf("failed to broadcast node tx: %v", err)
					}

					// Record successful node tx broadcast
					if nodeTxBroadcastCounter != nil {
						nodeTxBroadcastCounter.Add(ctx, 1, metric.WithAttributes(
							attribute.String("network", network.String()),
							attribute.String("result", "success"),
						))
					}
				}
			}
		}
	} else if len(node.RawRefundTx) > 0 && node.RefundConfirmationHeight == 0 {
		refundTx, err := common.TxFromRawTxBytes(node.RawRefundTx)
		if err != nil {
			return fmt.Errorf("failed to parse refund tx: %v", err)
		}

		timelockExpiryHeight := uint64(refundTx.TxIn[0].Sequence&0xFFFF) + node.NodeConfirmationHeight
		if timelockExpiryHeight <= uint64(blockHeight) {
			if err := BroadcastTransaction(ctx, bitcoinClient, node.ID.String(), node.RawRefundTx); err != nil {
				// Record refund tx broadcast failure
				if refundTxBroadcastCounter != nil {
					refundTxBroadcastCounter.Add(ctx, 1, metric.WithAttributes(
						attribute.String("network", network.String()),
						attribute.String("result", "failure"),
					))
				}
				slog.InfoContext(ctx, "Failed to broadcast refund tx", "error", err)
				return fmt.Errorf("failed to broadcast refund tx: %v", err)
			}

			// Record successful refund tx broadcast
			if refundTxBroadcastCounter != nil {
				refundTxBroadcastCounter.Add(ctx, 1, metric.WithAttributes(
					attribute.String("network", network.String()),
					attribute.String("result", "success"),
				))
			}
		}
	}

	return nil
}
