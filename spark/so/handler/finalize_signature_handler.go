package handler

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/lightsparkdev/spark/common"
	"github.com/lightsparkdev/spark/common/logging"
	pbcommon "github.com/lightsparkdev/spark/proto/common"
	pb "github.com/lightsparkdev/spark/proto/spark"
	pbinternal "github.com/lightsparkdev/spark/proto/spark_internal"
	"github.com/lightsparkdev/spark/so"
	"github.com/lightsparkdev/spark/so/ent"
	"github.com/lightsparkdev/spark/so/ent/depositaddress"
	st "github.com/lightsparkdev/spark/so/ent/schema/schematype"
	"github.com/lightsparkdev/spark/so/ent/signingkeyshare"
	enttransfer "github.com/lightsparkdev/spark/so/ent/transfer"
	"github.com/lightsparkdev/spark/so/ent/transferleaf"
	"github.com/lightsparkdev/spark/so/ent/treenode"
	"github.com/lightsparkdev/spark/so/helper"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// FinalizeSignatureHandler is the handler for the FinalizeNodeSignatures RPC.
type FinalizeSignatureHandler struct {
	config *so.Config
}

// NewFinalizeSignatureHandler creates a new FinalizeSignatureHandler.
func NewFinalizeSignatureHandler(config *so.Config) *FinalizeSignatureHandler {
	return &FinalizeSignatureHandler{config: config}
}

// FinalizeNodeSignatures verifies the node signatures and updates the node.
func (o *FinalizeSignatureHandler) FinalizeNodeSignatures(ctx context.Context, req *pb.FinalizeNodeSignaturesRequest) (*pb.FinalizeNodeSignaturesResponse, error) {
	if len(req.NodeSignatures) == 0 {
		return &pb.FinalizeNodeSignaturesResponse{Nodes: []*pb.TreeNode{}}, nil
	}

	var transfer *ent.Transfer
	if req.Intent == pbcommon.SignatureIntent_TRANSFER {
		var err error
		transfer, err = o.verifyAndUpdateTransfer(ctx, req)
		if err != nil {
			return nil, fmt.Errorf("failed to verify and update transfer for request %s: %w", logging.FormatProto("finalize_node_signatures_request", req), err)
		}
	}

	db := ent.GetDbFromContext(ctx)
	firstNodeID, err := uuid.Parse(req.NodeSignatures[0].NodeId)
	if err != nil {
		return nil, fmt.Errorf("invalid node id in request %s: %w", logging.FormatProto("finalize_node_signatures_request", req), err)
	}
	firstNode, err := db.TreeNode.Get(ctx, firstNodeID)
	if err != nil {
		return nil, fmt.Errorf("failed to get first node for request %s: %w", logging.FormatProto("finalize_node_signatures_request", req), err)
	}
	tree, err := firstNode.QueryTree().Only(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get tree for request %s: %w", logging.FormatProto("finalize_node_signatures_request", req), err)
	}
	network, err := common.NetworkFromSchemaNetwork(tree.Network)
	if err != nil {
		return nil, fmt.Errorf("failed to get network for request %s: %w", logging.FormatProto("finalize_node_signatures_request", req), err)
	}

	if tree.Status != st.TreeStatusAvailable {
		for _, nodeSignatures := range req.NodeSignatures {
			nodeID, err := uuid.Parse(nodeSignatures.NodeId)
			if err != nil {
				return nil, fmt.Errorf("invalid node id in request %s: %w", logging.FormatProto("finalize_node_signatures_request", req), err)
			}
			node, err := db.TreeNode.Get(ctx, nodeID)
			if err != nil {
				return nil, fmt.Errorf("failed to get node for request %s: %w", logging.FormatProto("finalize_node_signatures_request", req), err)
			}
			signingKeyshare, err := node.QuerySigningKeyshare().Only(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to get signing keyshare: %w", err)
			}
			address, err := db.DepositAddress.Query().Where(depositaddress.HasSigningKeyshareWith(signingkeyshare.IDEQ(signingKeyshare.ID))).Only(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to get deposit address: %w", err)
			}
			if address.ConfirmationHeight != 0 {
				_, err = tree.Update().SetStatus(st.TreeStatusAvailable).Save(ctx)
				if err != nil {
					return nil, fmt.Errorf("failed to update tree: %w", err)
				}
				break
			}
		}
	}

	nodes := make([]*pb.TreeNode, 0)
	internalNodes := make([]*pbinternal.TreeNode, 0)
	for _, nodeSignatures := range req.NodeSignatures {
		node, internalNode, err := o.updateNode(ctx, nodeSignatures, req.Intent)
		if err != nil {
			return nil, fmt.Errorf("failed to update node for request %s: %w", logging.FormatProto("finalize_node_signatures_request", req), err)
		}
		nodes = append(nodes, node)
		internalNodes = append(internalNodes, internalNode)
	}
	// Sync with all other SOs
	selection := helper.OperatorSelection{Option: helper.OperatorSelectionOptionExcludeSelf}
	_, err = helper.ExecuteTaskWithAllOperators(ctx, o.config, &selection, func(ctx context.Context, operator *so.SigningOperator) (interface{}, error) {
		conn, err := operator.NewGRPCConnection()
		if err != nil {
			return nil, fmt.Errorf("failed to connect to %s: %w", operator.Address, err)
		}
		defer conn.Close()

		client := pbinternal.NewSparkInternalServiceClient(conn)

		switch req.Intent {
		case pbcommon.SignatureIntent_CREATION:
			protoNetwork, err := common.ProtoNetworkFromNetwork(network)
			if err != nil {
				return nil, err
			}
			_, err = client.FinalizeTreeCreation(ctx, &pbinternal.FinalizeTreeCreationRequest{Nodes: internalNodes, Network: protoNetwork})
			return nil, err
		case pbcommon.SignatureIntent_AGGREGATE:
			_, err = client.FinalizeNodesAggregation(ctx, &pbinternal.FinalizeNodesAggregationRequest{Nodes: internalNodes})
			return nil, err
		case pbcommon.SignatureIntent_TRANSFER:
			_, err = client.FinalizeTransfer(ctx, &pbinternal.FinalizeTransferRequest{TransferId: transfer.ID.String(), Nodes: internalNodes, Timestamp: timestamppb.New(*transfer.CompletionTime)})
			return nil, err
		case pbcommon.SignatureIntent_REFRESH:
			_, err = client.FinalizeRefreshTimelock(ctx, &pbinternal.FinalizeRefreshTimelockRequest{Nodes: internalNodes})
			if err != nil {
				return nil, fmt.Errorf("finalize refresh failed for request %s: %w", logging.FormatProto("finalize_node_signatures_request", req), err)
			}
			return nil, nil
		case pbcommon.SignatureIntent_EXTEND:
			if len(internalNodes) == 0 {
				return nil, fmt.Errorf("no nodes to extend")
			}
			_, err = client.FinalizeExtendLeaf(ctx, &pbinternal.FinalizeExtendLeafRequest{Node: internalNodes[0]})
			if err != nil {
				return nil, fmt.Errorf("finalize extend failed for request %s: %w", logging.FormatProto("finalize_node_signatures_request", req), err)
			}
			return nil, nil
		}
		return nil, err
	})
	if err != nil {
		return nil, err
	}

	return &pb.FinalizeNodeSignaturesResponse{Nodes: nodes}, nil
}

func (o *FinalizeSignatureHandler) verifyAndUpdateTransfer(ctx context.Context, req *pb.FinalizeNodeSignaturesRequest) (*ent.Transfer, error) {
	db := ent.GetDbFromContext(ctx)
	var transfer *ent.Transfer
	for _, nodeSignatures := range req.NodeSignatures {
		leafID, err := uuid.Parse(nodeSignatures.NodeId)
		if err != nil {
			return nil, fmt.Errorf("invalid node id in request %s: %w", logging.FormatProto("finalize_node_signatures_request", req), err)
		}
		leafTransfer, err := db.Transfer.Query().
			Where(
				enttransfer.StatusEQ(st.TransferStatusReceiverRefundSigned),
				enttransfer.HasTransferLeavesWith(
					transferleaf.HasLeafWith(
						treenode.IDEQ(leafID),
					),
				),
			).
			Only(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to find pending transfer for leaf %s: %w", leafID.String(), err)
		}
		if transfer == nil {
			transfer = leafTransfer
		} else if transfer.ID != leafTransfer.ID {
			return nil, fmt.Errorf("expect all leaves to belong to the same transfer")
		}
	}
	numTransferLeaves, err := transfer.QueryTransferLeaves().Count(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get the number of transfer leaves for transfer %s: %w", transfer.ID.String(), err)
	}
	if len(req.NodeSignatures) != numTransferLeaves {
		return nil, fmt.Errorf("missing signatures for transfer %s", transfer.ID.String())
	}

	transfer, err = transfer.Update().SetStatus(st.TransferStatusCompleted).SetCompletionTime(time.Now()).Save(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to update transfer %s: %w", transfer.ID.String(), err)
	}
	return transfer, nil
}

func (o *FinalizeSignatureHandler) updateNode(ctx context.Context, nodeSignatures *pb.NodeSignatures, intent pbcommon.SignatureIntent) (*pb.TreeNode, *pbinternal.TreeNode, error) {
	db := ent.GetDbFromContext(ctx)

	nodeID, err := uuid.Parse(nodeSignatures.NodeId)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid node id in %s: %w", logging.FormatProto("node_signatures", nodeSignatures), err)
	}

	// Read the tree node
	node, err := db.TreeNode.Get(ctx, nodeID)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get node in %s: %w", logging.FormatProto("node_signatures", nodeSignatures), err)
	}
	if node == nil {
		return nil, nil, fmt.Errorf("node not found in %s", logging.FormatProto("node_signatures", nodeSignatures))
	}

	var nodeTxBytes []byte
	if intent == pbcommon.SignatureIntent_CREATION || ((intent == pbcommon.SignatureIntent_REFRESH || intent == pbcommon.SignatureIntent_EXTEND) && nodeSignatures.NodeTxSignature != nil) {
		nodeTxBytes, err = common.UpdateTxWithSignature(node.RawTx, 0, nodeSignatures.NodeTxSignature)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to update tx with signature %s: %w", logging.FormatProto("node_signatures", nodeSignatures), err)
		}
		// Node may not have parent if it is the root node
		nodeParent, err := node.QueryParent().Only(ctx)
		if err == nil && nodeParent != nil {
			treeNodeTx, err := common.TxFromRawTxBytes(nodeTxBytes)
			if err != nil {
				return nil, nil, fmt.Errorf("unable to deserialize node tx: %w", err)
			}
			treeNodeParentTx, err := common.TxFromRawTxBytes(nodeParent.RawTx)
			if err != nil {
				return nil, nil, fmt.Errorf("unable to deserialize parent tx: %w", err)
			}
			if len(treeNodeParentTx.TxOut) <= int(node.Vout) {
				return nil, nil, fmt.Errorf("vout out of bounds")
			}
			err = common.VerifySignatureSingleInput(treeNodeTx, 0, treeNodeParentTx.TxOut[node.Vout])
			if err != nil {
				return nil, nil, fmt.Errorf("unable to verify node tx signature: %w", err)
			}
		}
	} else {
		nodeTxBytes = node.RawTx
	}
	var refundTxBytes []byte
	if len(nodeSignatures.RefundTxSignature) > 0 {
		refundTxBytes, err = common.UpdateTxWithSignature(node.RawRefundTx, 0, nodeSignatures.RefundTxSignature)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to update refund tx with signature %s: %w", logging.FormatProto("node_signatures", nodeSignatures), err)
		}

		refundTx, err := common.TxFromRawTxBytes(refundTxBytes)
		if err != nil {
			return nil, nil, fmt.Errorf("unable to deserialize refund tx %s: %w", logging.FormatProto("node_signatures", nodeSignatures), err)
		}
		treeNodeTx, err := common.TxFromRawTxBytes(nodeTxBytes)
		if err != nil {
			return nil, nil, fmt.Errorf("unable to deserialize leaf tx: %w", err)
		}
		if len(treeNodeTx.TxOut) <= 0 {
			return nil, nil, fmt.Errorf("vout out of bounds")
		}
		err = common.VerifySignatureSingleInput(refundTx, 0, treeNodeTx.TxOut[0])
		if err != nil {
			return nil, nil, fmt.Errorf("unable to verify refund tx signature: %w", err)
		}
	} else {
		refundTxBytes = node.RawRefundTx
	}

	tree, err := node.QueryTree().Only(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get tree: %w", err)
	}

	// Update the tree node
	nodeMutator := node.Update().
		SetRawTx(nodeTxBytes).
		SetRawRefundTx(refundTxBytes)
	if tree.Status == st.TreeStatusAvailable {
		if len(node.RawRefundTx) > 0 {
			nodeMutator.SetStatus(st.TreeNodeStatusAvailable)
		} else {
			nodeMutator.SetStatus(st.TreeNodeStatusSplitted)
		}
	}
	node, err = nodeMutator.Save(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to update node: %w", err)
	}

	nodeSparkProto, err := node.MarshalSparkProto(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to marshal node %s on spark: %w", node.ID.String(), err)
	}
	internalNode, err := node.MarshalInternalProto(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to marshal node %s on internal: %w", node.ID.String(), err)
	}
	return nodeSparkProto, internalNode, nil
}
