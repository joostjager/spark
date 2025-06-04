package grpctest

import (
	"context"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/lightsparkdev/spark/common"
	pb "github.com/lightsparkdev/spark/proto/spark"
	testutil "github.com/lightsparkdev/spark/test_util"
	"github.com/lightsparkdev/spark/wallet"
	"github.com/stretchr/testify/require"
)

func TestTreeQuery(t *testing.T) {
	config, err := testutil.TestWalletConfig()
	if err != nil {
		t.Fatalf("failed to create wallet config: %v", err)
	}
	// Create gRPC connection using common helper
	conn, err := common.NewGRPCConnectionWithTestTLS(config.CoodinatorAddress(), nil)
	if err != nil {
		t.Fatalf("failed to connect to operator: %v", err)
	}
	defer conn.Close()

	// Authenticate the connection
	token, err := wallet.AuthenticateWithConnection(context.Background(), config, conn)
	if err != nil {
		t.Fatalf("Failed to authenticate: %v", err)
	}

	ctx := wallet.ContextWithToken(context.Background(), token)
	client := pb.NewSparkServiceClient(conn)

	// Create test nodes with parent chain
	rootPrivKey, err := secp256k1.GeneratePrivateKey()
	require.NoError(t, err)

	tree, err := testutil.CreateNewTree(config, faucet, rootPrivKey, 65536)
	require.NoError(t, err)

	// Generate tree structure for root with 2 levels
	rootTree, err := wallet.GenerateDepositAddressesForTree(ctx, config, nil, tree, uint32(0), rootPrivKey.Serialize(), 1)
	require.NoError(t, err)

	// Create initial tree with 2 levels
	treeNodes, err := wallet.CreateTree(ctx, config, nil, tree, uint32(0), rootTree, true)
	require.NoError(t, err)
	require.Len(t, treeNodes.Nodes, 5) // Root + 2 children + 2 leaves

	leafNode := treeNodes.Nodes[1]

	network, err := common.ProtoNetworkFromNetwork(config.Network)
	require.NoError(t, err, "failed to get proto network")

	t.Run("query by owner identity key", func(t *testing.T) {
		req := &pb.QueryNodesRequest{
			Source:         &pb.QueryNodesRequest_OwnerIdentityPubkey{OwnerIdentityPubkey: leafNode.OwnerIdentityPublicKey},
			IncludeParents: true,
			Network:        network,
		}

		resp, err := client.QueryNodes(ctx, req)
		require.NoError(t, err)
		require.Len(t, resp.Nodes, 6)
	})

	t.Run("query by owner identity key for regtest wallet returns empty for mainnet", func(t *testing.T) {
		networkMainnet := pb.Network_MAINNET
		req := &pb.QueryNodesRequest{
			Source:         &pb.QueryNodesRequest_OwnerIdentityPubkey{OwnerIdentityPubkey: leafNode.OwnerIdentityPublicKey},
			IncludeParents: true,
			Network:        networkMainnet,
		}

		resp, err := client.QueryNodes(ctx, req)
		require.NoError(t, err)
		require.Len(t, resp.Nodes, 0)
	})

	t.Run("query without network defaults to mainnet and returns empty for regtest test wallet", func(t *testing.T) {
		req := &pb.QueryNodesRequest{
			Source:         &pb.QueryNodesRequest_OwnerIdentityPubkey{OwnerIdentityPubkey: leafNode.OwnerIdentityPublicKey},
			IncludeParents: true,
		}

		resp, err := client.QueryNodes(ctx, req)
		require.NoError(t, err)
		require.Len(t, resp.Nodes, 0)
	})

	t.Run("query with paginations", func(t *testing.T) {
		nodeIDs := make([]string, 0, 2)
		req := &pb.QueryNodesRequest{
			Source:         &pb.QueryNodesRequest_OwnerIdentityPubkey{OwnerIdentityPubkey: leafNode.OwnerIdentityPublicKey},
			IncludeParents: false,
			Network:        network,
		}
		resp, err := client.QueryNodes(ctx, req)
		require.NoError(t, err)
		require.Len(t, resp.Nodes, 2)
		require.Equal(t, int(resp.Offset), 0)
		for id := range resp.Nodes {
			nodeIDs = append(nodeIDs, id)
		}

		req.Limit = 1
		resp, err = client.QueryNodes(ctx, req)
		require.NoError(t, err)
		require.Len(t, resp.Nodes, 1)
		require.Equal(t, int(resp.Offset), 1)
		for id := range resp.Nodes {
			require.Equal(t, id, nodeIDs[0])
		}

		req.Limit = 2
		req.Offset = resp.Offset
		resp, err = client.QueryNodes(ctx, req)
		require.NoError(t, err)
		require.Len(t, resp.Nodes, 1)
		require.Equal(t, int(resp.Offset), -1)
		for id := range resp.Nodes {
			require.Equal(t, id, nodeIDs[1])
		}
	})

	t.Run("query by node id without parents", func(t *testing.T) {
		req := &pb.QueryNodesRequest{
			Source:         &pb.QueryNodesRequest_NodeIds{NodeIds: &pb.TreeNodeIds{NodeIds: []string{leafNode.Id}}},
			IncludeParents: false,
			Network:        network,
		}

		resp, err := client.QueryNodes(ctx, req)
		require.NoError(t, err)

		require.Len(t, resp.Nodes, 1)
		node, exists := resp.Nodes[leafNode.Id]
		require.True(t, exists)
		require.Greater(t, len(node.SigningKeyshare.PublicKey), 0)
	})

	t.Run("query by node id with parents", func(t *testing.T) {
		req := &pb.QueryNodesRequest{
			Source:         &pb.QueryNodesRequest_NodeIds{NodeIds: &pb.TreeNodeIds{NodeIds: []string{leafNode.Id}}},
			IncludeParents: true,
			Network:        network,
		}

		resp, err := client.QueryNodes(ctx, req)
		require.NoError(t, err)

		require.Len(t, resp.Nodes, 3)
		_, exists := resp.Nodes[leafNode.Id]
		require.True(t, exists)
		_, exists = resp.Nodes[treeNodes.Nodes[0].Id]
		require.True(t, exists)
	})

	t.Run("query nodes distribution", func(t *testing.T) {
		req := &pb.QueryNodesDistributionRequest{
			OwnerIdentityPublicKey: leafNode.OwnerIdentityPublicKey,
		}

		resp, err := client.QueryNodesDistribution(ctx, req)
		require.NoError(t, err)
		require.Equal(t, len(resp.NodeDistribution), 1)
		t.Logf("resp.NodeDistribution: %v", resp.NodeDistribution)
		for _, v := range resp.NodeDistribution {
			require.Equal(t, v, uint64(2))
		}
	})

	t.Run("query nodes by value", func(t *testing.T) {
		rootPrivKey2, err := secp256k1.GeneratePrivateKey()
		require.NoError(t, err)
		tree2, err := testutil.CreateNewTree(config, faucet, rootPrivKey2, 32768)
		require.NoError(t, err)
		rootTree2, err := wallet.GenerateDepositAddressesForTree(ctx, config, nil, tree2, uint32(0), rootPrivKey2.Serialize(), 1)
		require.NoError(t, err)
		tree2Nodes, err := wallet.CreateTree(ctx, config, nil, tree2, uint32(0), rootTree2, true)
		require.NoError(t, err)
		require.Len(t, tree2Nodes.Nodes, 5)

		req := &pb.QueryNodesByValueRequest{
			OwnerIdentityPublicKey: leafNode.OwnerIdentityPublicKey,
			Limit:                  1,
			Offset:                 0,
			Value:                  30857,
		}
		resp, err := client.QueryNodesByValue(ctx, req)
		require.NoError(t, err)
		require.Len(t, resp.Nodes, 1)
		require.Equal(t, int(resp.Offset), 1)

		req.Offset = 1
		resp, err = client.QueryNodesByValue(ctx, req)
		require.NoError(t, err)
		require.Len(t, resp.Nodes, 1)
		require.Equal(t, int(resp.Offset), 2)

		req.Offset = 2
		resp, err = client.QueryNodesByValue(ctx, req)
		require.NoError(t, err)
		require.Len(t, resp.Nodes, 0)
		require.Equal(t, int(resp.Offset), -1)

		req.Value = 14473
		req.Offset = 0
		resp, err = client.QueryNodesByValue(ctx, req)
		require.NoError(t, err)
		require.Len(t, resp.Nodes, 1)
		require.Equal(t, int(resp.Offset), 1)
	})
}
