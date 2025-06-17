package grpctest

import (
	"context"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/google/uuid"
	"github.com/lightsparkdev/spark/common"
	mock "github.com/lightsparkdev/spark/proto/mock"
	pb "github.com/lightsparkdev/spark/proto/spark"
	pbssp "github.com/lightsparkdev/spark/proto/spark_ssp_internal"
	testutil "github.com/lightsparkdev/spark/test_util"
	"github.com/lightsparkdev/spark/wallet"
	"github.com/stretchr/testify/require"
)

func TestQueryLostNodes(t *testing.T) {
	config, err := testutil.TestWalletConfig()
	if err != nil {
		t.Fatalf("failed to create wallet config: %v", err)
	}

	priKey, err := secp256k1.GeneratePrivateKey()
	require.NoError(t, err, "failed to create node signing private key")
	root, err := testutil.CreateNewTree(config, faucet, priKey, 100_000)
	require.NoError(t, err, "failed to create new tree")

	conn, err := common.NewGRPCConnectionWithTestTLS(config.CoodinatorAddress(), nil)
	require.NoError(t, err, "failed to create gRPC connection")
	defer conn.Close()

	client := pb.NewSparkServiceClient(conn)
	network, err := common.ProtoNetworkFromNetwork(config.Network)
	require.NoError(t, err, "failed to get proto network")
	resp, err := client.QueryNodes(context.Background(), &pb.QueryNodesRequest{
		Source:         &pb.QueryNodesRequest_OwnerIdentityPubkey{OwnerIdentityPubkey: root.OwnerIdentityPublicKey},
		IncludeParents: false,
		Network:        network,
	})
	require.NoError(t, err)
	require.Len(t, resp.Nodes, 1)
	leafID := ""
	for _, node := range resp.Nodes {
		leafID = node.Id
	}

	sparkSspClient := pbssp.NewSparkSspInternalServiceClient(conn)
	response, err := sparkSspClient.QueryLostNodes(context.Background(), &pbssp.QueryLostNodesRequest{})
	require.NoError(t, err, "failed to query lost nodes")
	require.Len(t, response.Nodes, 0)

	mockClient := mock.NewMockServiceClient(conn)
	_, err = mockClient.UpdateNodesStatus(context.Background(), &mock.UpdateNodesStatusRequest{
		NodeIds: []string{leafID},
		Status:  "LOST",
	})
	require.NoError(t, err, "failed to mark node LOST")

	response, err = sparkSspClient.QueryLostNodes(context.Background(), &pbssp.QueryLostNodesRequest{})
	require.NoError(t, err, "failed to query lost nodes")
	require.Len(t, response.Nodes, 1)
}

func TestMagicSwap(t *testing.T) {
	// Create user nodes
	userConfig, err := testutil.TestWalletConfig()
	require.NoError(t, err)
	userLeafKey1, err := secp256k1.GeneratePrivateKey()
	require.NoError(t, err, "failed to create user signing private key")
	userNode1, err := testutil.CreateNewTree(userConfig, faucet, userLeafKey1, 100_000)
	require.NoError(t, err, "failed to create tree")
	userLeafKey2, err := secp256k1.GeneratePrivateKey()
	require.NoError(t, err, "failed to create user signing private key")
	userNode2, err := testutil.CreateNewTree(userConfig, faucet, userLeafKey2, 100_000)
	require.NoError(t, err, "failed to create tree")

	// Create ssp nodes
	sspConfig, err := testutil.TestWalletConfig()
	require.NoError(t, err)
	sspLeafKey, err := secp256k1.GeneratePrivateKey()
	require.NoError(t, err, "failed to create ssp signing private key")
	sspNode, err := testutil.CreateNewTree(sspConfig, faucet, sspLeafKey, 200_000)
	require.NoError(t, err, "failed to create tree")
	newSspLeafKey, err := secp256k1.GeneratePrivateKey()
	require.NoError(t, err, "failed to create new ssp signing private key")

	// SSP do magic swap with user nodes
	sspNodeKeyTweak := wallet.LeafKeyTweak{
		Leaf:              sspNode,
		SigningPrivKey:    sspLeafKey.Serialize(),
		NewSigningPrivKey: newSspLeafKey.Serialize(),
	}
	sspLeavesToTransfer := [1]wallet.LeafKeyTweak{sspNodeKeyTweak}

	conn, err := common.NewGRPCConnectionWithTestTLS(sspConfig.CoodinatorAddress(), nil)
	require.NoError(t, err, "failed to create grpc connection")
	defer conn.Close()

	sspAuthToken, err := wallet.AuthenticateWithServer(context.Background(), sspConfig)
	require.NoError(t, err, "failed to create auth token for SSP")
	sspCtx := wallet.ContextWithToken(context.Background(), sspAuthToken)
	transferID, err := uuid.NewV7()
	require.NoError(t, err, "failed to transfer ID")
	transferPackage, err := wallet.CreateTransferPackage(
		sspCtx,
		transferID,
		sspConfig,
		pb.NewSparkServiceClient(conn),
		sspLeavesToTransfer[:],
		userConfig.IdentityPublicKey(),
	)
	require.NoError(t, err, "failed to create transfer package")

	sparkSspClient := pbssp.NewSparkSspInternalServiceClient(conn)
	magicSwapResp, err := sparkSspClient.MagicSwap(sspCtx, &pbssp.MagicSwapRequest{
		TransferId:                transferID.String(),
		OwnerIdentityPublicKey:    sspConfig.IdentityPublicKey(),
		ReceiverIdentityPublicKey: userConfig.IdentityPublicKey(),
		TransferPackage:           transferPackage,
		SwapLeafIds:               []string{userNode1.Id, userNode2.Id},
	})
	require.NoError(t, err, "failed to make magic swap")

	// User claims the transfer
	userAuthToken, err := wallet.AuthenticateWithServer(context.Background(), userConfig)
	require.NoError(t, err, "failed to create auth token for user")
	userCtx := wallet.ContextWithToken(context.Background(), userAuthToken)
	userPendingTransfersResp, err := wallet.QueryPendingTransfers(userCtx, userConfig)
	require.NoError(t, err)
	require.Len(t, userPendingTransfersResp.Transfers, 1)
	require.Equal(t, userPendingTransfersResp.Transfers[0].Id, magicSwapResp.CounterSwapTransfer.Id)

	newUserLeafKey, err := secp256k1.GeneratePrivateKey()
	require.NoError(t, err, "failed to create new node signing private key")
	claimingNode := wallet.LeafKeyTweak{
		Leaf:              userPendingTransfersResp.Transfers[0].Leaves[0].Leaf,
		SigningPrivKey:    newSspLeafKey.Serialize(),
		NewSigningPrivKey: newUserLeafKey.Serialize(),
	}
	leavesToClaim := [1]wallet.LeafKeyTweak{claimingNode}
	_, err = wallet.ClaimTransfer(
		userCtx,
		userPendingTransfersResp.Transfers[0],
		userConfig,
		leavesToClaim[:],
	)
	require.NoError(t, err)

	// Check SSP now owns the user nodes
	network, err := common.ProtoNetworkFromNetwork(sspConfig.Network)
	require.NoError(t, err, "failed to get network")

	sparkClient := pb.NewSparkServiceClient(conn)
	sspNodeQueryResp, err := sparkClient.QueryNodes(sspCtx, &pb.QueryNodesRequest{
		Source:         &pb.QueryNodesRequest_OwnerIdentityPubkey{OwnerIdentityPubkey: sspConfig.IdentityPublicKey()},
		IncludeParents: true,
		Network:        network,
	})
	require.NoError(t, err)
	require.Len(t, sspNodeQueryResp.Nodes, 2)
	for _, node := range sspNodeQueryResp.Nodes {
		require.True(t, node.Id == userNode1.Id || node.Id == userNode2.Id)
	}

	// Check user now owns the ssp node
	userNodeQueryResp, err := sparkClient.QueryNodes(sspCtx, &pb.QueryNodesRequest{
		Source:         &pb.QueryNodesRequest_OwnerIdentityPubkey{OwnerIdentityPubkey: userConfig.IdentityPublicKey()},
		IncludeParents: true,
		Network:        network,
	})
	require.NoError(t, err)
	require.Len(t, userNodeQueryResp.Nodes, 1)
	for _, node := range userNodeQueryResp.Nodes {
		require.True(t, node.Id == sspNode.Id)
	}
}
