package handler

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/google/uuid"
	"github.com/lightsparkdev/spark/common"
	"github.com/lightsparkdev/spark/common/logging"
	secretsharing "github.com/lightsparkdev/spark/common/secret_sharing"
	pbcommon "github.com/lightsparkdev/spark/proto/common"
	pbfrost "github.com/lightsparkdev/spark/proto/frost"
	pbgossip "github.com/lightsparkdev/spark/proto/gossip"
	pb "github.com/lightsparkdev/spark/proto/spark"
	pbinternal "github.com/lightsparkdev/spark/proto/spark_internal"
	"github.com/lightsparkdev/spark/so"
	"github.com/lightsparkdev/spark/so/authn"
	"github.com/lightsparkdev/spark/so/authz"
	"github.com/lightsparkdev/spark/so/ent"
	"github.com/lightsparkdev/spark/so/ent/preimagerequest"
	"github.com/lightsparkdev/spark/so/ent/preimageshare"
	st "github.com/lightsparkdev/spark/so/ent/schema/schematype"
	"github.com/lightsparkdev/spark/so/ent/treenode"
	"github.com/lightsparkdev/spark/so/helper"
	decodepay "github.com/nbd-wtf/ln-decodepay"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/emptypb"
)

// LightningHandler is the handler for the lightning service.
type LightningHandler struct {
	config *so.Config
}

// NewLightningHandler returns a new LightningHandler.
func NewLightningHandler(config *so.Config) *LightningHandler {
	return &LightningHandler{config: config}
}

// StorePreimageShare stores the preimage share for the given payment hash.
func (h *LightningHandler) StorePreimageShare(ctx context.Context, req *pb.StorePreimageShareRequest) error {
	err := secretsharing.ValidateShare(
		&secretsharing.VerifiableSecretShare{
			SecretShare: secretsharing.SecretShare{
				FieldModulus: secp256k1.S256().N,
				Threshold:    int(h.config.Threshold),
				Index:        big.NewInt(int64(h.config.Index + 1)),
				Share:        new(big.Int).SetBytes(req.PreimageShare.SecretShare),
			},
			Proofs: req.PreimageShare.Proofs,
		},
	)
	if err != nil {
		return fmt.Errorf("unable to validate share: %w", err)
	}

	bolt11, err := decodepay.Decodepay(req.InvoiceString)
	if err != nil {
		return fmt.Errorf("unable to decode invoice: %w", err)
	}

	paymentHash, err := hex.DecodeString(bolt11.PaymentHash)
	if err != nil {
		return fmt.Errorf("unable to decode payment hash: %w", err)
	}

	if !bytes.Equal(paymentHash, req.PaymentHash) {
		return fmt.Errorf("payment hash mismatch")
	}

	db := ent.GetDbFromContext(ctx)
	_, err = db.PreimageShare.Create().
		SetPaymentHash(req.PaymentHash).
		SetPreimageShare(req.PreimageShare.SecretShare).
		SetThreshold(int32(req.Threshold)).
		SetInvoiceString(req.InvoiceString).
		SetOwnerIdentityPubkey(req.UserIdentityPublicKey).
		Save(ctx)
	if err != nil {
		return fmt.Errorf("unable to store preimage share: %w", err)
	}
	return nil
}

func (h *LightningHandler) validateNodeOwnership(ctx context.Context, nodes []*ent.TreeNode) error {
	if !h.config.AuthzEnforced() {
		return nil
	}

	session, err := authn.GetSessionFromContext(ctx)
	if err != nil {
		return err
	}
	sessionIdentityPubkeyBytes := session.IdentityPublicKeyBytes()

	var mismatchedNodes []string
	for _, node := range nodes {
		if !bytes.Equal(node.OwnerIdentityPubkey, sessionIdentityPubkeyBytes) {
			mismatchedNodes = append(mismatchedNodes, node.ID.String())
		}
	}

	if len(mismatchedNodes) > 0 {
		return &authz.Error{
			Code: authz.ErrorCodeIdentityMismatch,
			Message: fmt.Sprintf("nodes [%s] are not owned by the authenticated identity public key %x",
				strings.Join(mismatchedNodes, ", "),
				sessionIdentityPubkeyBytes),
			Cause: nil,
		}
	}
	return nil
}

func (h *LightningHandler) validateHasSession(ctx context.Context) error {
	if h.config.AuthzEnforced() {
		_, err := authn.GetSessionFromContext(ctx)
		if err != nil {
			return err
		}
	}
	return nil
}

// GetSigningCommitments gets the signing commitments for the given node ids.
func (h *LightningHandler) GetSigningCommitments(ctx context.Context, req *pb.GetSigningCommitmentsRequest) (*pb.GetSigningCommitmentsResponse, error) {
	if err := h.validateHasSession(ctx); err != nil {
		return nil, err
	}

	db := ent.GetDbFromContext(ctx)
	nodeIDs := make([]uuid.UUID, len(req.NodeIds))
	for i, nodeID := range req.NodeIds {
		nodeID, err := uuid.Parse(nodeID)
		if err != nil {
			return nil, fmt.Errorf("unable to parse node id: %w", err)
		}
		nodeIDs[i] = nodeID
	}

	nodes, err := db.TreeNode.Query().Where(treenode.IDIn(nodeIDs...)).All(ctx)
	if err != nil {
		return nil, fmt.Errorf("unable to get nodes: %w", err)
	}

	if err := h.validateNodeOwnership(ctx, nodes); err != nil {
		return nil, err
	}

	keyshareIDs := make([]uuid.UUID, len(nodes))
	for i, node := range nodes {
		keyshareIDs[i], err = node.QuerySigningKeyshare().OnlyID(ctx)
		if err != nil {
			return nil, fmt.Errorf("unable to get keyshare id: %w", err)
		}
	}

	commitments, err := helper.GetSigningCommitments(ctx, h.config, keyshareIDs)
	if err != nil {
		return nil, fmt.Errorf("unable to get signing commitments: %w", err)
	}

	commitmentsArray := common.MapOfArrayToArrayOfMap(commitments)

	requestedCommitments := make([]*pb.RequestedSigningCommitments, len(commitmentsArray))

	for i, commitment := range commitmentsArray {
		commitmentMapProto, err := common.ConvertObjectMapToProtoMap(commitment)
		if err != nil {
			return nil, fmt.Errorf("unable to convert signing commitment to proto: %w", err)
		}
		requestedCommitments[i] = &pb.RequestedSigningCommitments{
			SigningNonceCommitments: commitmentMapProto,
		}
	}

	return &pb.GetSigningCommitmentsResponse{SigningCommitments: requestedCommitments}, nil
}

func (h *LightningHandler) validateGetPreimageRequest(
	ctx context.Context,
	paymentHash []byte,
	transactions []*pb.UserSignedTxSigningJob,
	amount *pb.InvoiceAmount,
	destinationPubkey []byte,
	feeSats uint64,
	reason pb.InitiatePreimageSwapRequest_Reason,
) error {
	logger := logging.GetLoggerFromContext(ctx)

	// Step 0 Validate that there's no existing preimage request for this payment hash
	db := ent.GetDbFromContext(ctx)
	preimageRequests, err := db.PreimageRequest.Query().Where(
		preimagerequest.PaymentHashEQ(paymentHash),
		preimagerequest.ReceiverIdentityPubkeyEQ(destinationPubkey),
		preimagerequest.StatusNEQ(st.PreimageRequestStatusReturned),
	).All(ctx)
	if err != nil {
		return fmt.Errorf("unable to get preimage request: %w", err)
	}
	if len(preimageRequests) > 0 {
		return fmt.Errorf("preimage request already exists")
	}

	// Step 1 validate all signatures are valid
	conn, err := common.NewGRPCConnectionWithoutTLS(h.config.SignerAddress, nil)
	if err != nil {
		return fmt.Errorf("unable to connect to signer: %w", err)
	}
	defer conn.Close()

	client := pbfrost.NewFrostServiceClient(conn)
	for _, transaction := range transactions {
		if transaction == nil {
			return fmt.Errorf("transaction is nil")
		}
		if transaction.SigningCommitments == nil {
			return fmt.Errorf("signing commitments is nil")
		}
		if transaction.SigningNonceCommitment == nil {
			return fmt.Errorf("signing nonce commitment is nil")
		}
		// First fetch the node tx in order to calculate the sighash
		nodeID, err := uuid.Parse(transaction.LeafId)
		if err != nil {
			return fmt.Errorf("unable to parse node id: %w", err)
		}
		node, err := db.TreeNode.Get(ctx, nodeID)
		if err != nil {
			return fmt.Errorf("unable to get node: %w", err)
		}
		if node.Status != st.TreeNodeStatusAvailable {
			return fmt.Errorf("node %v is not available: %v", node.ID, node.Status)
		}
		keyshare, err := node.QuerySigningKeyshare().First(ctx)
		if err != nil {
			return fmt.Errorf("unable to get keyshare: %w", err)
		}
		tx, err := common.TxFromRawTxBytes(node.RawTx)
		if err != nil {
			return fmt.Errorf("unable to get tx: %w", err)
		}

		refundTx, err := common.TxFromRawTxBytes(transaction.RawTx)
		if err != nil {
			return fmt.Errorf("unable to get refund tx: %w", err)
		}

		if len(tx.TxOut) <= 0 {
			return fmt.Errorf("vout out of bounds")
		}
		sighash, err := common.SigHashFromTx(refundTx, 0, tx.TxOut[0])
		if err != nil {
			return fmt.Errorf("unable to get sighash: %w", err)
		}

		realUserPublicKey, err := common.SubtractPublicKeys(node.VerifyingPubkey, keyshare.PublicKey)
		if err != nil {
			return fmt.Errorf("unable to get real user public key: %w", err)
		}

		if !bytes.Equal(realUserPublicKey, node.OwnerSigningPubkey) {
			logger.Debug("real user public key mismatch", "expected", hex.EncodeToString(node.OwnerSigningPubkey), "got", hex.EncodeToString(realUserPublicKey))
			node, err = node.Update().SetOwnerSigningPubkey(realUserPublicKey).Save(ctx)
			if err != nil {
				return fmt.Errorf("unable to update node: %w", err)
			}
		}

		_, err = client.ValidateSignatureShare(ctx, &pbfrost.ValidateSignatureShareRequest{
			Message:         sighash,
			SignatureShare:  transaction.UserSignature,
			Role:            pbfrost.SigningRole_USER,
			VerifyingKey:    node.VerifyingPubkey,
			PublicShare:     node.OwnerSigningPubkey,
			Commitments:     transaction.SigningCommitments.SigningCommitments,
			UserCommitments: transaction.SigningNonceCommitment,
		})
		if err != nil {
			return fmt.Errorf("unable to validate signature share: %w, for sighash: %v, user pubkey: %v", err, hex.EncodeToString(sighash), hex.EncodeToString(node.OwnerSigningPubkey))
		}
	}

	// Step 2 validate the amount is correct and paid to the destination pubkey
	destinationPubkeyBytes, err := secp256k1.ParsePubKey(destinationPubkey)
	if err != nil {
		return fmt.Errorf("unable to parse destination pubkey: %w", err)
	}
	var totalAmount uint64
	for _, transaction := range transactions {
		refundTx, err := common.TxFromRawTxBytes(transaction.RawTx)
		if err != nil {
			return fmt.Errorf("unable to get refund tx: %w", err)
		}
		pubkeyScript, err := common.P2TRScriptFromPubKey(destinationPubkeyBytes)
		if err != nil {
			return fmt.Errorf("unable to extract pubkey from tx: %w", err)
		}
		if len(refundTx.TxOut) <= 0 {
			return fmt.Errorf("vout out of bounds")
		}
		if !bytes.Equal(pubkeyScript, refundTx.TxOut[0].PkScript) {
			return fmt.Errorf("invalid destination pubkey")
		}
		totalAmount += uint64(refundTx.TxOut[0].Value)
	}
	if reason == pb.InitiatePreimageSwapRequest_REASON_SEND {
		totalAmount -= feeSats
	}
	if totalAmount != amount.ValueSats {
		logger.Error("invalid amount", "expected", amount.ValueSats, "got", totalAmount)
	}
	return nil
}

func (h *LightningHandler) storeUserSignedTransactions(
	ctx context.Context,
	paymentHash []byte,
	preimageShare *ent.PreimageShare,
	transactions []*pb.UserSignedTxSigningJob,
	transfer *ent.Transfer,
	status st.PreimageRequestStatus,
	receiverIdentityPubkey []byte,
) (*ent.PreimageRequest, error) {
	db := ent.GetDbFromContext(ctx)
	preimageRequestMutator := db.PreimageRequest.Create().
		SetPaymentHash(paymentHash).
		SetReceiverIdentityPubkey(receiverIdentityPubkey).
		SetTransfers(transfer).
		SetStatus(status)
	if preimageShare != nil {
		preimageRequestMutator.SetPreimageShares(preimageShare)
	}
	preimageRequest, err := preimageRequestMutator.Save(ctx)
	if err != nil {
		return nil, fmt.Errorf("unable to create preimage request: %w", err)
	}

	for _, transaction := range transactions {
		commitmentsBytes, err := proto.Marshal(transaction.SigningCommitments)
		if err != nil {
			return nil, fmt.Errorf("unable to marshal signing commitments: %w", err)
		}
		nodeID, err := uuid.Parse(transaction.LeafId)
		if err != nil {
			return nil, fmt.Errorf("unable to parse node id: %w", err)
		}
		userSignatureCommitmentBytes, err := proto.Marshal(transaction.SigningNonceCommitment)
		if err != nil {
			return nil, fmt.Errorf("unable to marshal user signature commitment: %w", err)
		}
		_, err = db.UserSignedTransaction.Create().
			SetTransaction(transaction.RawTx).
			SetUserSignature(transaction.UserSignature).
			SetUserSignatureCommitment(userSignatureCommitmentBytes).
			SetSigningCommitments(commitmentsBytes).
			SetPreimageRequest(preimageRequest).
			SetTreeNodeID(nodeID).
			Save(ctx)
		if err != nil {
			return nil, fmt.Errorf("unable to store user signed transaction: %w", err)
		}

		node, err := db.TreeNode.Get(ctx, nodeID)
		if err != nil {
			return nil, fmt.Errorf("unable to get node: %w", err)
		}
		_, err = db.TreeNode.UpdateOne(node).SetStatus(st.TreeNodeStatusTransferLocked).Save(ctx)
		if err != nil {
			return nil, fmt.Errorf("unable to update node status: %w", err)
		}
	}
	return preimageRequest, nil
}

// GetPreimageShare gets the preimage share for the given payment hash.
func (h *LightningHandler) GetPreimageShare(ctx context.Context, req *pb.InitiatePreimageSwapRequest) ([]byte, error) {
	if req.Reason == pb.InitiatePreimageSwapRequest_REASON_RECEIVE && req.FeeSats != 0 {
		return nil, fmt.Errorf("fee is not allowed for receive preimage swap")
	}

	var preimageShare *ent.PreimageShare
	if req.Reason == pb.InitiatePreimageSwapRequest_REASON_RECEIVE {
		db := ent.GetDbFromContext(ctx)
		var err error
		preimageShare, err = db.PreimageShare.Query().Where(preimageshare.PaymentHash(req.PaymentHash)).First(ctx)
		if err != nil {
			return nil, fmt.Errorf("unable to get preimage share: %w", err)
		}
		if !bytes.Equal(preimageShare.OwnerIdentityPubkey, req.ReceiverIdentityPublicKey) {
			return nil, fmt.Errorf("preimage share owner identity public key mismatch")
		}
	}

	invoiceAmount := req.InvoiceAmount
	if preimageShare != nil {
		bolt11, err := decodepay.Decodepay(preimageShare.InvoiceString)
		if err != nil {
			return nil, fmt.Errorf("unable to decode invoice: %w", err)
		}
		invoiceAmount = &pb.InvoiceAmount{
			ValueSats: uint64(bolt11.MSatoshi / 1000),
			InvoiceAmountProof: &pb.InvoiceAmountProof{
				Bolt11Invoice: preimageShare.InvoiceString,
			},
		}
	}

	err := h.validateGetPreimageRequest(
		ctx,
		req.PaymentHash,
		req.Transfer.LeavesToSend,
		invoiceAmount,
		req.ReceiverIdentityPublicKey,
		req.FeeSats,
		req.Reason,
	)
	if err != nil {
		return nil, fmt.Errorf("unable to validate request: %w", err)
	}

	leafRefundMap := make(map[string][]byte)
	for _, transaction := range req.Transfer.LeavesToSend {
		leafRefundMap[transaction.LeafId] = transaction.RawTx
	}

	transferHandler := NewTransferHandler(h.config)
	transfer, _, err := transferHandler.createTransfer(
		ctx,
		req.Transfer.TransferId,
		st.TransferTypePreimageSwap,
		req.Transfer.ExpiryTime.AsTime(),
		req.Transfer.OwnerIdentityPublicKey,
		req.Transfer.ReceiverIdentityPublicKey,
		leafRefundMap,
		nil,
		TransferRoleCoordinator,
	)
	if err != nil {
		return nil, fmt.Errorf("unable to create transfer: %w", err)
	}

	var status st.PreimageRequestStatus
	if req.Reason == pb.InitiatePreimageSwapRequest_REASON_RECEIVE {
		status = st.PreimageRequestStatusPreimageShared
	} else {
		status = st.PreimageRequestStatusWaitingForPreimage
	}
	_, err = h.storeUserSignedTransactions(ctx, req.PaymentHash, preimageShare, req.Transfer.LeavesToSend, transfer, status, req.ReceiverIdentityPublicKey)
	if err != nil {
		return nil, fmt.Errorf("unable to store user signed transactions: %w", err)
	}

	if preimageShare != nil {
		return preimageShare.PreimageShare, nil
	}

	return nil, nil
}

// InitiatePreimageSwap initiates a preimage swap for the given payment hash.
func (h *LightningHandler) InitiatePreimageSwap(ctx context.Context, req *pb.InitiatePreimageSwapRequest) (*pb.InitiatePreimageSwapResponse, error) {
	if req.Transfer == nil {
		return nil, fmt.Errorf("transfer is required")
	}

	if len(req.Transfer.LeavesToSend) == 0 {
		return nil, fmt.Errorf("at least one leaf must be provided")
	}

	if req.Transfer.OwnerIdentityPublicKey == nil {
		return nil, fmt.Errorf("owner identity public key is required")
	}

	if req.Transfer.ReceiverIdentityPublicKey == nil {
		return nil, fmt.Errorf("receiver identity public key is required")
	}

	if req.Reason == pb.InitiatePreimageSwapRequest_REASON_RECEIVE && req.FeeSats != 0 {
		return nil, fmt.Errorf("fee is not allowed for receive preimage swap")
	}

	logger := logging.GetLoggerFromContext(ctx)

	var preimageShare *ent.PreimageShare
	if req.Reason == pb.InitiatePreimageSwapRequest_REASON_RECEIVE {
		db := ent.GetDbFromContext(ctx)
		var err error
		preimageShare, err = db.PreimageShare.Query().Where(preimageshare.PaymentHash(req.PaymentHash)).First(ctx)
		if err != nil {
			return nil, fmt.Errorf("unable to get preimage share: %w", err)
		}
		if !bytes.Equal(preimageShare.OwnerIdentityPubkey, req.ReceiverIdentityPublicKey) {
			return nil, fmt.Errorf("preimage share owner identity public key mismatch")
		}
	}

	invoiceAmount := req.InvoiceAmount
	if preimageShare != nil {
		bolt11, err := decodepay.Decodepay(preimageShare.InvoiceString)
		if err != nil {
			return nil, fmt.Errorf("unable to decode invoice: %w", err)
		}
		if bolt11.MSatoshi > 0 {
			invoiceAmount = &pb.InvoiceAmount{
				ValueSats: uint64(bolt11.MSatoshi / 1000),
				InvoiceAmountProof: &pb.InvoiceAmountProof{
					Bolt11Invoice: preimageShare.InvoiceString,
				},
			}
		}
	}

	err := h.validateGetPreimageRequest(
		ctx,
		req.PaymentHash,
		req.Transfer.LeavesToSend,
		invoiceAmount,
		req.ReceiverIdentityPublicKey,
		req.FeeSats,
		req.Reason,
	)
	if err != nil {
		return nil, fmt.Errorf("unable to validate request: %w", err)
	}

	leafRefundMap := make(map[string][]byte)
	for _, transaction := range req.Transfer.LeavesToSend {
		leafRefundMap[transaction.LeafId] = transaction.RawTx
	}

	transferHandler := NewTransferHandler(h.config)
	transfer, _, err := transferHandler.createTransfer(
		ctx,
		req.Transfer.TransferId,
		st.TransferTypePreimageSwap,
		req.Transfer.ExpiryTime.AsTime(),
		req.Transfer.OwnerIdentityPublicKey,
		req.Transfer.ReceiverIdentityPublicKey,
		leafRefundMap,
		nil,
		TransferRoleCoordinator,
	)
	if err != nil {
		return nil, fmt.Errorf("unable to create transfer: %w", err)
	}

	var status st.PreimageRequestStatus
	if req.Reason == pb.InitiatePreimageSwapRequest_REASON_RECEIVE {
		status = st.PreimageRequestStatusPreimageShared
	} else {
		status = st.PreimageRequestStatusWaitingForPreimage
	}
	preimageRequest, err := h.storeUserSignedTransactions(ctx, req.PaymentHash, preimageShare, req.Transfer.LeavesToSend, transfer, status, req.ReceiverIdentityPublicKey)
	if err != nil {
		return nil, fmt.Errorf("unable to store user signed transactions: %w", err)
	}

	selection := helper.OperatorSelection{Option: helper.OperatorSelectionOptionExcludeSelf}
	result, err := helper.ExecuteTaskWithAllOperators(ctx, h.config, &selection, func(ctx context.Context, operator *so.SigningOperator) ([]byte, error) {
		conn, err := operator.NewGRPCConnection()
		if err != nil {
			return nil, err
		}
		defer conn.Close()

		client := pbinternal.NewSparkInternalServiceClient(conn)
		response, err := client.InitiatePreimageSwap(ctx, req)
		if err != nil {
			return nil, fmt.Errorf("unable to initiate preimage swap: %w", err)
		}
		return response.PreimageShare, nil
	})
	if err != nil {
		// At least one operator failed to initiate preimage swap, cancel the transfer.
		baseHandler := NewBaseTransferHandler(h.config)
		err := baseHandler.CreateCancelTransferGossipMessage(ctx, transfer.ID.String())
		if err != nil {
			logger.Error("InitiatePreimageSwap: unable to cancel own send transfer", "error", err)
		}
		return nil, fmt.Errorf("unable to execute task with all operators: %w", err)
	}

	transferProto, err := transfer.MarshalProto(ctx)
	if err != nil {
		return nil, fmt.Errorf("unable to marshal transfer: %w", err)
	}

	// Recover secret if necessary
	if req.Reason == pb.InitiatePreimageSwapRequest_REASON_SEND {
		return &pb.InitiatePreimageSwapResponse{Transfer: transferProto}, nil
	}

	shares := make([]*secretsharing.SecretShare, 0)
	for identifier, share := range result {
		if share == nil {
			continue
		}
		index, ok := new(big.Int).SetString(identifier, 16)
		if !ok {
			return nil, fmt.Errorf("unable to parse index: %v", identifier)
		}
		shares = append(shares, &secretsharing.SecretShare{
			FieldModulus: secp256k1.S256().N,
			Threshold:    int(h.config.Threshold),
			Index:        index,
			Share:        new(big.Int).SetBytes(share),
		})
	}

	secret, err := secretsharing.RecoverSecret(shares)
	if err != nil {
		return nil, fmt.Errorf("unable to recover secret: %w", err)
	}

	secretBytes := secret.Bytes()
	if len(secretBytes) < 32 {
		secretBytes = append(make([]byte, 32-len(secretBytes)), secretBytes...)
	}

	hash := sha256.Sum256(secretBytes)
	if !bytes.Equal(hash[:], req.PaymentHash) {
		baseHandler := NewBaseTransferHandler(h.config)
		err := baseHandler.CreateCancelTransferGossipMessage(ctx, transfer.ID.String())
		if err != nil {
			logger.Error("InitiatePreimageSwap: unable to cancel own send transfer", "error", err)
		}
		return nil, fmt.Errorf("recovered preimage did not match payment hash: %w", ent.ErrNoRollback)
	}

	err = preimageRequest.Update().SetStatus(st.PreimageRequestStatusPreimageShared).Exec(ctx)
	if err != nil {
		return nil, fmt.Errorf("unable to update preimage request status: %w", err)
	}

	return &pb.InitiatePreimageSwapResponse{Preimage: secretBytes, Transfer: transferProto}, nil
}

// UpdatePreimageRequest updates the preimage request.
func (h *LightningHandler) UpdatePreimageRequest(ctx context.Context, req *pbinternal.UpdatePreimageRequestRequest) error {
	logger := logging.GetLoggerFromContext(ctx)
	db := ent.GetDbFromContext(ctx)

	paymentHash := sha256.Sum256(req.Preimage)
	preimageRequest, err := db.PreimageRequest.Query().Where(
		preimagerequest.And(
			preimagerequest.PaymentHashEQ(paymentHash[:]),
			preimagerequest.ReceiverIdentityPubkeyEQ(req.IdentityPublicKey),
			preimagerequest.StatusEQ(st.PreimageRequestStatusWaitingForPreimage),
		),
	).First(ctx)
	if err != nil {
		logger.Error("UpdatePreimageRequest: unable to get preimage request", "error", err, "paymentHash", hex.EncodeToString(paymentHash[:]), "identityPublicKey", hex.EncodeToString(req.IdentityPublicKey))
		return fmt.Errorf("UpdatePreimageRequest:unable to get preimage request: %w", err)
	}

	err = preimageRequest.Update().SetStatus(st.PreimageRequestStatusPreimageShared).Exec(ctx)
	if err != nil {
		return fmt.Errorf("unable to update preimage request status: %w", err)
	}
	return nil
}

// QueryUserSignedRefunds queries the user signed refunds for the given payment hash.
func (h *LightningHandler) QueryUserSignedRefunds(ctx context.Context, req *pb.QueryUserSignedRefundsRequest) (*pb.QueryUserSignedRefundsResponse, error) {
	logger := logging.GetLoggerFromContext(ctx)
	db := ent.GetDbFromContext(ctx)

	preimageRequest, err := db.PreimageRequest.Query().Where(
		preimagerequest.And(
			preimagerequest.PaymentHashEQ(req.PaymentHash),
			preimagerequest.ReceiverIdentityPubkeyEQ(req.IdentityPublicKey),
			preimagerequest.StatusEQ(st.PreimageRequestStatusWaitingForPreimage),
		),
	).First(ctx)
	if err != nil {
		logger.Error("QueryUserSignedRefunds: unable to get preimage request", "error", err, "paymentHash", hex.EncodeToString(req.PaymentHash), "identityPublicKey", hex.EncodeToString(req.IdentityPublicKey))
		return nil, fmt.Errorf("QueryUserSignedRefunds: unable to get preimage request: %w", err)
	}

	transfer, err := preimageRequest.QueryTransfers().Only(ctx)
	if err != nil {
		return nil, fmt.Errorf("unable to get transfer: %w", err)
	}

	if transfer.Status != st.TransferStatusSenderKeyTweakPending {
		return nil, fmt.Errorf("transfer is not in the sender key tweak pending status, status: %s", transfer.Status)
	}

	userSignedRefunds, err := preimageRequest.QueryTransactions().All(ctx)
	if err != nil {
		return nil, fmt.Errorf("unable to get user signed transactions: %w", err)
	}

	protos := make([]*pb.UserSignedRefund, len(userSignedRefunds))
	for i, userSignedRefund := range userSignedRefunds {
		userSigningCommitment := &pbcommon.SigningCommitment{}
		err := proto.Unmarshal(userSignedRefund.SigningCommitments, userSigningCommitment)
		if err != nil {
			return nil, fmt.Errorf("unable to unmarshal user signed refund: %w", err)
		}
		signingCommitments := &pb.SigningCommitments{}
		err = proto.Unmarshal(userSignedRefund.SigningCommitments, signingCommitments)
		if err != nil {
			return nil, fmt.Errorf("unable to unmarshal user signed refund: %w", err)
		}
		treeNode, err := userSignedRefund.QueryTreeNode().WithTree().Only(ctx)
		if err != nil {
			return nil, fmt.Errorf("unable to get tree node: %w", err)
		}
		networkProto, err := treeNode.Edges.Tree.Network.MarshalProto()
		if err != nil {
			return nil, fmt.Errorf("unable to marshal network: %w", err)
		}

		protos[i] = &pb.UserSignedRefund{
			NodeId:                  treeNode.ID.String(),
			RefundTx:                userSignedRefund.Transaction,
			UserSignature:           userSignedRefund.UserSignature,
			SigningCommitments:      signingCommitments,
			UserSignatureCommitment: userSigningCommitment,
			Network:                 networkProto,
		}
	}
	return &pb.QueryUserSignedRefundsResponse{UserSignedRefunds: protos}, nil
}

func (h *LightningHandler) ValidatePreimage(ctx context.Context, req *pb.ProvidePreimageRequest) (*ent.Transfer, error) {
	logger := logging.GetLoggerFromContext(ctx)
	db := ent.GetDbFromContext(ctx)

	calculatedPaymentHash := sha256.Sum256(req.Preimage)
	if !bytes.Equal(calculatedPaymentHash[:], req.PaymentHash) {
		return nil, fmt.Errorf("invalid preimage")
	}

	preimageRequest, err := db.PreimageRequest.Query().Where(
		preimagerequest.And(
			preimagerequest.PaymentHashEQ(req.PaymentHash),
			preimagerequest.ReceiverIdentityPubkeyEQ(req.IdentityPublicKey),
			preimagerequest.StatusEQ(st.PreimageRequestStatusWaitingForPreimage),
		),
	).First(ctx)
	if err != nil {
		logger.Error("ProvidePreimage: unable to get preimage request", "error", err, "paymentHash", hex.EncodeToString(req.PaymentHash), "identityPublicKey", hex.EncodeToString(req.IdentityPublicKey))
		return nil, fmt.Errorf("ProvidePreimage: unable to get preimage request: %w", err)
	}

	preimageRequest, err = preimageRequest.Update().
		SetStatus(st.PreimageRequestStatusPreimageShared).
		SetPreimage(req.Preimage).
		Save(ctx)
	if err != nil {
		return nil, fmt.Errorf("unable to update preimage request status: %w", err)
	}

	transfer, err := preimageRequest.QueryTransfers().Only(ctx)
	if err != nil {
		return nil, fmt.Errorf("unable to get transfer: %w", err)
	}
	return transfer, nil
}

func (h *LightningHandler) ValidatePreimageInternal(ctx context.Context, req *pbinternal.ProvidePreimageRequest) (*ent.Transfer, error) {
	providePreimageRequest := &pb.ProvidePreimageRequest{
		PaymentHash:       req.PaymentHash,
		Preimage:          req.Preimage,
		IdentityPublicKey: req.IdentityPublicKey,
	}
	transfer, err := h.ValidatePreimage(ctx, providePreimageRequest)
	if err != nil {
		return nil, fmt.Errorf("unable to validate preimage: %w", err)
	}

	transferHandler := NewBaseTransferHandler(h.config)
	err = transferHandler.validateKeyTweakProofs(ctx, transfer, req.KeyTweakProofs)
	if err != nil {
		return nil, fmt.Errorf("unable to get transfer leaves: %w", err)
	}
	return transfer, nil
}

func (h *LightningHandler) ProvidePreimage(ctx context.Context, req *pb.ProvidePreimageRequest) (*pb.ProvidePreimageResponse, error) {
	transfer, err := h.ValidatePreimage(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("unable to provide preimage: %w", err)
	}

	transferLeaves, err := transfer.QueryTransferLeaves().All(ctx)
	if err != nil {
		return nil, fmt.Errorf("unable to get transfer leaves: %w", err)
	}
	internalReq := &pbinternal.ProvidePreimageRequest{
		PaymentHash:       req.PaymentHash,
		Preimage:          req.Preimage,
		IdentityPublicKey: req.IdentityPublicKey,
	}
	keyTweakProofMap := make(map[string]*pb.SecretProof)
	for _, leaf := range transferLeaves {
		keyTweakProto := &pb.SendLeafKeyTweak{}
		err := proto.Unmarshal(leaf.KeyTweak, keyTweakProto)
		if err != nil {
			return nil, fmt.Errorf("unable to unmarshal key tweak: %w", err)
		}
		keyTweakProofMap[keyTweakProto.LeafId] = &pb.SecretProof{
			Proofs: keyTweakProto.SecretShareTweak.Proofs,
		}
	}
	internalReq.KeyTweakProofs = keyTweakProofMap

	operatorSelection := helper.OperatorSelection{Option: helper.OperatorSelectionOptionExcludeSelf}
	_, err = helper.ExecuteTaskWithAllOperators(ctx, h.config, &operatorSelection, func(ctx context.Context, operator *so.SigningOperator) (interface{}, error) {
		conn, err := operator.NewGRPCConnection()
		if err != nil {
			return nil, err
		}
		defer conn.Close()

		client := pbinternal.NewSparkInternalServiceClient(conn)
		_, err = client.ProvidePreimage(ctx, internalReq)
		if err != nil {
			return nil, fmt.Errorf("unable to provide preimage: %w", err)
		}
		return nil, nil
	})
	if err != nil {
		return nil, fmt.Errorf("unable to execute task with all operators: %w", err)
	}

	participants, err := operatorSelection.OperatorIdentifierList(h.config)
	if err != nil {
		return nil, fmt.Errorf("unable to get operator list: %w", err)
	}
	sendGossipHandler := NewSendGossipHandler(h.config)
	_, err = sendGossipHandler.CreateAndSendGossipMessage(ctx, &pbgossip.GossipMessage{
		Message: &pbgossip.GossipMessage_SettleSenderKeyTweak{
			SettleSenderKeyTweak: &pbgossip.GossipMessageSettleSenderKeyTweak{
				TransferId:           transfer.ID.String(),
				SenderKeyTweakProofs: keyTweakProofMap,
			},
		},
	}, participants)
	if err != nil {
		return nil, fmt.Errorf("unable to create and send gossip message to settle sender key tweak: %w", err)
	}

	db := ent.GetDbFromContext(ctx)
	transfer, err = db.Transfer.Get(ctx, transfer.ID)
	if err != nil {
		return nil, fmt.Errorf("unable to get transfer: %w", err)
	}

	transferProto, err := transfer.MarshalProto(ctx)
	if err != nil {
		return nil, fmt.Errorf("unable to marshal transfer: %w", err)
	}

	return &pb.ProvidePreimageResponse{Transfer: transferProto}, nil
}

func (h *LightningHandler) ReturnLightningPayment(ctx context.Context, req *pb.ReturnLightningPaymentRequest, internal bool) (*emptypb.Empty, error) {
	logger := logging.GetLoggerFromContext(ctx)

	if !internal {
		if err := authz.EnforceSessionIdentityPublicKeyMatches(ctx, h.config, req.UserIdentityPublicKey); err != nil {
			return nil, err
		}
	}

	db := ent.GetDbFromContext(ctx)
	preimageRequest, err := db.PreimageRequest.Query().Where(
		preimagerequest.And(
			preimagerequest.PaymentHashEQ(req.PaymentHash),
			preimagerequest.ReceiverIdentityPubkeyEQ(req.UserIdentityPublicKey),
			preimagerequest.StatusEQ(st.PreimageRequestStatusWaitingForPreimage),
		),
	).First(ctx)
	if err != nil {
		logger.Error("ReturnLightningPayment: unable to get preimage request", "error", err, "paymentHash", hex.EncodeToString(req.PaymentHash), "identityPublicKey", hex.EncodeToString(req.UserIdentityPublicKey))
		return nil, fmt.Errorf("ReturnLightningPayment: unable to get preimage request: %w", err)
	}

	if preimageRequest.Status != st.PreimageRequestStatusWaitingForPreimage {
		return nil, fmt.Errorf("preimage request is not in the waiting for preimage status")
	}

	err = preimageRequest.Update().SetStatus(st.PreimageRequestStatusReturned).Exec(ctx)
	if err != nil {
		return nil, fmt.Errorf("unable to update preimage request status: %w", err)
	}

	transfer, err := preimageRequest.QueryTransfers().Only(ctx)
	if err != nil {
		return nil, fmt.Errorf("unable to get transfer: %w", err)
	}

	if !bytes.Equal(transfer.ReceiverIdentityPubkey, req.UserIdentityPublicKey) {
		return nil, fmt.Errorf("transfer receiver identity public key mismatch")
	}

	transfer, err = transfer.Update().SetStatus(st.TransferStatusReturned).Save(ctx)
	if err != nil {
		return nil, fmt.Errorf("unable to update transfer status: %w", err)
	}

	transferLeaves, err := transfer.QueryTransferLeaves().All(ctx)
	if err != nil {
		return nil, fmt.Errorf("unable to get transfer leaves: %w", err)
	}

	for _, leaf := range transferLeaves {
		treenode, err := leaf.QueryLeaf().Only(ctx)
		if err != nil {
			return nil, fmt.Errorf("unable to get tree node: %w", err)
		}
		_, err = treenode.Update().SetStatus(st.TreeNodeStatusAvailable).Save(ctx)
		if err != nil {
			return nil, fmt.Errorf("unable to update tree node status: %w", err)
		}
	}

	if !internal {
		operatorSelection := helper.OperatorSelection{Option: helper.OperatorSelectionOptionExcludeSelf}
		_, err = helper.ExecuteTaskWithAllOperators(ctx, h.config, &operatorSelection, func(ctx context.Context, operator *so.SigningOperator) (interface{}, error) {
			conn, err := operator.NewGRPCConnection()
			if err != nil {
				return nil, err
			}
			defer conn.Close()

			client := pbinternal.NewSparkInternalServiceClient(conn)
			_, err = client.ReturnLightningPayment(ctx, req)
			if err != nil {
				return nil, fmt.Errorf("unable to return lightning payment: %w", err)
			}
			return nil, nil
		})
		if err != nil {
			return nil, fmt.Errorf("unable to execute task with all operators: %w", err)
		}
	}

	return &emptypb.Empty{}, nil
}
