package handler

import (
	"context"
	"fmt"
	"sync"

	"github.com/lightsparkdev/spark/common"
	"github.com/lightsparkdev/spark/common/logging"
	pbgossip "github.com/lightsparkdev/spark/proto/gossip"
	pbinternal "github.com/lightsparkdev/spark/proto/spark_internal"
	"github.com/lightsparkdev/spark/so"
	"github.com/lightsparkdev/spark/so/ent"
	st "github.com/lightsparkdev/spark/so/ent/schema/schematype"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

type SendGossipHandler struct {
	config *so.Config
}

func NewSendGossipHandler(config *so.Config) *SendGossipHandler {
	return &SendGossipHandler{config: config}
}

func (h *SendGossipHandler) postSendingGossipMessage(
	ctx context.Context,
	message *pbgossip.GossipMessage,
	gossip *ent.Gossip,
	bitMap *common.BitMap,
) (*ent.Gossip, error) {
	newStatus := st.GossipStatusPending
	if bitMap.IsAllSet() {
		newStatus = st.GossipStatusDelivered
	}
	gossip, err := gossip.Update().SetStatus(newStatus).SetReceipts(bitMap.Bytes()).Save(ctx)
	if err != nil {
		return nil, err
	}

	handler := NewGossipHandler(h.config)
	err = handler.HandleGossipMessage(ctx, message, true)
	if err != nil {
		return nil, err
	}
	return gossip, nil
}

func (h *SendGossipHandler) sendGossipMessageToParticipant(ctx context.Context, gossip *pbgossip.GossipMessage, participant string) error {
	logger := logging.GetLoggerFromContext(ctx)
	logger.Info("sending gossip message to participant", "participant", participant)
	operator, ok := h.config.SigningOperatorMap[participant]
	if !ok {
		return fmt.Errorf("operator %s not found", participant)
	}
	conn, err := operator.NewGRPCConnection()
	if err != nil {
		return err
	}
	client := pbinternal.NewSparkInternalServiceClient(conn)
	_, err = client.Gossip(ctx, gossip)
	if err != nil {
		if status.Code(err) == codes.Unavailable {
			return err
		}

		logger.Error("gossip message sent to participant with error", "participant", participant, "error", err)
		return nil
	}

	logger.Info("gossip message sent to participant", "participant", participant)
	return nil
}

func (h *SendGossipHandler) CreateAndSendGossipMessage(ctx context.Context, gossip *pbgossip.GossipMessage, participants []string) (*ent.Gossip, error) {
	db := ent.GetDbFromContext(ctx)
	messageBytes, err := proto.Marshal(gossip)
	if err != nil {
		return nil, err
	}
	receipts := common.NewBitMap(len(participants)).Bytes()
	ent, err := db.Gossip.Create().SetMessage(messageBytes).SetParticipants(participants).SetReceipts(receipts).Save(ctx)
	if err != nil {
		return nil, err
	}
	ent, err = h.SendGossipMessage(ctx, ent)
	if err != nil {
		return nil, err
	}
	return ent, nil
}

func (h *SendGossipHandler) SendGossipMessage(ctx context.Context, gossip *ent.Gossip) (*ent.Gossip, error) {
	logger := logging.GetLoggerFromContext(ctx)
	logger.Info("sending gossip message", "gossip_id", gossip.ID.String())
	bitMap := common.NewBitMapFromBytes(*gossip.Receipts, len(gossip.Participants))

	message := &pbgossip.GossipMessage{}
	if err := proto.Unmarshal(gossip.Message, message); err != nil {
		return nil, err
	}
	message.MessageId = gossip.ID.String()

	wg := sync.WaitGroup{}
	success := make(chan int, len(gossip.Participants))
	for i, participant := range gossip.Participants {
		if bitMap.Get(i) {
			continue
		}
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			err := h.sendGossipMessageToParticipant(ctx, message, participant)
			if err != nil {
				logger.Error("Failed to send gossip message", "error", err)
			} else {
				success <- i
			}
		}(i)
	}
	wg.Wait()
	close(success)

	for i := range success {
		bitMap.Set(i, true)
	}
	gossip, err := h.postSendingGossipMessage(ctx, message, gossip, bitMap)
	if err != nil {
		return nil, err
	}
	return gossip, nil
}
