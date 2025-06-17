package grpc

import (
	"context"

	pb "github.com/lightsparkdev/spark/proto/spark_ssp_internal"
	"github.com/lightsparkdev/spark/so"
	"github.com/lightsparkdev/spark/so/errors"
	"github.com/lightsparkdev/spark/so/handler"
)

type SparkSspServer struct {
	pb.UnimplementedSparkSspInternalServiceServer
	config *so.Config
}

func NewSparkSspServer(config *so.Config) *SparkSspServer {
	return &SparkSspServer{config: config}
}

func (s *SparkSspServer) QueryLostNodes(ctx context.Context, req *pb.QueryLostNodesRequest) (*pb.QueryLostNodesResponse, error) {
	sspRequestHandler := handler.NewSspRequestHandler(s.config)
	return errors.WrapWithGRPCError(sspRequestHandler.QueryLostNodes(ctx, req))
}

func (s *SparkSspServer) MagicSwap(ctx context.Context, req *pb.MagicSwapRequest) (*pb.MagicSwapResponse, error) {
	sspRequestHandler := handler.NewSspRequestHandler(s.config)
	return errors.WrapWithGRPCError(sspRequestHandler.MagicSwap(ctx, req))
}

func (s *SparkSspServer) GetStuckTransfers(ctx context.Context, req *pb.GetStuckTransfersRequest) (*pb.GetStuckTransfersResponse, error) {
	sspRequestHandler := handler.NewSspRequestHandler(s.config)
	return errors.WrapWithGRPCError(sspRequestHandler.GetStuckTransfers(ctx, req))
}

func (s *SparkSspServer) QueryStuckTransfer(ctx context.Context, req *pb.QueryStuckTransferRequest) (*pb.QueryStuckTransferResponse, error) {
	sspRequestHandler := handler.NewSspRequestHandler(s.config)
	return errors.WrapWithGRPCError(sspRequestHandler.QueryStuckTransfer(ctx, req))
}

func (s *SparkSspServer) CancelStuckTransfers(ctx context.Context, req *pb.CancelStuckTransferRequest) (*pb.CancelStuckTransferResponse, error) {
	sspRequestHandler := handler.NewSspRequestHandler(s.config)
	return errors.WrapWithGRPCError(sspRequestHandler.CancelStuckTransfer(ctx, req))
}
