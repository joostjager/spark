package schematype

import pb "github.com/lightsparkdev/spark/proto/spark"

type UtxoSwapRequestType string

const (
	UtxoSwapRequestTypeFixedAmount UtxoSwapRequestType = "FIXED_AMOUNT"
	UtxoSwapRequestTypeMaxFee      UtxoSwapRequestType = "MAX_FEE"
	UtxoSwapRequestTypeRefund      UtxoSwapRequestType = "REFUND"
)

func (UtxoSwapRequestType) Values() []string {
	return []string{
		string(UtxoSwapRequestTypeFixedAmount),
		string(UtxoSwapRequestTypeMaxFee),
		string(UtxoSwapRequestTypeRefund),
	}
}

func UtxoSwapFromProtoRequestType(requestType pb.UtxoSwapRequestType) UtxoSwapRequestType {
	switch requestType {
	case pb.UtxoSwapRequestType_Fixed:
		return UtxoSwapRequestTypeFixedAmount
	case pb.UtxoSwapRequestType_MaxFee:
		return UtxoSwapRequestTypeMaxFee
	case pb.UtxoSwapRequestType_Refund:
		return UtxoSwapRequestTypeRefund
	default:
		return UtxoSwapRequestTypeFixedAmount
	}
}
