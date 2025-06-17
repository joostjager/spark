package schematype

// TransferType is the type of transfer
type TransferType string

const (
	// TransferTypePreimageSwap is the type of transfer that is a preimage swap
	TransferTypePreimageSwap TransferType = "PREIMAGE_SWAP"
	// TransferTypeCooperativeExit is the type of transfer that is a cooperative exit
	TransferTypeCooperativeExit TransferType = "COOPERATIVE_EXIT"
	// TransferTypeTransfer is the type of transfer that is a normal transfer
	TransferTypeTransfer TransferType = "TRANSFER"
	// TransferTypeSwap is the type of transfer that is a swap of leaves for other leaves.
	TransferTypeSwap TransferType = "SWAP"
	// TransferTypeCounterSwap is the type of transfer that is the other side of a swap.
	TransferTypeCounterSwap TransferType = "COUNTER_SWAP"
	// TransferTypeUtxoSwap is the type of transfer that is a swap of an utxos for leaves.
	TransferTypeUtxoSwap TransferType = "UTXO_SWAP"
)

// Values returns the values of the transfer type.
func (TransferType) Values() []string {
	return []string{
		string(TransferTypePreimageSwap),
		string(TransferTypeCooperativeExit),
		string(TransferTypeTransfer),
		string(TransferTypeSwap),
		string(TransferTypeCounterSwap),
		string(TransferTypeUtxoSwap),
	}
}
