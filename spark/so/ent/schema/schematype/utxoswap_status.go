package schematype

type UtxoSwapStatus string

const (
	UtxoSwapStatusCreated   UtxoSwapStatus = "CREATED"
	UtxoSwapStatusCompleted UtxoSwapStatus = "COMPLETED"
	UtxoSwapStatusCancelled UtxoSwapStatus = "CANCELLED"
)

func (UtxoSwapStatus) Values() []string {
	return []string{
		string(UtxoSwapStatusCreated),
		string(UtxoSwapStatusCompleted),
		string(UtxoSwapStatusCancelled),
	}
}
