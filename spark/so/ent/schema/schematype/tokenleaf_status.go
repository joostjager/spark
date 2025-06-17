package schematype

// TokenLeafStatus is the status of a token leaf.
type TokenLeafStatus string

const (
	// TokenLeafStatusCreating is the status of a leaf after the creation has started
	// but before the transaction creating it has been signed.
	TokenLeafStatusCreatedStarted TokenLeafStatus = "CREATED_STARTED"
	// TokenLeafStatusSigned is the status after a leaf has been signed by the operator
	// but before the transaction has been finalized.
	TokenLeafStatusCreatedSigned TokenLeafStatus = "CREATED_SIGNED"
	// TokenLeafStatusFinalized is the status if a transaction creating this leaf was signed
	// but then cancelled due to a threshold of SOs not responding. These leaves are permanently invalid.
	TokenLeafStatusCreatedSignedCancelled TokenLeafStatus = "CREATED_SIGNED_CANCELLED"
	// TokenLeafStatusCreatedFinalized is the status after a leaf has been finalized by the
	// operator and is ready for spending.
	TokenLeafStatusCreatedFinalized TokenLeafStatus = "CREATED_FINALIZED"
	// TokenLeafStatusSpentStarted is the status of a leaf after a tx has come in to start
	// spending but before the transaction has been signed.
	TokenLeafStatusSpentStarted TokenLeafStatus = "SPENT_STARTED"
	// TokenLeafStatusSpent is the status of a leaf after the tx has been signed by the
	// operator to spend it but before it is finalized.
	TokenLeafStatusSpentSigned TokenLeafStatus = "SPENT_SIGNED"
	// TokenLeafStatusSpentFinalized is the status of a leaf after the tx has been signed
	// by the operator to spend it but before it is finalized.
	TokenLeafStatusSpentFinalized TokenLeafStatus = "SPENT_FINALIZED"
)

// Values returns the values of the token leaf status.
func (TokenLeafStatus) Values() []string {
	return []string{
		string(TokenLeafStatusCreatedStarted),
		string(TokenLeafStatusCreatedSigned),
		string(TokenLeafStatusCreatedSignedCancelled),
		string(TokenLeafStatusCreatedFinalized),
		string(TokenLeafStatusSpentStarted),
		string(TokenLeafStatusSpentSigned),
		string(TokenLeafStatusSpentFinalized),
	}
}
