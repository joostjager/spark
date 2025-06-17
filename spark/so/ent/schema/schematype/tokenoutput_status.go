package schematype

type TokenOutputStatus string

const (
	// TokenOutputStatusCreating is the status of an output after the creation has started
	// but before the transaction creating it has been signed.
	TokenOutputStatusCreatedStarted TokenOutputStatus = "CREATED_STARTED"
	// TokenOutputStatusFinalized is the status if a transaction creating this output was started
	// but then cancelled due to a threshold of SOs not responding. These outputs are permanently invalid.
	TokenOutputStatusCreatedStartedCancelled TokenOutputStatus = "CREATED_STARTED_CANCELLED"
	// TokenOutputStatusSigned is the status after an output has been signed by the operator
	// but before the transaction has been finalized.
	TokenOutputStatusCreatedSigned TokenOutputStatus = "CREATED_SIGNED"
	// TokenOutputStatusFinalized is the status if a transaction creating this output was signed
	// but then cancelled due to a threshold of SOs not responding. These outputs are permanently invalid.
	TokenOutputStatusCreatedSignedCancelled TokenOutputStatus = "CREATED_SIGNED_CANCELLED"
	// TokenOutputStatusCreatedFinalized is the status after an output has been finalized by the
	// operator and is ready for spending.
	TokenOutputStatusCreatedFinalized TokenOutputStatus = "CREATED_FINALIZED"
	// TokenOutputStatusSpentStarted is the status of an output after a tx has come in to start
	// spending but before the transaction has been signed.
	TokenOutputStatusSpentStarted TokenOutputStatus = "SPENT_STARTED"
	// TokenOutputStatusSpent is the status of an output after the tx has been signed by the
	// operator to spend it but before it is finalized.
	TokenOutputStatusSpentSigned TokenOutputStatus = "SPENT_SIGNED"
	// TokenOutputStatusSpentFinalized is the status of an output after the tx has been signed
	// by the operator to spend it but before it is finalized.
	TokenOutputStatusSpentFinalized TokenOutputStatus = "SPENT_FINALIZED"
)

func (TokenOutputStatus) Values() []string {
	return []string{
		string(TokenOutputStatusCreatedStarted),
		string(TokenOutputStatusCreatedStartedCancelled),
		string(TokenOutputStatusCreatedSigned),
		string(TokenOutputStatusCreatedSignedCancelled),
		string(TokenOutputStatusCreatedFinalized),
		string(TokenOutputStatusSpentStarted),
		string(TokenOutputStatusSpentSigned),
		string(TokenOutputStatusSpentFinalized),
	}
}
