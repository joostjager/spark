package schematype

// TokenFreezeStatus is the status of a token leaf.
type TokenFreezeStatus string

const (
	// TokenFreezeStatusCreating is the default status once a freeze has been applied.
	TokenFreezeStatusFrozen TokenFreezeStatus = "FROZEN"
	// TokenFreezeStatusThawed is the status after a prior freeze was removed.
	TokenFreezeStatusThawed TokenFreezeStatus = "THAWED"
)

// Values returns the values of the token leaf status.
func (TokenFreezeStatus) Values() []string {
	return []string{
		string(TokenFreezeStatusFrozen),
		string(TokenFreezeStatusThawed),
	}
}
