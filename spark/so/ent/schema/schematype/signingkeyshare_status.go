package schematype

// SigningKeyshareStatus is the status of a signing keyshare.
type SigningKeyshareStatus string

const (
	// KeyshareStatusAvailable is the status of a signing keyshare that is available.
	KeyshareStatusAvailable SigningKeyshareStatus = "AVAILABLE"
	// KeyshareStatusInUse is the status of a signing keyshare that is in use.
	KeyshareStatusInUse SigningKeyshareStatus = "IN_USE"
)

// Values returns the values of the signing keyshare status.
func (SigningKeyshareStatus) Values() []string {
	return []string{
		string(KeyshareStatusAvailable),
		string(KeyshareStatusInUse),
	}
}
