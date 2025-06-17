package schematype

// TreeStatus is the status of a tree node.
type TreeStatus string

const (
	// TreeStatusPending is the status of a tree that the base L1 transaction is not confirmed yet.
	TreeStatusPending TreeStatus = "PENDING"
	// TreeStatusAvailable is the status of a tree that the base L1 transaction is confirmed.
	TreeStatusAvailable TreeStatus = "AVAILABLE"
	// TreeStatusExited is the status of a tree that has exited.
	TreeStatusExited TreeStatus = "EXITED"
)

// Values returns the values of the tree node status.
func (TreeStatus) Values() []string {
	return []string{
		string(TreeStatusPending),
		string(TreeStatusAvailable),
		string(TreeStatusExited),
	}
}
