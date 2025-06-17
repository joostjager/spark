package schematype

// PreimageRequestStatus is the status of the preimage request
type PreimageRequestStatus string

const (
	// PreimageRequestStatusWaitingForPreimage is the status of the preimage request when it is waiting for preimage
	PreimageRequestStatusWaitingForPreimage PreimageRequestStatus = "WAITING_FOR_PREIMAGE"
	// PreimageRequestStatusPreimageShared is the status of the preimage request when it is preimage shared
	PreimageRequestStatusPreimageShared PreimageRequestStatus = "PREIMAGE_SHARED"
	// PreimageRequestStatusReturned is the status of the preimage request when it is returned
	PreimageRequestStatusReturned PreimageRequestStatus = "RETURNED"
)

// Values returns the values of the preimage request status
func (PreimageRequestStatus) Values() []string {
	return []string{
		string(PreimageRequestStatusWaitingForPreimage),
		string(PreimageRequestStatusPreimageShared),
		string(PreimageRequestStatusReturned),
	}
}
