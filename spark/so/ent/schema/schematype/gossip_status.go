package schematype

type GossipStatus string

const (
	GossipStatusPending   GossipStatus = "PENDING"
	GossipStatusDelivered GossipStatus = "DELIVERED"
)

func (GossipStatus) Values() []string {
	return []string{
		string(GossipStatusPending),
		string(GossipStatusDelivered),
	}
}
