package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
)

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

type Gossip struct {
	ent.Schema
}

func (Gossip) Mixin() []ent.Mixin {
	return []ent.Mixin{
		BaseMixin{},
	}
}

func (Gossip) Fields() []ent.Field {
	return []ent.Field{
		// List of participants that should receive the message.
		field.Strings("participants").Immutable(),
		// The message payload. Serilalized GossipMessage in gossip.proto
		field.Bytes("message").NotEmpty().Immutable(),
		// A bitmap of participants that have received the message, it maps with the order of participants.
		field.Bytes("receipts").Nillable(),
		// If all participants have received the message, the status is changed to DELIVERED.
		field.Enum("status").GoType(GossipStatus("")).Default(string(GossipStatusPending)),
	}
}

func (Gossip) Edges() []ent.Edge {
	return []ent.Edge{}
}

func (Gossip) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("status"),
	}
}
