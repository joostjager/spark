package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	st "github.com/lightsparkdev/spark/so/ent/schema/schematype"
)

// TokenTransactionAuthorization is the schema for tracking keys required to authorize issuance and transfers.
type TokenCreate struct {
	ent.Schema
}

func (TokenCreate) Mixin() []ent.Mixin {
	return []ent.Mixin{
		BaseMixin{},
	}
}

func (TokenCreate) Fields() []ent.Field {
	return []ent.Field{
		field.Bytes("issuer_public_key").NotEmpty().Immutable().Unique(),
		field.Uint64("wallet_provided_timestamp").Optional().Immutable(),
		field.Bytes("issuer_signature").NotEmpty().Optional().Unique(),
		field.Bytes("operator_specific_issuer_signature").Optional().Unique(),
		field.Bytes("creation_entity_public_key").NotEmpty().Immutable(),
		field.String("token_name").NotEmpty().Immutable(),
		field.String("token_ticker").NotEmpty().Immutable(),
		field.Uint32("decimals").Immutable(),
		field.Bytes("max_supply").NotEmpty().Immutable(),
		field.Bool("is_freezable").Immutable(),
		field.Enum("network").GoType(st.Network("")).Immutable(),
	}
}

func (TokenCreate) Edges() []ent.Edge {
	return []ent.Edge{
		// Maps to the token transaction representing the token mint.
		edge.From("token_transaction", TokenTransaction.Type).
			Ref("create"),
	}
}

func (TokenCreate) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("issuer_public_key").Unique(),
	}
}
