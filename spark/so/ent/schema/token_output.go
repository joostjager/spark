package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	st "github.com/lightsparkdev/spark/so/ent/schema/schematype"
)

type TokenOutput struct {
	ent.Schema
}

func (TokenOutput) Mixin() []ent.Mixin {
	return []ent.Mixin{
		BaseMixin{},
	}
}

func (TokenOutput) Fields() []ent.Field {
	return []ent.Field{
		field.Enum("status").GoType(st.TokenOutputStatus("")),
		field.Bytes("owner_public_key").NotEmpty().Immutable(),
		field.Uint64("withdraw_bond_sats").Immutable(),
		field.Uint64("withdraw_relative_block_locktime").Immutable(),
		field.Bytes("withdraw_revocation_commitment").Immutable(),
		field.Bytes("token_public_key").NotEmpty().Immutable(),
		field.Bytes("token_amount").NotEmpty().Immutable(),
		field.Int32("created_transaction_output_vout").Immutable(),
		field.Bytes("spent_ownership_signature").Optional(),
		field.Bytes("spent_operator_specific_ownership_signature").Optional(),
		field.Int32("spent_transaction_input_vout").Optional(),
		field.Bytes("spent_revocation_secret").Optional(),
		field.Bytes("confirmed_withdraw_block_hash").Optional(),
		field.Enum("network").GoType(st.Network("")).Optional(),
		field.Bytes("token_identifier").Immutable().Optional(),
	}
}

func (TokenOutput) Edges() []ent.Edge {
	return []ent.Edge{
		edge.To("revocation_keyshare", SigningKeyshare.Type).
			Unique().
			Required().
			Immutable(),
		edge.To("output_created_token_transaction", TokenTransaction.Type).
			Unique(),
		// Not required because these are only set once the output has been spent.
		edge.To("output_spent_token_transaction", TokenTransaction.Type).
			Unique(),
	}
}

func (TokenOutput) Indexes() []ent.Index {
	return []ent.Index{
		// Enable fast fetching of all outputs owned by a token owner, or optionally all token outputs
		// owned by a token owner for a specific token type.
		index.Fields("owner_public_key", "token_public_key"),
		index.Fields("owner_public_key", "token_identifier"),
		// Enables quick unmarking of withdrawn outputs in response to block reorgs.
		index.Fields("confirmed_withdraw_block_hash"),
	}
}
