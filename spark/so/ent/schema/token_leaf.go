package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	st "github.com/lightsparkdev/spark/so/ent/schema/schematype"
)

// TokenLeaf is the schema for the token leafs table.
type TokenLeaf struct {
	ent.Schema
}

// Mixin is the mixin for the token leafs table.
func (TokenLeaf) Mixin() []ent.Mixin {
	return []ent.Mixin{
		BaseMixin{},
	}
}

// Fields are the fields for the token leafs table.
func (TokenLeaf) Fields() []ent.Field {
	return []ent.Field{
		field.Enum("status").GoType(st.TokenLeafStatus("")),
		field.Bytes("owner_public_key").NotEmpty().Immutable(),
		field.Uint64("withdraw_bond_sats").Immutable(),
		field.Uint64("withdraw_relative_block_locktime").Immutable(),
		field.Bytes("withdraw_revocation_public_key").Immutable(),
		field.Bytes("token_public_key").NotEmpty().Immutable(),
		field.Bytes("token_amount").NotEmpty().Immutable(),
		field.Int32("leaf_created_transaction_output_vout").Immutable(),
		field.Bytes("leaf_spent_ownership_signature").Optional(),
		field.Bytes("leaf_spent_operator_specific_ownership_signature").Optional(),
		field.Int32("leaf_spent_transaction_input_vout").Optional(),
		field.Bytes("leaf_spent_revocation_private_key").Optional(),
		field.Bytes("confirmed_withdraw_block_hash").Optional(),
		field.Enum("network").GoType(st.Network("")).Optional(),
	}
}

// Edges are the edges for the token leafs table.
func (TokenLeaf) Edges() []ent.Edge {
	return []ent.Edge{
		edge.To("revocation_keyshare", SigningKeyshare.Type).
			Unique().
			Required().
			Immutable(),
		edge.To("leaf_created_token_transaction_receipt", TokenTransactionReceipt.Type).
			Unique(),
		// Not required because these are only set once the leaf has been spent.
		edge.To("leaf_spent_token_transaction_receipt", TokenTransactionReceipt.Type).
			Unique(),
	}
}

// Indexes are the indexes for the token leafs table.
func (TokenLeaf) Indexes() []ent.Index {
	return []ent.Index{
		// Enable fast fetching of all leaves owned by a token owner, or optionally all token leaves
		// owned by a token owner for a specific token type.
		index.Fields("owner_public_key", "token_public_key"),
		// Enables quick unmarking of withdrawn leaves in response to block reorgs.
		index.Fields("confirmed_withdraw_block_hash"),
	}
}
