package ent

import (
	"context"
)

// ContextKey is a type for context keys.
type contextKey string

// TxKey is the context key for the database transaction.
const txKey contextKey = "tx"

// Inject the database transaction into the context. This should ONLY be called from the start of
// a request or worker context (e.g. in a top-level gRPC interceptor).
func Inject(ctx context.Context, tx *Tx) context.Context {
	return context.WithValue(ctx, txKey, tx)
}

// GetDbFromContext returns the database transaction from the context.
func GetDbFromContext(ctx context.Context) *Tx {
	return ctx.Value(txKey).(*Tx)
}
