package database

import (
	"context"

	"gorm.io/gorm"
)

type contextKey string

const txKey contextKey = "gorm_tx"

// TxManager executes a function within a database transaction.
// If fn returns an error, the transaction is rolled back; otherwise it is committed.
type TxManager interface {
	WithTransaction(ctx context.Context, fn func(ctx context.Context) error) error
}

type txManager struct {
	db *gorm.DB
}

func NewTxManager(db *gorm.DB) TxManager {
	return &txManager{db: db}
}

func (m *txManager) WithTransaction(ctx context.Context, fn func(ctx context.Context) error) error {
	return m.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		return fn(contextWithTx(ctx, tx))
	})
}

func contextWithTx(ctx context.Context, tx *gorm.DB) context.Context {
	return context.WithValue(ctx, txKey, tx)
}

// TxFromContext retrieves a GORM transaction stored in the context, if any.
func TxFromContext(ctx context.Context) (*gorm.DB, bool) {
	tx, ok := ctx.Value(txKey).(*gorm.DB)
	return tx, ok
}
