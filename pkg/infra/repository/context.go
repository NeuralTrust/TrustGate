package repository

import (
	"context"

	"github.com/NeuralTrust/TrustGate/pkg/infra/database"
	"gorm.io/gorm"
)

func dbFromContext(ctx context.Context, fallback *gorm.DB) *gorm.DB {
	if tx, ok := database.TxFromContext(ctx); ok {
		return tx
	}
	return fallback
}
