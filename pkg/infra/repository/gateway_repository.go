package repository

import (
	"context"

	"github.com/NeuralTrust/TrustGate/pkg/common"
	"github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/models"
	"gorm.io/gorm"
)

type gatewayRepository struct {
	db *gorm.DB
}

func NewGatewayRepository(db *gorm.DB) gateway.Repository {
	return &gatewayRepository{
		db: db,
	}
}

func (r *gatewayRepository) Save(ctx context.Context, gateway *models.Gateway) error {
	ctx = context.WithValue(ctx, common.CacherKey, r)
	return r.db.WithContext(ctx).Create(gateway).Error
}
