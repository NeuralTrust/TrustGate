package repository

import (
	"context"
	"errors"

	"github.com/NeuralTrust/TrustGate/pkg/common"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/errors"
	"github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/types"
	"github.com/google/uuid"
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

func (r *gatewayRepository) Save(ctx context.Context, gateway *gateway.Gateway) error {
	ctx = context.WithValue(ctx, common.CacherKey, r)
	return r.db.WithContext(ctx).Create(gateway).Error
}

func (r *gatewayRepository) GetGateway(ctx context.Context, id uuid.UUID) (*gateway.Gateway, error) {
	var entity gateway.Gateway
	if err := r.db.WithContext(ctx).First(&entity, "id = ?", id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, domain.NewNotFoundError("gateway", id)
		}
		return nil, err
	}
	if entity.RequiredPlugins == nil {
		entity.RequiredPlugins = []types.PluginConfig{}
	}
	return &entity, nil
}
