package repository

import (
	"context"
	"errors"

	"github.com/NeuralTrust/TrustGate/pkg/common"
	"github.com/NeuralTrust/TrustGate/pkg/domain/apikey"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/errors"
	"github.com/NeuralTrust/TrustGate/pkg/domain/forwarding_rule"
	"github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/domain/service"
	"github.com/NeuralTrust/TrustGate/pkg/domain/upstream"
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

func (r *gatewayRepository) Get(ctx context.Context, id uuid.UUID) (*gateway.Gateway, error) {
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

func (r *gatewayRepository) List(ctx context.Context, offset, limit int) ([]gateway.Gateway, error) {
	var gateways []gateway.Gateway
	err := r.db.WithContext(ctx).Model(&gateway.Gateway{}).
		Order("created_at desc").
		Limit(limit).
		Offset(offset).
		Find(&gateways).Error

	for i := range gateways {
		if gateways[i].RequiredPlugins == nil {
			gateways[i].RequiredPlugins = []types.PluginConfig{}
		}
	}

	return gateways, err
}

func (r *gatewayRepository) Update(ctx context.Context, gateway *gateway.Gateway) error {
	if gateway.RequiredPlugins == nil {
		gateway.RequiredPlugins = []types.PluginConfig{}
	}
	return r.db.WithContext(ctx).Save(gateway).Error
}

func (r *gatewayRepository) Delete(id uuid.UUID) error {
	// Start a transaction
	tx := r.db.Begin()
	tx = tx.Debug()
	if tx.Error != nil {
		return tx.Error
	}

	// Delete associated forwarding rules first
	if err := tx.Unscoped().Where("gateway_id = ?", id).Delete(&forwarding_rule.ForwardingRule{}).Error; err != nil {
		tx.Rollback()
		return err
	}
	if err := tx.Unscoped().Where("gateway_id = ?", id).Delete(&service.Service{}).Error; err != nil {
		tx.Rollback()
		return err
	}
	if err := tx.Unscoped().Where("gateway_id = ?", id).Delete(&upstream.Upstream{}).Error; err != nil {
		tx.Rollback()
		return err
	}
	if err := tx.Unscoped().Where("gateway_id = ?", id).Delete(&apikey.APIKey{}).Error; err != nil {
		tx.Rollback()
		return err
	}

	// Then delete the gateway
	if err := tx.Unscoped().Delete(&gateway.Gateway{ID: id}).Error; err != nil {
		tx.Rollback()
		return err
	}

	// Commit the transaction and check for errors
	if err := tx.Commit().Error; err != nil {
		return err
	}

	return nil
}
