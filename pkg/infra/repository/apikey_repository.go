package repository

import (
	"context"
	"fmt"

	"github.com/NeuralTrust/TrustGate/pkg/domain/apikey"
	"github.com/NeuralTrust/TrustGate/pkg/models"
	"gorm.io/gorm"
)

type ApiKeyRepository struct {
	db *gorm.DB
}

func NewApiKeyRepository(db *gorm.DB) apikey.Repository {
	return &ApiKeyRepository{
		db: db,
	}
}

func (r *ApiKeyRepository) GetByKey(ctx context.Context, gatewayID, key string) (*models.APIKey, error) {
	entity := new(models.APIKey)
	if err := r.db.WithContext(ctx).
		Where("key = ? AND gateway_id = ?", key, gatewayID).
		First(entity).Error; err != nil {
		return nil, fmt.Errorf("apikey not found: %w", err)
	}
	return entity, nil
}
