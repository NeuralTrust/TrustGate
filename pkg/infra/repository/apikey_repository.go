package repository

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/domain/apikey"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/errors"
	"github.com/google/uuid"
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

func (r *ApiKeyRepository) GetByKey(ctx context.Context, gatewayID string, key string) (*apikey.APIKey, error) {
	entity := new(apikey.APIKey)
	if err := r.db.WithContext(ctx).
		Where("key = ? AND gateway_id = ?", key, gatewayID).
		First(entity).Error; err != nil {
		return nil, fmt.Errorf("apikey not found: %w", err)
	}
	return entity, nil
}

func (r *ApiKeyRepository) GetByID(ctx context.Context, id uuid.UUID) (*apikey.APIKey, error) {
	entity := new(apikey.APIKey)
	if err := r.db.WithContext(ctx).Where("id = ?", id).First(entity).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, domain.NewNotFoundError("apikey", id)
		}
		return nil, err
	}
	return entity, nil
}

func (r *ApiKeyRepository) CreateAPIKey(ctx context.Context, apiKey *apikey.APIKey) error {
	if apiKey.GatewayID == uuid.Nil {
		return fmt.Errorf("gateway_id is required")
	}
	if apiKey.Name == "" {
		return fmt.Errorf("name is required")
	}
	if apiKey.Key == "" {
		return fmt.Errorf("key is required")
	}

	now := time.Now()
	if apiKey.CreatedAt.IsZero() {
		apiKey.CreatedAt = now
	}

	if !apiKey.Active {
		apiKey.Active = true
	}

	result := r.db.WithContext(ctx).Create(apiKey)
	if result.Error != nil {
		return fmt.Errorf("failed to create API key: %w", result.Error)
	}

	return nil
}
