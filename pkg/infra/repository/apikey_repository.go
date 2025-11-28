package repository

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/domain"
	"github.com/NeuralTrust/TrustGate/pkg/domain/iam/apikey"
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

func (r *ApiKeyRepository) GetByKey(ctx context.Context, key string) (*apikey.APIKey, error) {
	entity := new(apikey.APIKey)
	if err := r.db.WithContext(ctx).
		Where("key = ?", key).
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

func (r *ApiKeyRepository) Get(ctx context.Context, id string) (*apikey.APIKey, error) {
	var entity apikey.APIKey
	err := r.db.WithContext(ctx).Where("id = ?", id).First(&entity).Error
	if err != nil {
		return nil, err
	}
	return &entity, nil
}

func (r *ApiKeyRepository) ListWithSubject(ctx context.Context, subjectID uuid.UUID) ([]apikey.APIKey, error) {
	var apiKeys []apikey.APIKey
	err := r.db.WithContext(ctx).Where("subject = ?", subjectID).Find(&apiKeys).Error
	return apiKeys, err
}

func (r *ApiKeyRepository) Update(ctx context.Context, apiKey *apikey.APIKey) error {
	result := r.db.WithContext(ctx).Save(apiKey)
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return fmt.Errorf("api key not found")
	}
	return nil
}

func (r *ApiKeyRepository) Delete(ctx context.Context, id uuid.UUID) error {
	result := r.db.WithContext(ctx).Where("id = ?", id).Delete(&apikey.APIKey{})
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return fmt.Errorf("api key not found")
	}
	return nil
}

func (r *ApiKeyRepository) DeleteWithSubject(ctx context.Context, id, subjectID uuid.UUID) error {
	result := r.db.WithContext(ctx).Where("id = ? AND subject = ?", id, subjectID).Delete(&apikey.APIKey{})
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return fmt.Errorf("api key not found")
	}
	return nil
}

func (r *ApiKeyRepository) Create(ctx context.Context, apiKey *apikey.APIKey) error {
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
