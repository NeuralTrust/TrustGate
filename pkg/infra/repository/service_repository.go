package repository

import (
	"context"
	"fmt"

	"github.com/NeuralTrust/TrustGate/pkg/domain/service"
	"gorm.io/gorm"
)

type ServiceRepository struct {
	db *gorm.DB
}

func NewServiceRepository(db *gorm.DB) service.Repository {
	return &ServiceRepository{
		db: db,
	}
}

func (r *ServiceRepository) GetService(ctx context.Context, id string) (*service.Service, error) {
	var entity service.Service
	result := r.db.WithContext(ctx).
		Preload("Upstream").
		First(&entity, "id = ?", id)
	if result.Error != nil {
		return nil, fmt.Errorf("service: %w", result.Error)
	}
	return &entity, nil
}
