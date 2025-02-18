package repository

import (
	"context"
	"github.com/NeuralTrust/TrustGate/pkg/domain/upstream"
	"github.com/NeuralTrust/TrustGate/pkg/models"
	"gorm.io/gorm"
)

type UpstreamRepository struct {
	db *gorm.DB
}

func NewUpstreamRepository(db *gorm.DB) upstream.Repository {
	return &UpstreamRepository{
		db: db,
	}
}

func (r *UpstreamRepository) GetUpstream(ctx context.Context, id string) (*models.Upstream, error) {
	var entity models.Upstream
	if err := r.db.WithContext(ctx).First(&entity, "id = ?", id).Error; err != nil {
		return nil, err
	}
	return &entity, nil
}
