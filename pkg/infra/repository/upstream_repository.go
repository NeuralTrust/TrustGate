package repository

import (
	"context"

	"github.com/NeuralTrust/TrustGate/pkg/domain/upstream"
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

func (r *UpstreamRepository) GetUpstream(ctx context.Context, id string) (*upstream.Upstream, error) {
	var entity upstream.Upstream
	if err := r.db.WithContext(ctx).First(&entity, "id = ?", id).Error; err != nil {
		return nil, err
	}
	return &entity, nil
}
