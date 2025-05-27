package repository

import (
	"context"

	"github.com/NeuralTrust/TrustGate/pkg/domain/service"
	"github.com/NeuralTrust/TrustGate/pkg/domain/upstream"
	"github.com/google/uuid"
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

func (r *UpstreamRepository) GetUpstream(ctx context.Context, id uuid.UUID) (*upstream.Upstream, error) {
	var entity upstream.Upstream
	if err := r.db.WithContext(ctx).First(&entity, "id = ?", id).Error; err != nil {
		return nil, err
	}
	return &entity, nil
}

func (r *UpstreamRepository) CreateUpstream(ctx context.Context, upstream *upstream.Upstream) error {
	return r.db.WithContext(ctx).Create(upstream).Error
}

func (r *UpstreamRepository) ListUpstreams(ctx context.Context, gatewayID uuid.UUID, offset, limit int) ([]upstream.Upstream, error) {
	var upstreams []upstream.Upstream
	query := r.db.WithContext(ctx).Where("gateway_id = ?", gatewayID)

	if limit > 0 {
		query = query.Offset(offset).Limit(limit)
	}

	if err := query.Find(&upstreams).Error; err != nil {
		return nil, err
	}
	return upstreams, nil
}

func (r *UpstreamRepository) UpdateUpstream(ctx context.Context, upstream *upstream.Upstream) error {
	return r.db.WithContext(ctx).Save(upstream).Error
}

func (r *UpstreamRepository) DeleteUpstream(ctx context.Context, id string) error {
	var count int64
	if err := r.db.WithContext(ctx).Model(&service.Service{}).Where("upstream_id = ?", id).Count(&count).Error; err != nil {
		return err
	}
	if count > 0 {
		return upstream.ErrUpstreamIsBeingUsed
	}

	return r.db.WithContext(ctx).Delete(&upstream.Upstream{}, "id = ?", id).Error
}
