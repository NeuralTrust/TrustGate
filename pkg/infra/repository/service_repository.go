package repository

import (
	"context"
	"fmt"

	"github.com/NeuralTrust/TrustGate/pkg/domain/forwarding_rule"
	"github.com/NeuralTrust/TrustGate/pkg/domain/service"
	"github.com/NeuralTrust/TrustGate/pkg/domain/upstream"
	"github.com/google/uuid"
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

func (r *ServiceRepository) Get(ctx context.Context, id string) (*service.Service, error) {
	var entity service.Service
	result := r.db.WithContext(ctx).
		Preload("Upstream").
		First(&entity, "id = ?", id)
	if result.Error != nil {
		return nil, fmt.Errorf("service: %w", result.Error)
	}
	return &entity, nil
}

func (r *ServiceRepository) Create(ctx context.Context, service *service.Service) error {
	// Verify upstream exists and belongs to the same gateway
	var entity upstream.Upstream
	if err := r.db.WithContext(ctx).Where("id = ? AND gateway_id = ?", service.UpstreamID, service.GatewayID).
		First(&entity).Error; err != nil {
		return fmt.Errorf("invalid upstream_id or upstream belongs to different gateway: %w", err)
	}

	return r.db.WithContext(ctx).Create(service).Error
}

func (r *ServiceRepository) List(ctx context.Context, gatewayID uuid.UUID, offset, limit int) ([]service.Service, error) {
	var services []service.Service
	query := r.db.WithContext(ctx).Where("gateway_id = ?", gatewayID).Preload("Upstream")

	if limit > 0 {
		query = query.Offset(offset).Limit(limit)
	}

	if err := query.Find(&services).Error; err != nil {
		return nil, err
	}
	return services, nil
}

func (r *ServiceRepository) Update(ctx context.Context, service *service.Service) error {
	// Verify upstream exists and belongs to the same gateway
	var entity upstream.Upstream
	if err := r.db.WithContext(ctx).
		Where("id = ? AND gateway_id = ?", service.UpstreamID, service.GatewayID).
		First(&entity).Error; err != nil {
		return fmt.Errorf("invalid upstream_id or upstream belongs to different gateway: %w", err)
	}

	return r.db.WithContext(ctx).Save(service).Error
}

func (r *ServiceRepository) Delete(ctx context.Context, id string) error {
	var count int64
	if err := r.db.WithContext(ctx).Model(&forwarding_rule.ForwardingRule{}).Where("service_id = ?", id).Count(&count).Error; err != nil {
		return err
	}
	if count > 0 {
		return service.ErrServiceIsBeingUsed
	}

	return r.db.WithContext(ctx).Delete(&service.Service{}, "id = ?", id).Error
}
