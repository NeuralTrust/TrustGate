package service

import (
	"context"

	"github.com/google/uuid"
)

type Repository interface {
	Get(ctx context.Context, id string) (*Service, error)
	Create(ctx context.Context, service *Service) error
	List(ctx context.Context, gatewayID uuid.UUID, offset, limit int) ([]Service, error)
	Update(ctx context.Context, service *Service) error
	Delete(ctx context.Context, id string) error
}
