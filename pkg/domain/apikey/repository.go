package apikey

import (
	"context"

	"github.com/google/uuid"
)

type Repository interface {
	GetByKey(ctx context.Context, key string) (*APIKey, error)
	GetByID(ctx context.Context, id uuid.UUID) (*APIKey, error)
	Get(ctx context.Context, id string) (*APIKey, error)
	List(ctx context.Context, gatewayID uuid.UUID) ([]APIKey, error)
	Create(ctx context.Context, apiKey *APIKey) error
	Update(ctx context.Context, apiKey *APIKey) error
	Delete(ctx context.Context, id, gatewayID uuid.UUID) error
	Validate(ctx context.Context, gatewayID string, apiKey string) (bool, error)
}
