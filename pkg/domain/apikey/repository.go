package apikey

import (
	"context"

	"github.com/google/uuid"
)

type Repository interface {
	GetByKey(ctx context.Context, gatewayID string, key string) (*APIKey, error)
	GetByID(ctx context.Context, id uuid.UUID) (*APIKey, error)
	CreateAPIKey(ctx context.Context, apiKey *APIKey) error
}
