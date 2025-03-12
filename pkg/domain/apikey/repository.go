package apikey

import (
	"context"
)

type Repository interface {
	GetByKey(ctx context.Context, gatewayID string, key string) (*APIKey, error)
	GetByID(ctx context.Context, id string) (*APIKey, error)
	CreateAPIKey(ctx context.Context, apiKey *APIKey) error
}
