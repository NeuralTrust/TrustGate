package apikey

import (
	"context"
)

type Repository interface {
	GetByKey(ctx context.Context, gatewayID string, key string) (*APIKey, error)
}
