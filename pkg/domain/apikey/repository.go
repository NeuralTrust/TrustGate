package apikey

import (
	"context"

	"github.com/NeuralTrust/TrustGate/pkg/models"
)

type Repository interface {
	GetByKey(ctx context.Context, gatewayID string, key string) (*models.APIKey, error)
}
