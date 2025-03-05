package gateway

import (
	"context"

	"github.com/NeuralTrust/TrustGate/pkg/models"
)

type Repository interface {
	Save(ctx context.Context, gateway *models.Gateway) error
}
