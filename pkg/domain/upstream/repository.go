package upstream

import (
	"context"
	"github.com/NeuralTrust/TrustGate/pkg/models"
)

type Repository interface {
	GetUpstream(ctx context.Context, id string) (*models.Upstream, error)
}
