package service

import (
	"context"

	"github.com/NeuralTrust/TrustGate/pkg/models"
)

type Repository interface {
	GetService(ctx context.Context, id string) (*models.Service, error)
}
