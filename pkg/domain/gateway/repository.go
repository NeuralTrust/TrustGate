package gateway

import (
	"context"

	"github.com/google/uuid"
)

//go:generate mockery --name=Repository --dir=. --output=../../../mocks --filename=gateway_repository_mock.go --case=underscore --with-expecter
type Repository interface {
	Save(ctx context.Context, gateway *Gateway) error
	GetGateway(ctx context.Context, id uuid.UUID) (*Gateway, error)
}
