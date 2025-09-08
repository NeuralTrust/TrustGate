package gateway

import (
	"context"

	"github.com/google/uuid"
)

//go:generate mockery --name=Repository --dir=. --output=./mocks --filename=gateway_repository_mock.go --case=underscore --with-expecter
type Repository interface {
	Save(ctx context.Context, gateway *Gateway) error
	Get(ctx context.Context, id uuid.UUID) (*Gateway, error)
	List(ctx context.Context, offset, limit int) ([]Gateway, error)
	Update(ctx context.Context, gateway *Gateway) error
	Delete(id uuid.UUID) error
}
