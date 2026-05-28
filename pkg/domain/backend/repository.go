package backend

import (
	"context"

	"github.com/google/uuid"
)

type ListFilter struct {
	GatewayID    uuid.UUID
	NameContains string
	Page         int
	Size         int
}

//go:generate mockery --name=Repository --dir=. --output=./mocks --filename=backend_repository_mock.go --case=underscore --with-expecter
type Repository interface {
	Save(ctx context.Context, b *Backend) error
	Update(ctx context.Context, b *Backend) error
	Delete(ctx context.Context, id uuid.UUID) error
	FindByID(ctx context.Context, id uuid.UUID) (*Backend, error)
	FindByIDs(ctx context.Context, gatewayID uuid.UUID, ids []uuid.UUID) ([]*Backend, error)
	List(ctx context.Context, filter ListFilter) (items []*Backend, total int, err error)
}
