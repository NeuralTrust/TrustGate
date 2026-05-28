package gateway

import (
	"context"

	"github.com/google/uuid"
)

// ListFilter is the input shape consumed by Repository.List. Page and
// Size are 1-based and must respect the bounds enforced by the HTTP
// helpers (page >= 1, 1 <= size <= 200).
type ListFilter struct {
	NameContains string
	Page         int
	Size         int
}

//go:generate mockery --name=Repository --dir=. --output=./mocks --filename=gateway_repository_mock.go --case=underscore --with-expecter

// Repository abstracts persistence for the gateway aggregate. The
// pgx implementation lives in pkg/infra/repository/gateway.
type Repository interface {
	Save(ctx context.Context, g *Gateway) error
	Update(ctx context.Context, g *Gateway) error
	Delete(ctx context.Context, id uuid.UUID) error
	FindByID(ctx context.Context, id uuid.UUID) (*Gateway, error)
	List(ctx context.Context, filter ListFilter) (items []*Gateway, total int, err error)
}
