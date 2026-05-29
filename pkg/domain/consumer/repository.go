package consumer

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

//go:generate mockery --name=Repository --dir=. --output=./mocks --filename=consumer_repository_mock.go --case=underscore --with-expecter
type Repository interface {
	Save(ctx context.Context, c *Consumer) error
	Update(ctx context.Context, c *Consumer) error
	Delete(ctx context.Context, id uuid.UUID) error
	FindByID(ctx context.Context, id uuid.UUID) (*Consumer, error)
	List(ctx context.Context, filter ListFilter) (items []*Consumer, total int, err error)
	// ListByGateway returns every consumer of a gateway, unpaginated. It backs
	// the per-gateway aggregated read model consumed on the hot path.
	ListByGateway(ctx context.Context, gatewayID uuid.UUID) ([]*Consumer, error)
}
