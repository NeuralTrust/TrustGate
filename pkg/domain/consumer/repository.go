package consumer

import (
	"context"

	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
)

type ListFilter struct {
	GatewayID    ids.GatewayID
	NameContains string
	Page         int
	Size         int
}

//go:generate mockery --name=Repository --dir=. --output=./mocks --filename=consumer_repository_mock.go --case=underscore --with-expecter
type Repository interface {
	Save(ctx context.Context, c *Consumer) error
	Update(ctx context.Context, c *Consumer) error
	Delete(ctx context.Context, id ids.ConsumerID) error
	FindByID(ctx context.Context, id ids.ConsumerID) (*Consumer, error)
	List(ctx context.Context, filter ListFilter) (items []*Consumer, total int, err error)
	// ListByGateway returns every consumer of a gateway, unpaginated. It backs
	// the per-gateway aggregated read model consumed on the hot path.
	ListByGateway(ctx context.Context, gatewayID ids.GatewayID) ([]*Consumer, error)
}
