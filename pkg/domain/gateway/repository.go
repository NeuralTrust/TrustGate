package gateway

import (
	"context"

	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
)

type ListFilter struct {
	NameContains string
	Page         int
	Size         int
}

//go:generate mockery --name=Repository --dir=. --output=./mocks --filename=gateway_repository_mock.go --case=underscore --with-expecter
type Repository interface {
	Save(ctx context.Context, g *Gateway) error
	Update(ctx context.Context, g *Gateway) error
	Delete(ctx context.Context, id ids.GatewayID) error
	FindByID(ctx context.Context, id ids.GatewayID) (*Gateway, error)
	List(ctx context.Context, filter ListFilter) (items []*Gateway, total int, err error)
}
