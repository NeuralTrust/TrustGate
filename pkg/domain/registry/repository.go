package registry

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

//go:generate mockery --name=Repository --dir=. --output=./mocks --filename=registry_repository_mock.go --case=underscore --with-expecter
type Repository interface {
	Save(ctx context.Context, b *Registry) error
	Update(ctx context.Context, b *Registry) error
	Delete(ctx context.Context, id ids.RegistryID) error
	FindByID(ctx context.Context, id ids.RegistryID) (*Registry, error)
	FindByIDs(ctx context.Context, gatewayID ids.GatewayID, registryIDs []ids.RegistryID) ([]*Registry, error)
	List(ctx context.Context, filter ListFilter) (items []*Registry, total int, err error)
}
