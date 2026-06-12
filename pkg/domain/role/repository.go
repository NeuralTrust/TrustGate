package role

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

//go:generate mockery --name=Repository --dir=. --output=./mocks --filename=role_repository_mock.go --case=underscore --with-expecter
type Repository interface {
	Save(ctx context.Context, r *Role) error
	Update(ctx context.Context, r *Role) error
	Delete(ctx context.Context, id ids.RoleID) error
	FindByID(ctx context.Context, id ids.RoleID) (*Role, error)
	FindByIDs(ctx context.Context, gatewayID ids.GatewayID, roleIDs []ids.RoleID) ([]*Role, error)
	List(ctx context.Context, filter ListFilter) (items []*Role, total int, err error)
	ListByGateway(ctx context.Context, gatewayID ids.GatewayID) ([]*Role, error)
	AttachRegistry(ctx context.Context, roleID ids.RoleID, registryID ids.RegistryID) error
	DetachRegistry(ctx context.Context, roleID ids.RoleID, registryID ids.RegistryID) error
	DetachRegistryIfUnreferenced(ctx context.Context, gatewayID ids.GatewayID, roleID ids.RoleID, registryID ids.RegistryID) (*Role, error)
}
