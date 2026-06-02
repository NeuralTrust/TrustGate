package backend

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

//go:generate mockery --name=Repository --dir=. --output=./mocks --filename=backend_repository_mock.go --case=underscore --with-expecter
type Repository interface {
	Save(ctx context.Context, b *Backend) error
	Update(ctx context.Context, b *Backend) error
	Delete(ctx context.Context, id ids.BackendID) error
	FindByID(ctx context.Context, id ids.BackendID) (*Backend, error)
	FindByIDs(ctx context.Context, gatewayID ids.GatewayID, backendIDs []ids.BackendID) ([]*Backend, error)
	List(ctx context.Context, filter ListFilter) (items []*Backend, total int, err error)
}
