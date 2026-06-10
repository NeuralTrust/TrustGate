package auth

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

//go:generate mockery --name=Repository --dir=. --output=./mocks --filename=auth_repository_mock.go --case=underscore --with-expecter
type Repository interface {
	Save(ctx context.Context, a *Auth) error
	Update(ctx context.Context, a *Auth) error
	Delete(ctx context.Context, id ids.AuthID) error
	FindByID(ctx context.Context, id ids.AuthID) (*Auth, error)
	FindByIDs(ctx context.Context, gatewayID ids.GatewayID, authIDs []ids.AuthID) ([]*Auth, error)
	FindByAPIKeyHash(ctx context.Context, keyHash string) (*Auth, error)
	ListEnabledByGatewayAndType(ctx context.Context, gatewayID ids.GatewayID, authType Type) ([]*Auth, error)
	List(ctx context.Context, filter ListFilter) (items []*Auth, total int, err error)
}
