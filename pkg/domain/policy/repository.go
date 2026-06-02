package policy

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

//go:generate mockery --name=Repository --dir=. --output=./mocks --filename=policy_repository_mock.go --case=underscore --with-expecter
type Repository interface {
	Save(ctx context.Context, p *Policy) error
	Update(ctx context.Context, p *Policy) error
	Delete(ctx context.Context, id ids.PolicyID) error
	FindByID(ctx context.Context, id ids.PolicyID) (*Policy, error)
	FindByIDs(ctx context.Context, gatewayID ids.GatewayID, policyIDs []ids.PolicyID) ([]*Policy, error)
	List(ctx context.Context, filter ListFilter) (items []*Policy, total int, err error)
}
