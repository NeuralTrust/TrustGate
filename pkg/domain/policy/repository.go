package policy

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

//go:generate mockery --name=Repository --dir=. --output=./mocks --filename=policy_repository_mock.go --case=underscore --with-expecter
type Repository interface {
	Save(ctx context.Context, p *Policy) error
	Update(ctx context.Context, p *Policy) error
	Delete(ctx context.Context, id uuid.UUID) error
	FindByID(ctx context.Context, id uuid.UUID) (*Policy, error)
	FindByIDs(ctx context.Context, gatewayID uuid.UUID, ids []uuid.UUID) ([]*Policy, error)
	List(ctx context.Context, filter ListFilter) (items []*Policy, total int, err error)
}
