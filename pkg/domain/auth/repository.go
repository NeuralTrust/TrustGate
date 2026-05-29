package auth

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

//go:generate mockery --name=Repository --dir=. --output=./mocks --filename=auth_repository_mock.go --case=underscore --with-expecter
type Repository interface {
	Save(ctx context.Context, a *Auth) error
	Update(ctx context.Context, a *Auth) error
	Delete(ctx context.Context, id uuid.UUID) error
	FindByID(ctx context.Context, id uuid.UUID) (*Auth, error)
	FindByIDs(ctx context.Context, gatewayID uuid.UUID, ids []uuid.UUID) ([]*Auth, error)
	List(ctx context.Context, filter ListFilter) (items []*Auth, total int, err error)
}
