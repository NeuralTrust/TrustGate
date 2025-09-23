package upstream

import (
	"context"

	"github.com/google/uuid"
)

//go:generate mockery --name=Repository --dir=. --output=./mocks --filename=upstream_repository_mock.go --case=underscore --with-expecter
type Repository interface {
	GetUpstream(ctx context.Context, id uuid.UUID) (*Upstream, error)
	CreateUpstream(ctx context.Context, upstream *Upstream) error
	ListUpstreams(ctx context.Context, gatewayID uuid.UUID, offset, limit int) ([]Upstream, error)
	UpdateUpstream(ctx context.Context, upstream *Upstream) error
	DeleteUpstream(ctx context.Context, id string) error
}
