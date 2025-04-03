package upstream

import (
	"context"

	"github.com/google/uuid"
)

type Repository interface {
	GetUpstream(ctx context.Context, id uuid.UUID) (*Upstream, error)
}
