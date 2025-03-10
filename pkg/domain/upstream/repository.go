package upstream

import (
	"context"
)

type Repository interface {
	GetUpstream(ctx context.Context, id string) (*Upstream, error)
}
