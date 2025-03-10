package gateway

import (
	"context"
)

type Repository interface {
	Save(ctx context.Context, gateway *Gateway) error
}
