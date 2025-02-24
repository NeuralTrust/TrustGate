package cache

import (
	"context"
)

type EventSubscriber[T any] interface {
	OnEvent(ctx context.Context, ev T) error
}
