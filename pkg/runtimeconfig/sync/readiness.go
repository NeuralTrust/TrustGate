package configsync

import "context"

func ReadinessCheck[T any](store ConfigStore[T]) func(context.Context) error {
	return func(context.Context) error {
		if _, ok := store.Load(); ok {
			return nil
		}
		return ErrNotReady
	}
}
