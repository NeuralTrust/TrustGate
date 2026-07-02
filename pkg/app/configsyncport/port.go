package configsyncport

import "context"

type SnapshotSignaler interface {
	Signal(ctx context.Context)
}
