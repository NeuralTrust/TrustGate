package configsyncport

import (
	"context"
	"time"
)

type SnapshotSignaler interface {
	Signal(ctx context.Context)
}

// VersionBroadcaster fans a new snapshot version out to connected data planes. The
// gRPC hub implements it; the dispatcher depends only on this port so the app layer
// never imports gRPC.
type VersionBroadcaster interface {
	Broadcast(version string)
}

// OutboxRepository is the change-marker outbox as seen by the dispatcher: read the
// marker frontier, drain by processed seq, and prune under the safety bound. It
// carries no pgx types; the in-transaction append lives in the infra Appender the
// admin repositories consume, so the app layer never imports pgx.
type OutboxRepository interface {
	MaxSeq(ctx context.Context) (seq int64, err error)
	PendingCount(ctx context.Context) (int64, error)
	DeleteUpTo(ctx context.Context, seq int64) (deleted int64, err error)
	PruneOlderThan(ctx context.Context, cutoff time.Time, keepMax int) (deleted int64, err error)
}
