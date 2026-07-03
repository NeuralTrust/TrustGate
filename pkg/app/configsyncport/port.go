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
// set of markers visible before a compile, drain exactly that set once the snapshot
// is broadcast, and prune under the safety bound. It carries no pgx types; the
// in-transaction append lives in the infra Appender the admin repositories consume,
// so the app layer never imports pgx.
//
// Drain works on the observed set rather than a seq range because BIGSERIAL seq is
// assigned at INSERT, not COMMIT: a lower seq can become visible after a higher one,
// so a range delete could drop a marker whose write was not yet in the compiled
// snapshot. Deleting only the observed set lets such a late marker survive to the
// next cycle.
type OutboxRepository interface {
	Pending(ctx context.Context) (seqs []int64, err error)
	PendingCount(ctx context.Context) (int64, error)
	DeleteSeqs(ctx context.Context, seqs []int64) (deleted int64, err error)
	PruneOlderThan(ctx context.Context, cutoff time.Time, keepMax int) (deleted int64, err error)
}
