// Copyright 2026 NeuralTrust
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package configsyncport

import (
	"context"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
)

type SnapshotSignaler interface {
	Signal(ctx context.Context)
}

// VersionBroadcaster fans a new snapshot version out to connected data planes. The
// gRPC hub implements it; the dispatcher depends only on this port so the app layer
// never imports gRPC.
type VersionBroadcaster interface {
	// Broadcast delivers version to every connected data plane.
	Broadcast(version string)
	// BroadcastScope delivers version only to connections registered under scope,
	// so a change to one instance wakes only that instance's pods. An empty scope
	// targets the in-cluster shared/composite data planes that serve the global
	// snapshot.
	BroadcastScope(scope, version string)
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

// MarkerKind names what an outbox marker dirtied.
type MarkerKind string

const (
	// MarkerGateway dirties the configuration of one gateway.
	MarkerGateway MarkerKind = "gateway"
	// MarkerCatalog dirties the shared provider and model catalog.
	MarkerCatalog MarkerKind = "catalog"
	// MarkerAll dirties everything and forces a full compile. Markers written
	// before the outbox carried a kind read as MarkerAll.
	MarkerAll MarkerKind = "all"
)

// Marker is one committed change marker and what it dirtied. GatewayID is set
// only when Kind is MarkerGateway.
type Marker struct {
	Seq       int64
	Kind      MarkerKind
	GatewayID ids.GatewayID
}

// OutboxMarkerReader reads committed change markers with what they dirtied.
// ReadSince returns, oldest first, the markers whose seq is above afterSeq,
// plus the lowest seq still in the outbox (zero when it is empty) so a reader
// can tell that rows it never saw were pruned.
type OutboxMarkerReader interface {
	ReadSince(ctx context.Context, afterSeq int64) (markers []Marker, minSeq int64, err error)
}
