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

// LayeredBroadcaster is a VersionBroadcaster that also tells each data plane
// the version matching how it pulls: layeredVersion to one that pulls layered
// snapshots, version to any other. An empty layeredVersion notifies every
// connection of version.
type LayeredBroadcaster interface {
	VersionBroadcaster
	BroadcastScopeLayered(scope, version, layeredVersion string)
}

// OutboxRepository is the change-marker outbox as seen by the dispatcher. Every
// admin replica reads it through its own cursor and never deletes markers: rows
// leave only through PruneOlderThan, so one replica's compile cannot hide a
// marker from another. It carries no pgx types; the in-transaction append lives
// in the infra Appender the admin repositories consume.
//
// ReadSince returns, oldest first, the markers whose seq is above afterSeq, plus
// the lowest and highest seq still in the outbox (zero when it is empty), so a
// reader can tell that rows it never saw were pruned, or that the sequence
// restarted below what it already read. ReadSeqs returns the markers among
// seqs that are visible now; a reader uses it for seqs that were missing when it
// moved past them, because BIGSERIAL seq is assigned at INSERT, not COMMIT, and
// a lower seq can become visible after a higher one.
type OutboxRepository interface {
	ReadSince(ctx context.Context, afterSeq int64) (markers []Marker, bounds OutboxBounds, err error)
	ReadSeqs(ctx context.Context, seqs []int64) ([]Marker, error)
	PruneOlderThan(ctx context.Context, cutoff time.Time, keepMax int) (deleted int64, err error)
}

// OutboxBounds are the lowest and highest seq in the outbox, zero when it is
// empty.
type OutboxBounds struct {
	Min int64
	Max int64
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

// FragmentRef names one fragment of a layered snapshot by the SHA-256 of its
// bytes.
type FragmentRef struct {
	Digest [32]byte
	Size   int
}

// Manifest is a layered snapshot: the fragments whose concatenation, in order,
// decodes to the same configuration as the single-blob snapshot, and the
// version that names that list.
type Manifest struct {
	Version   string
	Fragments []FragmentRef
}
