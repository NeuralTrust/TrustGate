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

package configsnapshot

import (
	"context"
	"log/slog"

	"github.com/NeuralTrust/TrustGate/pkg/infra/cache"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache/event"
)

// LocalSignaler triggers a recompile-and-broadcast on the current process.
type LocalSignaler interface {
	Signal(ctx context.Context)
}

// DistributedSignaler recompiles the snapshot on the local admin process and
// fans the same nudge out to every other admin replica over the Redis event bus.
//
// Version broadcast to data planes is in-process per admin pod: a write handled
// by replica A only reaches the data planes streaming from A. Publishing a
// SnapshotDirtyEvent makes replica B recompile and push to its own data planes
// immediately, instead of leaving them stale until B's periodic backstop fires.
type DistributedSignaler struct {
	local     LocalSignaler
	publisher cache.EventPublisher
	logger    *slog.Logger
}

func NewDistributedSignaler(local LocalSignaler, publisher cache.EventPublisher, logger *slog.Logger) *DistributedSignaler {
	return &DistributedSignaler{local: local, publisher: publisher, logger: logger}
}

func (s *DistributedSignaler) Signal(ctx context.Context) {
	if s.local != nil {
		s.local.Signal(ctx)
	}
	if s.publisher == nil {
		return
	}
	if err := s.publisher.Publish(ctx, event.SnapshotDirtyEvent{}); err != nil {
		s.logger.Warn("configsnapshot: failed to publish snapshot dirty event to peers",
			slog.String("error", err.Error()))
	}
}
