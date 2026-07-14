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

package subscriber

import (
	"context"

	"github.com/NeuralTrust/TrustGate/pkg/infra/cache"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache/event"
)

// SnapshotSignaler triggers a local recompile-and-broadcast of the runtime
// config snapshot. It is satisfied by the config-sync dispatcher.
type SnapshotSignaler interface {
	Signal()
}

var _ cache.EventSubscriber[event.SnapshotDirtyEvent] = (*SnapshotDirtyEventSubscriber)(nil)

// SnapshotDirtyEventSubscriber recompiles the local snapshot when a peer admin
// replica reports a config change, so every replica pushes the new version to
// its own connected data planes without waiting for the backstop timer.
type SnapshotDirtyEventSubscriber struct {
	signaler SnapshotSignaler
}

func NewSnapshotDirtyEventSubscriber(signaler SnapshotSignaler) cache.EventSubscriber[event.SnapshotDirtyEvent] {
	return &SnapshotDirtyEventSubscriber{signaler: signaler}
}

func (s *SnapshotDirtyEventSubscriber) OnEvent(_ context.Context, _ event.SnapshotDirtyEvent) error {
	if s.signaler == nil {
		return nil
	}
	s.signaler.Signal()
	return nil
}
