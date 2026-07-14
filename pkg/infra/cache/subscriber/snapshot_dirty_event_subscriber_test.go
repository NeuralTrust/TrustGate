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

package subscriber_test

import (
	"context"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/infra/cache/event"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache/subscriber"
)

type countingSignaler struct {
	calls int
}

func (c *countingSignaler) Signal() {
	c.calls++
}

func TestSnapshotDirtyEventSubscriber_OnEvent_SignalsLocalRecompile(t *testing.T) {
	t.Parallel()
	signaler := &countingSignaler{}
	sub := subscriber.NewSnapshotDirtyEventSubscriber(signaler)

	if err := sub.OnEvent(context.Background(), event.SnapshotDirtyEvent{}); err != nil {
		t.Fatalf("OnEvent error: %v", err)
	}

	if signaler.calls != 1 {
		t.Fatalf("expected local recompile to be signalled once, got %d", signaler.calls)
	}
}

func TestSnapshotDirtyEventSubscriber_OnEvent_NilSignalerIsNoOp(t *testing.T) {
	t.Parallel()
	sub := subscriber.NewSnapshotDirtyEventSubscriber(nil)

	if err := sub.OnEvent(context.Background(), event.SnapshotDirtyEvent{}); err != nil {
		t.Fatalf("OnEvent with nil signaler must not error: %v", err)
	}
}
