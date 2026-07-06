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

package configsnapshot_test

import (
	"context"
	"testing"

	appsnapshot "github.com/NeuralTrust/TrustGate/pkg/app/configsnapshot"
)

type countingSignaler struct {
	calls int
}

func (c *countingSignaler) Signal() { c.calls++ }

func TestSnapshotVersionPublisherSignals(t *testing.T) {
	sig := &countingSignaler{}
	publisher := appsnapshot.NewSnapshotVersionPublisher(sig)
	publisher.Signal(context.Background())
	publisher.Signal(context.Background())
	if sig.calls != 2 {
		t.Fatalf("expected 2 signals, got %d", sig.calls)
	}
}

func TestSnapshotVersionPublisherNilIsNoop(t *testing.T) {
	publisher := appsnapshot.NewSnapshotVersionPublisher(nil)
	publisher.Signal(context.Background())
}
