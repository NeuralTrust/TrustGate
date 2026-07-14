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
	"errors"
	"io"
	"log/slog"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/infra/cache/event"
	infrasnapshot "github.com/NeuralTrust/TrustGate/pkg/infra/configsnapshot"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

type recordingLocal struct {
	calls int
}

func (r *recordingLocal) Signal(_ context.Context) {
	r.calls++
}

type recordingPublisher struct {
	published []string
	err       error
}

func (p *recordingPublisher) Publish(_ context.Context, ev event.Event) error {
	p.published = append(p.published, ev.Type())
	return p.err
}

func TestDistributedSignaler_Signal_RecompilesLocallyAndFansOut(t *testing.T) {
	t.Parallel()
	local := &recordingLocal{}
	publisher := &recordingPublisher{}
	signaler := infrasnapshot.NewDistributedSignaler(local, publisher, discardLogger())

	signaler.Signal(context.Background())

	if local.calls != 1 {
		t.Fatalf("expected local recompile once, got %d", local.calls)
	}
	if len(publisher.published) != 1 || publisher.published[0] != event.SnapshotDirtyEventType {
		t.Fatalf("expected one SnapshotDirtyEvent published to peers, got %v", publisher.published)
	}
}

func TestDistributedSignaler_Signal_LocalRecompileSurvivesPublishError(t *testing.T) {
	t.Parallel()
	local := &recordingLocal{}
	publisher := &recordingPublisher{err: errors.New("redis down")}
	signaler := infrasnapshot.NewDistributedSignaler(local, publisher, discardLogger())

	signaler.Signal(context.Background())

	if local.calls != 1 {
		t.Fatalf("local recompile must run even when peer fan-out fails, got %d calls", local.calls)
	}
}

func TestDistributedSignaler_Signal_NilPublisherStillRecompilesLocally(t *testing.T) {
	t.Parallel()
	local := &recordingLocal{}
	signaler := infrasnapshot.NewDistributedSignaler(local, nil, discardLogger())

	signaler.Signal(context.Background())

	if local.calls != 1 {
		t.Fatalf("expected local recompile once, got %d", local.calls)
	}
}
