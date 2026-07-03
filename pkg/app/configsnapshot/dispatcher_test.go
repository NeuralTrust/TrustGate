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
	"sync"
	"testing"
	"time"

	appsnapshot "github.com/NeuralTrust/TrustGate/pkg/app/configsnapshot"
	authdomain "github.com/NeuralTrust/TrustGate/pkg/domain/auth"
	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	gatewaydomain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	policydomain "github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	roledomain "github.com/NeuralTrust/TrustGate/pkg/domain/role"
	infrasnapshot "github.com/NeuralTrust/TrustGate/pkg/infra/configsnapshot"
	"github.com/NeuralTrust/TrustGate/pkg/runtimeconfig/snapshot/readmodel"
)

var errCompile = errors.New("compile failed")

type settableGateways struct {
	mu    sync.Mutex
	items []*gatewaydomain.Gateway
}

func (s *settableGateways) set(items []*gatewaydomain.Gateway) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.items = items
}

func (s *settableGateways) List(_ context.Context, filter gatewaydomain.ListFilter) ([]*gatewaydomain.Gateway, int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if filter.Page > 1 {
		return nil, 0, nil
	}
	return s.items, len(s.items), nil
}

func newDispatchCompiler(gateways appsnapshot.GatewayReader) *appsnapshot.Compiler {
	return appsnapshot.NewCompiler(
		gateways,
		fakeConsumers{byGateway: map[string][]*consumerdomain.Consumer{}},
		fakeRegistries{byGateway: map[string][]*registrydomain.Registry{}},
		fakePolicies{byGateway: map[string][]*policydomain.Policy{}},
		fakeAuths{byGateway: map[string][]*authdomain.Auth{}},
		fakeRoles{byGateway: map[string][]*roledomain.Role{}},
		fakeCatalog{},
		nil,
	)
}

type fakeBroadcaster struct {
	mu       sync.Mutex
	versions []string
}

func (b *fakeBroadcaster) Broadcast(version string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.versions = append(b.versions, version)
}

func (b *fakeBroadcaster) broadcasted() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]string, len(b.versions))
	copy(out, b.versions)
	return out
}

type fakeOutbox struct {
	mu          sync.Mutex
	seqs        []int64
	deletes     []int64
	pruneCalls  int
	pruneKeep   int
	pruneCutoff time.Time
}

func (o *fakeOutbox) setSeqs(seqs ...int64) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.seqs = append([]int64(nil), seqs...)
}

func (o *fakeOutbox) appendSeqs(seqs ...int64) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.seqs = append(o.seqs, seqs...)
}

func (o *fakeOutbox) Pending(context.Context) ([]int64, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	return append([]int64(nil), o.seqs...), nil
}

func (o *fakeOutbox) PendingCount(context.Context) (int64, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	return int64(len(o.seqs)), nil
}

func (o *fakeOutbox) DeleteSeqs(_ context.Context, seqs []int64) (int64, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	drop := make(map[int64]struct{}, len(seqs))
	for _, s := range seqs {
		drop[s] = struct{}{}
		o.deletes = append(o.deletes, s)
	}
	kept := o.seqs[:0:0]
	for _, s := range o.seqs {
		if _, ok := drop[s]; !ok {
			kept = append(kept, s)
		}
	}
	o.seqs = kept
	return int64(len(seqs)), nil
}

func (o *fakeOutbox) PruneOlderThan(_ context.Context, cutoff time.Time, keepMax int) (int64, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.pruneCalls++
	o.pruneKeep = keepMax
	o.pruneCutoff = cutoff
	return 0, nil
}

func (o *fakeOutbox) deletedSeqs() []int64 {
	o.mu.Lock()
	defer o.mu.Unlock()
	out := make([]int64, len(o.deletes))
	copy(out, o.deletes)
	return out
}

func (o *fakeOutbox) remainingSeqs() []int64 {
	o.mu.Lock()
	defer o.mu.Unlock()
	out := make([]int64, len(o.seqs))
	copy(out, o.seqs)
	return out
}

func (o *fakeOutbox) pruneInfo() (int, int, time.Time) {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.pruneCalls, o.pruneKeep, o.pruneCutoff
}

type hookedCompiler struct {
	inner     appsnapshot.SnapshotCompiler
	onCompile func()
}

func (h hookedCompiler) Compile(ctx context.Context) (*readmodel.Snapshot, error) {
	if h.onCompile != nil {
		h.onCompile()
	}
	return h.inner.Compile(ctx)
}

type failingCompiler struct{ err error }

func (f failingCompiler) Compile(context.Context) (*readmodel.Snapshot, error) {
	return nil, f.err
}

func TestDispatch_BroadcastsOnceThenDedupsIdenticalData(t *testing.T) {
	t.Parallel()
	gwA := mustGatewayID(t, "11111111-1111-1111-1111-111111111111")
	gateways := &settableGateways{items: []*gatewaydomain.Gateway{{ID: gwA}}}
	holder := appsnapshot.NewHolder()
	broadcaster := &fakeBroadcaster{}
	outbox := &fakeOutbox{}
	outbox.setSeqs(5)
	d := appsnapshot.NewDispatcher(newDispatchCompiler(gateways), infrasnapshot.NewCodec(), holder, broadcaster, outbox, nil, appsnapshot.DispatcherConfig{})

	if err := d.Dispatch(context.Background()); err != nil {
		t.Fatalf("first dispatch: %v", err)
	}
	if err := d.Dispatch(context.Background()); err != nil {
		t.Fatalf("second dispatch: %v", err)
	}

	versions := broadcaster.broadcasted()
	if len(versions) != 1 {
		t.Fatalf("identical data must broadcast once, got %d", len(versions))
	}
	if _, held, ok := holder.Snapshot(); !ok || held != versions[0] {
		t.Fatalf("holder must hold the broadcast version, got %q ok=%v", held, ok)
	}

	deletes := outbox.deletedSeqs()
	if len(deletes) != 1 || deletes[0] != 5 {
		t.Fatalf("the first cycle must drain the observed marker 5 and the second must find nothing, got %v", deletes)
	}
}

func TestDispatch_ChangedDataBroadcastsNewVersion(t *testing.T) {
	t.Parallel()
	gwA := mustGatewayID(t, "11111111-1111-1111-1111-111111111111")
	gwB := mustGatewayID(t, "22222222-2222-2222-2222-222222222222")
	gateways := &settableGateways{items: []*gatewaydomain.Gateway{{ID: gwA}}}
	holder := appsnapshot.NewHolder()
	broadcaster := &fakeBroadcaster{}
	outbox := &fakeOutbox{}
	d := appsnapshot.NewDispatcher(newDispatchCompiler(gateways), infrasnapshot.NewCodec(), holder, broadcaster, outbox, nil, appsnapshot.DispatcherConfig{})

	if err := d.Dispatch(context.Background()); err != nil {
		t.Fatalf("first dispatch: %v", err)
	}
	gateways.set([]*gatewaydomain.Gateway{{ID: gwA}, {ID: gwB}})
	if err := d.Dispatch(context.Background()); err != nil {
		t.Fatalf("second dispatch: %v", err)
	}

	versions := broadcaster.broadcasted()
	if len(versions) != 2 {
		t.Fatalf("a config change must broadcast a new version, got %d", len(versions))
	}
	if versions[0] == versions[1] {
		t.Fatalf("changed data must produce a distinct version, got %v", versions)
	}
}

func TestDispatch_DrainsPreCompileFrontierSoMidCycleMarkerSurvives(t *testing.T) {
	t.Parallel()
	gwA := mustGatewayID(t, "11111111-1111-1111-1111-111111111111")
	gateways := &settableGateways{items: []*gatewaydomain.Gateway{{ID: gwA}}}
	holder := appsnapshot.NewHolder()
	broadcaster := &fakeBroadcaster{}
	outbox := &fakeOutbox{}
	outbox.setSeqs(1, 2, 3)
	compiler := hookedCompiler{inner: newDispatchCompiler(gateways), onCompile: func() { outbox.appendSeqs(4, 5) }}
	d := appsnapshot.NewDispatcher(compiler, infrasnapshot.NewCodec(), holder, broadcaster, outbox, nil, appsnapshot.DispatcherConfig{})

	if err := d.Dispatch(context.Background()); err != nil {
		t.Fatalf("dispatch: %v", err)
	}

	deletes := outbox.deletedSeqs()
	if len(deletes) != 3 || deletes[0] != 1 || deletes[1] != 2 || deletes[2] != 3 {
		t.Fatalf("drain must delete only the set observed before compile, got %v", deletes)
	}
	if remaining := outbox.remainingSeqs(); len(remaining) != 2 || remaining[0] != 4 || remaining[1] != 5 {
		t.Fatalf("markers that appear mid-compile must survive to the next cycle, got %v", remaining)
	}
}

func TestDispatch_DrainKeepsLowerSeqCommittedAfterObserve(t *testing.T) {
	t.Parallel()
	gwA := mustGatewayID(t, "11111111-1111-1111-1111-111111111111")
	gateways := &settableGateways{items: []*gatewaydomain.Gateway{{ID: gwA}}}
	holder := appsnapshot.NewHolder()
	broadcaster := &fakeBroadcaster{}
	outbox := &fakeOutbox{}
	// A higher seq (101) is visible before compile; a lower seq (100) becomes visible
	// only after Pending is observed, modelling BIGSERIAL assigned at INSERT while its
	// transaction commits after a higher seq. A range delete up to 101 would drop 100.
	outbox.setSeqs(101)
	compiler := hookedCompiler{inner: newDispatchCompiler(gateways), onCompile: func() { outbox.appendSeqs(100) }}
	d := appsnapshot.NewDispatcher(compiler, infrasnapshot.NewCodec(), holder, broadcaster, outbox, nil, appsnapshot.DispatcherConfig{})

	if err := d.Dispatch(context.Background()); err != nil {
		t.Fatalf("dispatch: %v", err)
	}

	if deletes := outbox.deletedSeqs(); len(deletes) != 1 || deletes[0] != 101 {
		t.Fatalf("drain must delete only the observed seq 101, got %v", deletes)
	}
	if remaining := outbox.remainingSeqs(); len(remaining) != 1 || remaining[0] != 100 {
		t.Fatalf("a lower seq committing after the observe must survive the drain, got %v", remaining)
	}
}

func TestDispatch_PrunesUnderSafetyBound(t *testing.T) {
	t.Parallel()
	gwA := mustGatewayID(t, "11111111-1111-1111-1111-111111111111")
	gateways := &settableGateways{items: []*gatewaydomain.Gateway{{ID: gwA}}}
	holder := appsnapshot.NewHolder()
	broadcaster := &fakeBroadcaster{}
	outbox := &fakeOutbox{}
	retention := 90 * time.Minute
	before := time.Now().Add(-retention)
	d := appsnapshot.NewDispatcher(newDispatchCompiler(gateways), infrasnapshot.NewCodec(), holder, broadcaster, outbox, nil,
		appsnapshot.DispatcherConfig{Retention: retention, MaxRows: 42})

	if err := d.Dispatch(context.Background()); err != nil {
		t.Fatalf("dispatch: %v", err)
	}

	calls, keepMax, cutoff := outbox.pruneInfo()
	if calls != 1 || keepMax != 42 {
		t.Fatalf("prune must run once with the configured row bound, calls=%d keepMax=%d", calls, keepMax)
	}
	if cutoff.Sub(before) > time.Minute || before.Sub(cutoff) > time.Minute {
		t.Fatalf("prune cutoff must track the retention window, got %s want ~%s", cutoff, before)
	}
}

func TestDispatch_PrunesEvenWhenCompileFails(t *testing.T) {
	t.Parallel()
	holder := appsnapshot.NewHolder()
	broadcaster := &fakeBroadcaster{}
	outbox := &fakeOutbox{}
	d := appsnapshot.NewDispatcher(failingCompiler{err: errCompile}, infrasnapshot.NewCodec(), holder, broadcaster, outbox, nil,
		appsnapshot.DispatcherConfig{Retention: time.Hour, MaxRows: 7})

	if err := d.Dispatch(context.Background()); err == nil {
		t.Fatal("dispatch must surface the compile failure")
	}

	calls, keepMax, _ := outbox.pruneInfo()
	if calls != 1 || keepMax != 7 {
		t.Fatalf("prune must run on every cycle so a compile outage cannot grow the outbox unbounded, calls=%d keepMax=%d", calls, keepMax)
	}
	if len(broadcaster.broadcasted()) != 0 {
		t.Fatal("a failed compile must not broadcast a version")
	}
}

func TestRun_BootWithPendingMarkersTriggersDispatch(t *testing.T) {
	t.Parallel()
	gwA := mustGatewayID(t, "11111111-1111-1111-1111-111111111111")
	gateways := &settableGateways{items: []*gatewaydomain.Gateway{{ID: gwA}}}
	holder := appsnapshot.NewHolder()
	broadcaster := &fakeBroadcaster{}
	outbox := &fakeOutbox{}
	outbox.setSeqs(1)
	d := appsnapshot.NewDispatcher(newDispatchCompiler(gateways), infrasnapshot.NewCodec(), holder, broadcaster, outbox, nil,
		appsnapshot.DispatcherConfig{Debounce: 20 * time.Millisecond, Backstop: time.Hour})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		_ = d.Run(ctx)
		close(done)
	}()

	waitFor(t, func() bool { return len(broadcaster.broadcasted()) == 1 }, 2*time.Second)

	cancel()
	<-done
}

func TestRun_DebounceCoalescesBurst(t *testing.T) {
	t.Parallel()
	gwA := mustGatewayID(t, "11111111-1111-1111-1111-111111111111")
	gateways := &settableGateways{items: []*gatewaydomain.Gateway{{ID: gwA}}}
	holder := appsnapshot.NewHolder()
	broadcaster := &fakeBroadcaster{}
	outbox := &fakeOutbox{}
	d := appsnapshot.NewDispatcher(newDispatchCompiler(gateways), infrasnapshot.NewCodec(), holder, broadcaster, outbox, nil,
		appsnapshot.DispatcherConfig{Debounce: 40 * time.Millisecond, Backstop: time.Hour})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		_ = d.Run(ctx)
		close(done)
	}()

	for i := 0; i < 6; i++ {
		d.Signal()
	}

	time.Sleep(200 * time.Millisecond)
	cancel()
	<-done

	if len(broadcaster.broadcasted()) != 1 {
		t.Fatalf("a coalesced burst must broadcast once, got %d", len(broadcaster.broadcasted()))
	}
}

func TestRun_ConcurrentSignalAndBackstopStayRaceFree(t *testing.T) {
	t.Parallel()
	gwA := mustGatewayID(t, "11111111-1111-1111-1111-111111111111")
	gateways := &settableGateways{items: []*gatewaydomain.Gateway{{ID: gwA}}}
	holder := appsnapshot.NewHolder()
	broadcaster := &fakeBroadcaster{}
	outbox := &fakeOutbox{}
	d := appsnapshot.NewDispatcher(newDispatchCompiler(gateways), infrasnapshot.NewCodec(), holder, broadcaster, outbox, nil,
		appsnapshot.DispatcherConfig{Debounce: 5 * time.Millisecond, Backstop: 5 * time.Millisecond})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		_ = d.Run(ctx)
		close(done)
	}()

	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				d.Signal()
				time.Sleep(time.Millisecond)
			}
		}()
	}
	wg.Wait()

	cancel()
	<-done

	if _, _, ok := holder.Snapshot(); !ok {
		t.Fatal("the dispatcher must have held a snapshot after concurrent signals")
	}
}

func waitFor(t *testing.T, cond func() bool, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("condition not met within %s", timeout)
}
