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
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	appsnapshot "github.com/NeuralTrust/TrustGate/pkg/app/configsnapshot"
	"github.com/NeuralTrust/TrustGate/pkg/app/configsyncport"
	authdomain "github.com/NeuralTrust/TrustGate/pkg/domain/auth"
	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	gatewaydomain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	policydomain "github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	ratelimitdomain "github.com/NeuralTrust/TrustGate/pkg/domain/ratelimit"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	"github.com/NeuralTrust/TrustGate/pkg/domain/sessionrevocation"
	infrasnapshot "github.com/NeuralTrust/TrustGate/pkg/infra/configsnapshot"
	"github.com/NeuralTrust/TrustGate/pkg/runtimeconfig/snapshot/readmodel"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/attribute"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

// findingGateways adds FindByID to settableGateways, the lookup the
// incremental path uses for one dirty gateway. onFind, when set, runs once on
// the next lookup, to land a write while a compile is reading.
type findingGateways struct {
	*settableGateways
	hookMu sync.Mutex
	onFind func()
}

func (g *findingGateways) FindByID(_ context.Context, id ids.GatewayID) (*gatewaydomain.Gateway, error) {
	g.hookMu.Lock()
	hook := g.onFind
	g.onFind = nil
	g.hookMu.Unlock()
	if hook != nil {
		hook()
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	for _, gw := range g.items {
		if gw.ID == id {
			copied := *gw
			return &copied, nil
		}
	}
	return nil, gatewaydomain.ErrNotFound
}

type mutableCaps struct {
	caps []ratelimitdomain.TenantCaps
	// perRead, when set, answers every read with a fresh value, as a plan
	// change landing between two reads would.
	perRead func(read int) []ratelimitdomain.TenantCaps
	reads   int
}

func (m *mutableCaps) ListTenantCaps(context.Context) ([]ratelimitdomain.TenantCaps, error) {
	if m.perRead != nil {
		m.reads++
		return m.perRead(m.reads), nil
	}
	return m.caps, nil
}

type world struct {
	t           testing.TB
	rng         *rand.Rand
	gateways    *findingGateways
	consumers   map[string][]*consumerdomain.Consumer
	registries  map[string][]*registrydomain.Registry
	policies    map[string][]*policydomain.Policy
	auths       map[string][]*authdomain.Auth
	caps        *mutableCaps
	revocations *revocationsReader
	catalog     *mutableCatalog
	outboxes    []*fakeOutbox
	seq         int64
	serial      int
	everSeen    map[string]struct{}
}

func newWorld(t testing.TB, seed uint64) *world {
	w := &world{
		t:           t,
		rng:         rand.New(rand.NewPCG(seed, seed^0x9e3779b97f4a7c15)),
		gateways:    &findingGateways{settableGateways: &settableGateways{}},
		consumers:   map[string][]*consumerdomain.Consumer{},
		registries:  map[string][]*registrydomain.Registry{},
		policies:    map[string][]*policydomain.Policy{},
		auths:       map[string][]*authdomain.Auth{},
		caps:        &mutableCaps{},
		revocations: &revocationsReader{},
		catalog:     &mutableCatalog{catalog: sharedCatalogFixture(3)},
		everSeen:    map[string]struct{}{},
	}
	return w
}

func (w *world) compiler() *appsnapshot.Compiler {
	return appsnapshot.NewCompiler(
		w.gateways,
		fakeConsumers{byGateway: w.consumers},
		fakeRegistries{byGateway: w.registries},
		fakePolicies{byGateway: w.policies},
		fakeAuths{byGateway: w.auths},
		w.catalog,
		nil,
		appsnapshot.WithTenantCaps(w.caps),
		appsnapshot.WithSessionRevocations(w.revocations, time.Hour),
		appsnapshot.WithPlaygroundTokenKeys([]readmodel.VerificationKey{{KID: "k1", PEM: "a"}}),
		appsnapshot.WithUsageEnforcement(true),
	)
}

func (w *world) dispatcher(incremental bool, logs *bytes.Buffer, cfg appsnapshot.DispatcherConfig) (*appsnapshot.Dispatcher, *appsnapshot.Holder) {
	outbox := &fakeOutbox{}
	w.outboxes = append(w.outboxes, outbox)
	holder := appsnapshot.NewHolder()
	compiler := w.compiler()
	var opts []appsnapshot.DispatcherOption
	if incremental {
		opts = append(opts, appsnapshot.WithIncrementalCompile(infrasnapshot.NewFragments(), compiler))
	}
	if logs == nil {
		logs = &bytes.Buffer{}
	}
	d := appsnapshot.NewDispatcher(compiler, infrasnapshot.NewCodec(), holder, &fakeBroadcaster{}, outbox,
		slog.New(slog.NewTextHandler(logs, nil)), cfg, opts...)
	return d, holder
}

func (w *world) newID() uuid.UUID {
	var u uuid.UUID
	for i := range u {
		u[i] = byte(w.rng.UintN(256))
	}
	u[6] = (u[6] & 0x0f) | 0x40
	u[8] = (u[8] & 0x3f) | 0x80
	return u
}

func (w *world) mark(markers ...configsyncport.Marker) {
	for i := range markers {
		w.seq++
		markers[i].Seq = w.seq
	}
	for _, outbox := range w.outboxes {
		outbox.appendMarkers(markers...)
	}
}

func (w *world) markGateway(id ids.GatewayID) {
	w.mark(configsyncport.Marker{Kind: configsyncport.MarkerGateway, GatewayID: id})
}

func (w *world) gatewayList() []*gatewaydomain.Gateway {
	w.gateways.mu.Lock()
	defer w.gateways.mu.Unlock()
	return slices.Clone(w.gateways.items)
}

func (w *world) setGateways(items []*gatewaydomain.Gateway) {
	w.gateways.set(items)
}

func (w *world) pickGateway() (*gatewaydomain.Gateway, bool) {
	items := w.gatewayList()
	if len(items) == 0 {
		return nil, false
	}
	return items[w.rng.IntN(len(items))], true
}

func (w *world) planes() []string {
	return []string{"", gatewaydomain.DataPlaneHybrid, gatewaydomain.DataPlaneDedicated}
}

func (w *world) addGateway() ids.GatewayID {
	w.serial++
	id := ids.From[ids.GatewayKind](w.newID())
	gw := gatewayWithTeam(id, fmt.Sprintf("team-%d", w.rng.IntN(3)))
	gw.Slug = fmt.Sprintf("gw-%d", w.serial)
	gw.Entitlements.DataPlane = w.planes()[w.rng.IntN(3)]
	w.setGateways(append(w.gatewayList(), gw))
	w.everSeen[id.String()] = struct{}{}
	return id
}

func (w *world) updateGateway(id ids.GatewayID, change func(*gatewaydomain.Gateway)) {
	items := w.gatewayList()
	for i, gw := range items {
		if gw.ID == id {
			copied := *gw
			copied.Entitlements = gw.Entitlements
			change(&copied)
			items[i] = &copied
		}
	}
	w.setGateways(items)
}

func (w *world) deleteGateway(id ids.GatewayID) {
	items := w.gatewayList()
	items = slices.DeleteFunc(items, func(gw *gatewaydomain.Gateway) bool { return gw.ID == id })
	w.setGateways(items)
	key := id.String()
	delete(w.consumers, key)
	delete(w.registries, key)
	delete(w.policies, key)
	delete(w.auths, key)
}

func (w *world) step() string {
	gw, ok := w.pickGateway()
	op := w.rng.IntN(14)
	if !ok || op == 0 {
		w.markGateway(w.addGateway())
		return "add gateway"
	}
	key := gw.ID.String()
	switch op {
	case 1:
		if len(w.gatewayList()) > 1 {
			w.deleteGateway(gw.ID)
			w.markGateway(gw.ID)
			return "delete gateway"
		}
		w.markGateway(w.addGateway())
		return "add gateway"
	case 2:
		next := w.planes()[w.rng.IntN(3)]
		w.updateGateway(gw.ID, func(g *gatewaydomain.Gateway) { g.Entitlements.DataPlane = next })
		w.markGateway(gw.ID)
		return "flip data plane to " + next
	case 3:
		w.serial++
		slug := fmt.Sprintf("renamed-%d", w.serial)
		w.updateGateway(gw.ID, func(g *gatewaydomain.Gateway) { g.Slug = slug })
		w.markGateway(gw.ID)
		return "rename gateway"
	case 4:
		w.serial++
		c := &consumerdomain.Consumer{ID: ids.From[ids.ConsumerKind](w.newID()), GatewayID: gw.ID, Slug: fmt.Sprintf("c-%d", w.serial)}
		if regs := w.registries[key]; len(regs) > 0 && w.rng.IntN(2) == 0 {
			c.RegistryIDs = []ids.RegistryID{regs[w.rng.IntN(len(regs))].ID}
		}
		w.consumers[key] = append(w.consumers[key], c)
		w.markGateway(gw.ID)
		return "add consumer"
	case 5:
		if n := len(w.consumers[key]); n > 0 {
			i := w.rng.IntN(n)
			w.consumers[key] = slices.Delete(slices.Clone(w.consumers[key]), i, i+1)
		}
		w.markGateway(gw.ID)
		return "remove consumer"
	case 6:
		w.serial++
		w.registries[key] = append(w.registries[key], &registrydomain.Registry{ID: ids.From[ids.RegistryKind](w.newID()), GatewayID: gw.ID, Name: fmt.Sprintf("r-%d", w.serial), Enabled: true})
		w.markGateway(gw.ID)
		return "add registry"
	case 7:
		if n := len(w.registries[key]); n > 0 {
			i := w.rng.IntN(n)
			w.registries[key] = slices.Delete(slices.Clone(w.registries[key]), i, i+1)
		}
		w.markGateway(gw.ID)
		return "remove registry"
	case 8:
		w.serial++
		a := &authdomain.Auth{ID: ids.From[ids.AuthKind](w.newID()), GatewayID: gw.ID, Name: fmt.Sprintf("a-%d", w.serial)}
		if w.rng.IntN(2) == 0 {
			a.KeyHash = fmt.Sprintf("hash-%d", w.serial)
		}
		w.auths[key] = append(w.auths[key], a)
		w.markGateway(gw.ID)
		return "add auth"
	case 9:
		w.serial++
		w.policies[key] = append(w.policies[key], &policydomain.Policy{ID: ids.From[ids.PolicyKind](w.newID()), GatewayID: gw.ID, Name: fmt.Sprintf("p-%d", w.serial)})
		w.markGateway(gw.ID)
		return "add policy"
	case 10:
		w.catalog.catalog = sharedCatalogFixture(1 + w.rng.IntN(6))
		w.mark(configsyncport.Marker{Kind: configsyncport.MarkerCatalog})
		return "catalog change"
	case 11:
		team := gw.TenantID()
		w.caps.caps = []ratelimitdomain.TenantCaps{{TenantID: team, Tier: "pro", BurstPerMin: 1 + w.rng.IntN(100)}}
		return "tenant caps change, no marker"
	case 12:
		w.serial++
		w.revocations.rows = append(w.revocations.rows, sessionrevocation.Record{
			GatewayID: key, Org: "org", Subject: fmt.Sprintf("s-%d", w.serial), RevokedAt: time.Now().Add(-time.Minute).UTC(),
		})
		w.markGateway(gw.ID)
		return "session revocation"
	default:
		w.serial++
		slug := fmt.Sprintf("all-%d", w.serial)
		w.updateGateway(gw.ID, func(g *gatewaydomain.Gateway) { g.Slug = slug })
		w.mark(configsyncport.Marker{Kind: configsyncport.MarkerAll})
		return "write marked all"
	}
}

func (w *world) requireSameServed(t *testing.T, label string, incremental, full *appsnapshot.Holder) {
	t.Helper()
	codec := infrasnapshot.NewCodec()
	gotRaw, gotVersion, gotOK := incremental.Snapshot()
	wantRaw, wantVersion, wantOK := full.Snapshot()
	require.Equal(t, wantOK, gotOK, "%s: global presence", label)
	require.True(t, bytes.Equal(wantRaw, gotRaw), "%s: global bytes differ", label)
	require.Equal(t, wantVersion, gotVersion, "%s: global version", label)
	require.Equal(t, codec.Version(gotRaw), gotVersion, "%s: global version is not the hash of its bytes", label)
	for scope := range w.everSeen {
		gotRaw, gotVersion, gotOK := incremental.SnapshotFor(scope)
		wantRaw, wantVersion, wantOK := full.SnapshotFor(scope)
		require.Equal(t, wantOK, gotOK, "%s: scope %s presence", label, scope)
		require.True(t, bytes.Equal(wantRaw, gotRaw), "%s: scope %s bytes differ", label, scope)
		require.Equal(t, wantVersion, gotVersion, "%s: scope %s version", label, scope)
	}
}

func TestIncrementalCompileMatchesFullCompileOverMutationSequences(t *testing.T) {
	for _, seed := range []uint64{1, 7, 42, 2026, 31337} {
		t.Run(fmt.Sprintf("seed=%d", seed), func(t *testing.T) {
			w := newWorld(t, seed)
			for range 4 {
				w.addGateway()
			}
			var logs bytes.Buffer
			inc, incHolder := w.dispatcher(true, &logs, appsnapshot.DispatcherConfig{})
			full, fullHolder := w.dispatcher(false, nil, appsnapshot.DispatcherConfig{})
			ctx := context.Background()
			require.NoError(t, inc.Dispatch(ctx))
			require.NoError(t, full.Dispatch(ctx))
			w.requireSameServed(t, "boot", incHolder, fullHolder)

			incrementalCycles := 0
			for i := range 60 {
				label := fmt.Sprintf("step %d (%s)", i, w.step())
				logs.Reset()
				require.NoError(t, inc.Dispatch(ctx), label)
				require.NoError(t, full.Dispatch(ctx), label)
				w.requireSameServed(t, label, incHolder, fullHolder)
				if strings.Contains(logs.String(), "mode=incremental") {
					incrementalCycles++
				}
			}
			require.Positive(t, incrementalCycles, "the sequence must exercise incremental cycles")
		})
	}
}

func TestIncrementalCompilePicksUpAWriteThatLandsMidCompile(t *testing.T) {
	w := newWorld(t, 99)
	first := w.addGateway()
	second := w.addGateway()
	inc, incHolder := w.dispatcher(true, nil, appsnapshot.DispatcherConfig{})
	full, fullHolder := w.dispatcher(false, nil, appsnapshot.DispatcherConfig{})
	ctx := context.Background()
	require.NoError(t, inc.Dispatch(ctx))
	require.NoError(t, full.Dispatch(ctx))

	w.updateGateway(first, func(g *gatewaydomain.Gateway) { g.Slug = "first-renamed" })
	w.markGateway(first)
	w.gateways.hookMu.Lock()
	w.gateways.onFind = func() {
		w.updateGateway(second, func(g *gatewaydomain.Gateway) { g.Slug = "second-renamed-mid-compile" })
		w.markGateway(second)
	}
	w.gateways.hookMu.Unlock()
	require.NoError(t, inc.Dispatch(ctx))
	require.NoError(t, inc.Dispatch(ctx))
	require.NoError(t, full.Dispatch(ctx))
	w.requireSameServed(t, "after a mid-compile write", incHolder, fullHolder)
}

func driftCounts(t *testing.T, reader *sdkmetric.ManualReader) map[string]int64 {
	t.Helper()
	var rm metricdata.ResourceMetrics
	require.NoError(t, reader.Collect(context.Background(), &rm))
	out := map[string]int64{}
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name != "trustgate.configsnapshot.drift" {
				continue
			}
			sum, ok := m.Data.(metricdata.Sum[int64])
			require.True(t, ok)
			for _, p := range sum.DataPoints {
				out[p.Attributes.Encoded(attribute.DefaultEncoder())] = p.Value
			}
		}
	}
	return out
}

func TestBackstopCountsDriftAndPublishesTheFullCompile(t *testing.T) {
	reader := installMeter(t, "")
	w := newWorld(t, 5)
	hosted := w.addGateway()
	w.updateGateway(hosted, func(g *gatewaydomain.Gateway) { g.Entitlements.DataPlane = "" })
	w.addGateway()
	inc, incHolder := w.dispatcher(true, nil, appsnapshot.DispatcherConfig{Backstop: 30 * time.Millisecond})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- inc.Run(ctx) }()
	waitFor(t, func() bool { _, _, ok := incHolder.Snapshot(); return ok }, 2*time.Second)
	_, before, _ := incHolder.Snapshot()

	// A write no marker names: only the backstop's full compile can see it.
	w.updateGateway(hosted, func(g *gatewaydomain.Gateway) { g.Slug = "renamed-without-marker" })

	waitFor(t, func() bool { return driftCounts(t, reader)["scope_kind=global"] > 0 }, 2*time.Second)
	waitFor(t, func() bool { _, v, _ := incHolder.Snapshot(); return v != before }, 2*time.Second)
	cancel()
	<-done

	full, fullHolder := w.dispatcher(false, nil, appsnapshot.DispatcherConfig{})
	require.NoError(t, full.Dispatch(context.Background()))
	w.requireSameServed(t, "after the backstop", incHolder, fullHolder)
	counts := driftCounts(t, reader)
	require.Positive(t, counts["scope_kind=scoped"], "the hosted gateway's own scope drifted too")
}

func TestBackstopCountsNoDriftWhenOnlyTheSharedInputsMoveBetweenReads(t *testing.T) {
	reader := installMeter(t, "")
	w := newWorld(t, 7)
	for range 3 {
		id := w.addGateway()
		w.updateGateway(id, func(g *gatewaydomain.Gateway) { g.Entitlements.DataPlane = "" })
	}
	d, _ := w.dispatcher(true, nil, appsnapshot.DispatcherConfig{})
	ctx := context.Background()
	require.NoError(t, d.Dispatch(ctx))

	w.caps.perRead = func(read int) []ratelimitdomain.TenantCaps {
		var caps []ratelimitdomain.TenantCaps
		for team := range 3 {
			caps = append(caps, ratelimitdomain.TenantCaps{TenantID: fmt.Sprintf("team-%d", team), Tier: "pro", BurstPerMin: read})
		}
		return caps
	}
	for range 3 {
		require.NoError(t, d.DispatchBackstop(ctx))
	}

	require.Positive(t, w.caps.reads, "the backstops read the tenant caps")
	require.Empty(t, driftCounts(t, reader), "caps that change between reads are one input to both compiles, not drift")
}

func TestBackstopCountsNoDriftForALateMarkerCommittedDuringTheComparison(t *testing.T) {
	reader := installMeter(t, "")
	w := newWorld(t, 9)
	dirtyID := w.addGateway()
	otherID := w.addGateway()
	for _, id := range []ids.GatewayID{dirtyID, otherID} {
		w.updateGateway(id, func(g *gatewaydomain.Gateway) { g.Entitlements.DataPlane = "" })
	}
	d, _ := w.dispatcher(true, nil, appsnapshot.DispatcherConfig{GapExpiry: time.Millisecond})
	ctx := context.Background()
	require.NoError(t, d.Dispatch(ctx))
	w.markGateway(dirtyID)
	require.NoError(t, d.Dispatch(ctx), "the cursor starts reading the outbox")

	w.seq++
	lateSeq := w.seq
	w.markGateway(dirtyID)
	require.NoError(t, d.Dispatch(ctx))
	time.Sleep(5 * time.Millisecond)
	require.NoError(t, d.Dispatch(ctx), "the missing seq expires into the late set")

	w.markGateway(dirtyID)
	w.gateways.hookMu.Lock()
	w.gateways.onFind = func() {
		w.updateGateway(otherID, func(g *gatewaydomain.Gateway) { g.Slug = "renamed-by-a-slow-write" })
		for _, outbox := range w.outboxes {
			outbox.appendMarkers(configsyncport.Marker{Seq: lateSeq, Kind: configsyncport.MarkerGateway, GatewayID: otherID})
		}
	}
	w.gateways.hookMu.Unlock()
	require.NoError(t, d.DispatchBackstop(ctx))

	require.Empty(t, driftCounts(t, reader), "a late marker committed between the two compiles is a write in flight, not drift")
}

func TestIncrementalCompileIsOffByDefault(t *testing.T) {
	w := newWorld(t, 3)
	w.addGateway()
	var logs bytes.Buffer
	d, _ := w.dispatcher(false, &logs, appsnapshot.DispatcherConfig{})
	ctx := context.Background()
	require.NoError(t, d.Dispatch(ctx))
	gw, _ := w.pickGateway()
	w.updateGateway(gw.ID, func(g *gatewaydomain.Gateway) { g.Slug = "renamed" })
	w.markGateway(gw.ID)
	logs.Reset()
	require.NoError(t, d.Dispatch(ctx))
	require.Contains(t, logs.String(), "mode=full reason=switch_off dirty=1")
}

func benchmarkWorld(b *testing.B) *world {
	b.Helper()
	w := newWorld(b, 11)
	w.catalog.catalog = sharedCatalogFixture(3000)
	for range 600 {
		id := w.addGateway()
		key := id.String()
		for j := range 3 {
			w.consumers[key] = append(w.consumers[key], &consumerdomain.Consumer{ID: ids.From[ids.ConsumerKind](w.newID()), GatewayID: id, Slug: fmt.Sprintf("%s-c%d", key, j)})
		}
		w.auths[key] = append(w.auths[key], &authdomain.Auth{ID: ids.From[ids.AuthKind](w.newID()), GatewayID: id, Name: "key", KeyHash: "h"})
	}
	return w
}

func BenchmarkDispatchIncrementalOneDirtyGateway(b *testing.B) {
	w := benchmarkWorld(b)
	d, _ := w.dispatcher(true, nil, appsnapshot.DispatcherConfig{})
	ctx := context.Background()
	if err := d.Dispatch(ctx); err != nil {
		b.Fatal(err)
	}
	items := w.gatewayList()
	b.ReportAllocs()
	b.ResetTimer()
	i := 0
	for b.Loop() {
		gw := items[i%len(items)]
		i++
		w.serial++
		slug := fmt.Sprintf("bench-%d", w.serial)
		w.updateGateway(gw.ID, func(g *gatewaydomain.Gateway) { g.Slug = slug })
		w.markGateway(gw.ID)
		if err := d.Dispatch(ctx); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDispatchFullCompileManyGateways(b *testing.B) {
	w := benchmarkWorld(b)
	d, _ := w.dispatcher(false, nil, appsnapshot.DispatcherConfig{})
	ctx := context.Background()
	if err := d.Dispatch(ctx); err != nil {
		b.Fatal(err)
	}
	items := w.gatewayList()
	b.ReportAllocs()
	b.ResetTimer()
	i := 0
	for b.Loop() {
		gw := items[i%len(items)]
		i++
		w.serial++
		slug := fmt.Sprintf("bench-%d", w.serial)
		w.updateGateway(gw.ID, func(g *gatewaydomain.Gateway) { g.Slug = slug })
		w.markGateway(gw.ID)
		if err := d.Dispatch(ctx); err != nil {
			b.Fatal(err)
		}
	}
}
