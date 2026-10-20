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
	"sync/atomic"
	"testing"
	"time"

	appsnapshot "github.com/NeuralTrust/TrustGate/pkg/app/configsnapshot"
	authdomain "github.com/NeuralTrust/TrustGate/pkg/domain/auth"
	catalogdomain "github.com/NeuralTrust/TrustGate/pkg/domain/catalog"
	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	gatewaydomain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	policydomain "github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	sessionrevocation "github.com/NeuralTrust/TrustGate/pkg/domain/sessionrevocation"
	infrasnapshot "github.com/NeuralTrust/TrustGate/pkg/infra/configsnapshot"
	"github.com/NeuralTrust/TrustGate/pkg/runtimeconfig/snapshot/readmodel"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

type revocationsReader struct {
	rows  []sessionrevocation.Record
	err   error
	since time.Time
	calls int
}

func (r *revocationsReader) Upsert(context.Context, string, string, string, time.Time) error {
	return nil
}

func (r *revocationsReader) ListActive(_ context.Context, since time.Time) ([]sessionrevocation.Record, error) {
	r.calls++
	r.since = since
	if r.err != nil {
		return nil, r.err
	}
	return r.rows, nil
}

type flakyRevocations struct {
	inner revocationsReader
	fail  atomic.Bool
}

func (f *flakyRevocations) Upsert(context.Context, string, string, string, time.Time) error {
	return nil
}

func (f *flakyRevocations) ListActive(ctx context.Context, since time.Time) ([]sessionrevocation.Record, error) {
	if f.fail.Load() {
		f.inner.calls++
		return nil, errors.New("db down")
	}
	return f.inner.ListActive(ctx, since)
}

func compilerWithRevocations(t *testing.T, reader sessionrevocation.Store, maxAge time.Duration) *appsnapshot.Compiler {
	t.Helper()
	acme := mustGatewayID(t, capsAcme)
	globex := mustGatewayID(t, capsGlobex)
	globexGW := gatewayWithTeam(globex, "globex")
	globexGW.Entitlements.DataPlane = gatewaydomain.DataPlaneHybrid
	return appsnapshot.NewCompiler(
		fakeGateways{items: []*gatewaydomain.Gateway{
			gatewayWithTeam(acme, "acme"),
			globexGW,
		}},
		fakeConsumers{byGateway: map[string][]*consumerdomain.Consumer{
			acme.String():   {{ID: mustConsumerID(t, "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"), GatewayID: acme}},
			globex.String(): {{ID: mustConsumerID(t, "cccccccc-cccc-cccc-cccc-cccccccccccc"), GatewayID: globex}},
		}},
		fakeRegistries{byGateway: map[string][]*registrydomain.Registry{}},
		fakePolicies{byGateway: map[string][]*policydomain.Policy{}},
		fakeAuths{byGateway: map[string][]*authdomain.Auth{}},
		fakeCatalog{providers: []catalogdomain.Provider{{Code: "openai"}}},
		nil,
		appsnapshot.WithSessionRevocations(reader, maxAge),
	)
}

func revocationRows(now time.Time) []sessionrevocation.Record {
	return []sessionrevocation.Record{
		{GatewayID: capsAcme, Org: "acme", Subject: "user-1", RevokedAt: now.Add(-time.Hour)},
		{GatewayID: capsAcme, Org: "acme", Subject: "old", RevokedAt: now.Add(-40 * 24 * time.Hour)},
		{GatewayID: capsGlobex, Org: "globex", Subject: "user-2", RevokedAt: now.Add(-time.Minute)},
	}
}

func subjects(rows []readmodel.SessionRevocation) []string {
	out := make([]string, 0, len(rows))
	for _, row := range rows {
		out = append(out, row.Subject)
	}
	return out
}

func TestCompilePutsActiveSessionRevocationsOnTheGatewayScope(t *testing.T) {
	t.Parallel()
	now := time.Now()
	reader := &revocationsReader{rows: revocationRows(now)}
	global, scoped, catalog, err := compilerWithRevocations(t, reader, 0).CompileAll(context.Background())
	require.NoError(t, err)

	assert.Empty(t, catalog.Data().SessionRevocations, "the catalog snapshot does not carry revocations")
	assert.Equal(t, []string{"user-1"}, subjects(global.Data().SessionRevocations), "the global snapshot keeps the hosted gateway and drops the hybrid one and the expired row")
	assert.Equal(t, []string{"user-1"}, subjects(scoped[capsAcme].Data().SessionRevocations))
	assert.Equal(t, []string{"user-2"}, subjects(scoped[capsGlobex].Data().SessionRevocations), "the hybrid gateway's marker travels only in its scoped snapshot")

	wantSince := now.Add(-30 * 24 * time.Hour)
	assert.WithinDuration(t, wantSince, reader.since, 2*time.Second)

	at, ok := scoped[capsGlobex].SessionRevokedAt(capsGlobex, "globex", "user-2")
	require.True(t, ok)
	assert.WithinDuration(t, now.Add(-time.Minute), at, time.Second)
	_, ok = scoped[capsAcme].SessionRevokedAt(capsGlobex, "globex", "user-2")
	assert.False(t, ok)
}

func TestCompileSessionRevocationWindowFollowsTheSessionCap(t *testing.T) {
	t.Parallel()
	now := time.Now()
	reader := &revocationsReader{rows: revocationRows(now)}
	_, scoped, _, err := compilerWithRevocations(t, reader, 90*24*time.Hour).CompileAll(context.Background())
	require.NoError(t, err)

	assert.Equal(t, []string{"old", "user-1"}, subjects(scoped[capsAcme].Data().SessionRevocations))
	assert.WithinDuration(t, now.Add(-90*24*time.Hour), reader.since, 2*time.Second)
}

func TestCompileReusesTheLastSessionRevocationsWhenTheNextReadFails(t *testing.T) {
	t.Parallel()
	reader := &flakyRevocations{inner: revocationsReader{rows: revocationRows(time.Now())}}
	c := compilerWithRevocations(t, reader, 0)

	first, err := c.CompileFor(context.Background(), capsAcme)
	require.NoError(t, err)
	require.Equal(t, []string{"user-1"}, subjects(first.Data().SessionRevocations))

	reader.fail.Store(true)
	again, err := c.CompileFor(context.Background(), capsAcme)
	require.NoError(t, err)
	assert.Equal(t, []string{"user-1"}, subjects(again.Data().SessionRevocations), "a failed read must not publish a snapshot that drops the marker")
}

func TestCompileWithoutSessionRevocationsLeavesTheSnapshotWithoutThem(t *testing.T) {
	t.Parallel()
	snap, err := twoTenantCompiler(t,
		mustGatewayID(t, capsAcme), mustGatewayID(t, capsGlobex),
		mustConsumerID(t, "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"), mustConsumerID(t, "cccccccc-cccc-cccc-cccc-cccccccccccc"),
	).CompileFor(context.Background(), capsAcme)
	require.NoError(t, err)
	assert.Empty(t, snap.Data().SessionRevocations)
	_, ok := snap.SessionRevokedAt(capsAcme, "acme", "user-1")
	assert.False(t, ok)
}

func TestCompileSessionRevocationReadErrorWithoutSeedFails(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	prev := otel.GetMeterProvider()
	otel.SetMeterProvider(mp)
	t.Cleanup(func() { otel.SetMeterProvider(prev); _ = mp.Shutdown(context.Background()) })

	readErr := errors.New("db down")
	c := compilerWithRevocations(t, &revocationsReader{err: readErr}, 0)

	snap, err := c.CompileFor(context.Background(), capsAcme)
	require.ErrorIs(t, err, readErr)
	assert.Nil(t, snap)

	global, scoped, catalog, err := c.CompileAll(context.Background())
	require.ErrorIs(t, err, readErr)
	assert.Nil(t, global)
	assert.Nil(t, scoped)
	assert.Nil(t, catalog)

	assert.EqualValues(t, 2, sessionRevocationErrors(t, reader, "fail_closed"))
	assert.EqualValues(t, 0, sessionRevocationErrors(t, reader, "fallback"))
}

func TestCompileSessionRevocationReadErrorWithSeedKeepsPrior(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	prev := otel.GetMeterProvider()
	otel.SetMeterProvider(mp)
	t.Cleanup(func() { otel.SetMeterProvider(prev); _ = mp.Shutdown(context.Background()) })

	now := time.Now()
	c := compilerWithRevocations(t, &revocationsReader{err: errors.New("db down")}, 0)
	c.SeedSessionRevocations([]readmodel.SessionRevocation{
		{GatewayID: capsAcme, Org: "acme", Subject: "user-1", RevokedAt: now.Add(-time.Hour)},
		{GatewayID: capsAcme, Org: "acme", Subject: "old", RevokedAt: now.Add(-40 * 24 * time.Hour)},
		{GatewayID: capsGlobex, Org: "globex", Subject: "user-2", RevokedAt: now.Add(-time.Minute)},
	})

	snap, err := c.CompileFor(context.Background(), capsAcme)
	require.NoError(t, err)
	assert.Equal(t, []string{"user-1"}, subjects(snap.Data().SessionRevocations))

	global, scoped, _, err := c.CompileAll(context.Background())
	require.NoError(t, err)
	assert.Equal(t, []string{"user-1"}, subjects(global.Data().SessionRevocations))
	assert.Equal(t, []string{"user-1"}, subjects(scoped[capsAcme].Data().SessionRevocations))
	assert.Equal(t, []string{"user-2"}, subjects(scoped[capsGlobex].Data().SessionRevocations))

	assert.EqualValues(t, 2, sessionRevocationErrors(t, reader, "fallback"))
	assert.EqualValues(t, 0, sessionRevocationErrors(t, reader, "fail_closed"))
}

func TestCompileSessionRevocationReadErrorWithEmptySeedPublishesNone(t *testing.T) {
	t.Parallel()
	c := compilerWithRevocations(t, &revocationsReader{err: errors.New("db down")}, 0)
	c.SeedSessionRevocations(nil)

	snap, err := c.CompileFor(context.Background(), capsAcme)
	require.NoError(t, err)
	assert.Empty(t, snap.Data().SessionRevocations)

	global, scoped, _, err := c.CompileAll(context.Background())
	require.NoError(t, err)
	assert.Empty(t, global.Data().SessionRevocations)
	assert.Empty(t, scoped[capsAcme].Data().SessionRevocations)
}

func TestRestoreSeedsSessionRevocations(t *testing.T) {
	t.Parallel()
	now := time.Now()
	listing := &revocationsReader{rows: revocationRows(now)}
	store := newFakeLKGStore()
	sealer, err := infrasnapshot.NewLKGSealer(lkgTestSecret(t))
	require.NoError(t, err)
	codec := infrasnapshot.NewCodec()

	first := appsnapshot.NewDispatcher(
		compilerWithRevocations(t, listing, 0),
		codec,
		appsnapshot.NewHolder(),
		&fakeBroadcaster{},
		&fakeOutbox{},
		nil,
		appsnapshot.DispatcherConfig{},
		appsnapshot.WithLKG(store, sealer, appsnapshot.LKGConfig{}),
	)
	require.NoError(t, first.Dispatch(context.Background()))
	require.NotZero(t, listing.calls)

	failing := &revocationsReader{err: errors.New("db down")}
	holder := appsnapshot.NewHolder()
	restarted := appsnapshot.NewDispatcher(
		compilerWithRevocations(t, failing, 0),
		codec,
		holder,
		&fakeBroadcaster{},
		&fakeOutbox{},
		nil,
		appsnapshot.DispatcherConfig{},
		appsnapshot.WithLKG(store, sealer, appsnapshot.LKGConfig{}),
	)
	restarted.Restore(context.Background())
	require.NoError(t, restarted.Dispatch(context.Background()))
	require.NotZero(t, failing.calls, "the restarted compile must attempt the read and still publish")

	globalRaw, _, ok := holder.Snapshot()
	require.True(t, ok)
	global, err := codec.Decode(globalRaw)
	require.NoError(t, err)
	assert.Equal(t, []string{"user-1"}, subjects(global.Data().SessionRevocations))

	scopedRaw, _, ok := holder.SnapshotFor(capsGlobex)
	require.True(t, ok)
	scoped, err := codec.Decode(scopedRaw)
	require.NoError(t, err)
	assert.Equal(t, []string{"user-2"}, subjects(scoped.Data().SessionRevocations), "a hybrid gateway's marker is only in its scoped snapshot, so the seed has to come from that row")
}

func TestRestoreDoesNotSeedRevocationsWhenAScopedRowIsRejected(t *testing.T) {
	t.Parallel()
	listing := &revocationsReader{rows: revocationRows(time.Now())}
	store := newFakeLKGStore()
	sealer, err := infrasnapshot.NewLKGSealer(lkgTestSecret(t))
	require.NoError(t, err)
	codec := infrasnapshot.NewCodec()

	firstHolder := appsnapshot.NewHolder()
	first := appsnapshot.NewDispatcher(
		compilerWithRevocations(t, listing, 0),
		codec,
		firstHolder,
		&fakeBroadcaster{},
		&fakeOutbox{},
		nil,
		appsnapshot.DispatcherConfig{},
		appsnapshot.WithLKG(store, sealer, appsnapshot.LKGConfig{}),
	)
	require.NoError(t, first.Dispatch(context.Background()))
	scopedRaw, _, ok := firstHolder.SnapshotFor(capsGlobex)
	require.True(t, ok)
	scoped, err := codec.Decode(scopedRaw)
	require.NoError(t, err)
	require.Equal(t, []string{"user-2"}, subjects(scoped.Data().SessionRevocations))

	bad := store.row(capsGlobex)
	bad.KeyID = "0000000000000000"
	store.put(bad)

	failing := &revocationsReader{err: errors.New("db down")}
	holder := appsnapshot.NewHolder()
	restarted := appsnapshot.NewDispatcher(
		compilerWithRevocations(t, failing, 0),
		codec,
		holder,
		&fakeBroadcaster{},
		&fakeOutbox{},
		nil,
		appsnapshot.DispatcherConfig{},
		appsnapshot.WithLKG(store, sealer, appsnapshot.LKGConfig{}),
	)
	restarted.Restore(context.Background())
	_, _, globexRestored := holder.SnapshotFor(capsGlobex)
	require.False(t, globexRestored)

	dispatchErr := restarted.Dispatch(context.Background())
	require.NotZero(t, failing.calls)
	raw, _, served := holder.SnapshotFor(capsGlobex)
	if served {
		republished, decErr := codec.Decode(raw)
		require.NoError(t, decErr)
		assert.Contains(t, subjects(republished.Data().SessionRevocations), "user-2")
	}
	require.Error(t, dispatchErr)
	assert.False(t, served, "a rejected hybrid row must not be republished without its markers")
}

func sessionRevocationErrors(t *testing.T, reader *sdkmetric.ManualReader, result string) int64 {
	t.Helper()
	var rm metricdata.ResourceMetrics
	require.NoError(t, reader.Collect(context.Background(), &rm))
	var count int64
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			sum, ok := m.Data.(metricdata.Sum[int64])
			if !ok || m.Name != "trustgate.configsnapshot.session_revocations.errors" {
				continue
			}
			for _, dp := range sum.DataPoints {
				got, _ := dp.Attributes.Value(attribute.Key("result"))
				if got.AsString() == result {
					count += dp.Value
				}
			}
		}
	}
	return count
}
