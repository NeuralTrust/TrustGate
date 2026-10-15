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

	appsnapshot "github.com/NeuralTrust/TrustGate/pkg/app/configsnapshot"
	ratelimitdomain "github.com/NeuralTrust/TrustGate/pkg/domain/ratelimit"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

type fakeTenantCaps struct {
	caps []ratelimitdomain.TenantCaps
	err  error
}

func (f fakeTenantCaps) ListTenantCaps(context.Context) ([]ratelimitdomain.TenantCaps, error) {
	return f.caps, f.err
}

// flakyTenantCaps answers like caps until told to fail.
type flakyTenantCaps struct {
	caps fakeTenantCaps
	fail atomic.Bool
}

func (f *flakyTenantCaps) ListTenantCaps(ctx context.Context) ([]ratelimitdomain.TenantCaps, error) {
	if f.fail.Load() {
		return nil, errors.New("db down")
	}
	return f.caps.ListTenantCaps(ctx)
}

func twoTenantCaps() fakeTenantCaps {
	return fakeTenantCaps{caps: []ratelimitdomain.TenantCaps{
		{TenantID: "acme", Tier: "standard", BurstPerMin: 300, QuotaPerMonth: 100000, MaxInstances: 5},
		{TenantID: "globex", Tier: "free", BurstPerMin: 60, QuotaPerMonth: 10000, MaxInstances: 5},
		{TenantID: "tenant-without-gateway", Tier: "free", BurstPerMin: 60, QuotaPerMonth: 10000, MaxInstances: 5},
	}}
}

const (
	capsAcme   = "11111111-1111-1111-1111-111111111111"
	capsGlobex = "22222222-2222-2222-2222-222222222222"
)

func compilerWithCaps(t *testing.T, reader ratelimitdomain.TenantCapsLister) *appsnapshot.Compiler {
	t.Helper()
	return twoTenantCompiler(t,
		mustGatewayID(t, capsAcme), mustGatewayID(t, capsGlobex),
		mustConsumerID(t, "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"), mustConsumerID(t, "cccccccc-cccc-cccc-cccc-cccccccccccc"),
		appsnapshot.WithTenantCaps(reader))
}

// A scoped snapshot is handed to a data plane that serves one gateway. It must
// carry that tenant's plan and nobody else's.
func TestCompileForScopedSnapshotCarriesOnlyItsOwnTenantCaps(t *testing.T) {
	t.Parallel()
	snap, err := compilerWithCaps(t, twoTenantCaps()).CompileFor(context.Background(), capsAcme)
	require.NoError(t, err)

	require.Len(t, snap.Data().TenantCaps, 1)
	assert.Equal(t, "acme", snap.Data().TenantCaps[0].TenantID)
	_, leaked := snap.TenantCapsByTenantID("globex")
	assert.False(t, leaked, "a scoped snapshot must never learn another tenant's plan")
}

func TestCompileAllPartitionsTenantCapsPerScope(t *testing.T) {
	t.Parallel()
	global, scoped, _, err := compilerWithCaps(t, twoTenantCaps()).CompileAll(context.Background())
	require.NoError(t, err)

	require.Len(t, global.Data().TenantCaps, 2, "global carries the tenants that own a gateway, not orphan rows")
	for scope, tenant := range map[string]string{capsAcme: "acme", capsGlobex: "globex"} {
		caps := scoped[scope].Data().TenantCaps
		require.Len(t, caps, 1, scope)
		assert.Equal(t, tenant, caps[0].TenantID)
	}
}

func TestCompileWithoutTenantCapsReaderLeavesSnapshotUnchanged(t *testing.T) {
	t.Parallel()
	snap, err := twoTenantCompiler(t,
		mustGatewayID(t, capsAcme), mustGatewayID(t, capsGlobex),
		mustConsumerID(t, "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"), mustConsumerID(t, "cccccccc-cccc-cccc-cccc-cccccccccccc"),
	).CompileFor(context.Background(), capsAcme)
	require.NoError(t, err)
	assert.Empty(t, snap.Data().TenantCaps)
}

// Caps are an enrichment: a plan-table outage must not freeze every other change
// behind a snapshot that cannot be compiled. The snapshot goes out without caps,
// so the data planes use the stamp on each gateway, and the failure is counted.
func TestCompileSurvivesATenantCapsReadFailureAndCountsIt(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	prev := otel.GetMeterProvider()
	otel.SetMeterProvider(mp)
	t.Cleanup(func() { otel.SetMeterProvider(prev); _ = mp.Shutdown(context.Background()) })

	boom := errors.New("db down")

	snap, err := compilerWithCaps(t, fakeTenantCaps{err: boom}).CompileFor(context.Background(), capsAcme)
	require.NoError(t, err)
	assert.Empty(t, snap.Data().TenantCaps)
	require.Len(t, snap.Data().Gateways, 1, "the rest of the snapshot is intact")

	global, scoped, _, err := compilerWithCaps(t, fakeTenantCaps{err: boom}).CompileAll(context.Background())
	require.NoError(t, err)
	assert.Empty(t, global.Data().TenantCaps)
	for scope, s := range scoped {
		assert.Empty(t, s.Data().TenantCaps, scope)
	}

	var rm metricdata.ResourceMetrics
	require.NoError(t, reader.Collect(context.Background(), &rm))
	var count int64
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if sum, ok := m.Data.(metricdata.Sum[int64]); ok && m.Name == "trustgate.configsnapshot.tenant_caps.errors" {
				for _, dp := range sum.DataPoints {
					count += dp.Value
				}
			}
		}
	}
	assert.EqualValues(t, 2, count, "one per compile that lost its caps")
}

// A transient failure after a success must not send the data planes back to the
// stamps on the gateways: the snapshot keeps the last caps it listed.
func TestCompileReusesTheLastTenantCapsWhenTheNextReadFails(t *testing.T) {
	t.Parallel()
	reader := &flakyTenantCaps{caps: twoTenantCaps()}
	c := compilerWithCaps(t, reader)

	first, err := c.CompileFor(context.Background(), capsAcme)
	require.NoError(t, err)
	require.Len(t, first.Data().TenantCaps, 1)

	reader.fail.Store(true)
	again, err := c.CompileFor(context.Background(), capsAcme)
	require.NoError(t, err)
	require.Len(t, again.Data().TenantCaps, 1, "the last listing is reused")
	assert.Equal(t, "acme", again.Data().TenantCaps[0].TenantID)

	global, scoped, _, err := c.CompileAll(context.Background())
	require.NoError(t, err)
	assert.Len(t, global.Data().TenantCaps, 2)
	assert.Len(t, scoped[capsGlobex].Data().TenantCaps, 1)
}
