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
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"slices"
	"strings"
	"testing"

	appsnapshot "github.com/NeuralTrust/TrustGate/pkg/app/configsnapshot"
	authdomain "github.com/NeuralTrust/TrustGate/pkg/domain/auth"
	catalogdomain "github.com/NeuralTrust/TrustGate/pkg/domain/catalog"
	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	gatewaydomain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	policydomain "github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	infrasnapshot "github.com/NeuralTrust/TrustGate/pkg/infra/configsnapshot"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/metric/noop"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

const (
	metricsGatewayA = "11111111-1111-1111-1111-111111111111"
	metricsGatewayB = "22222222-2222-2222-2222-222222222222"
	metricsGatewayC = "33333333-3333-3333-3333-333333333333"
	encodedBytes    = "trustgate.configsnapshot.encoded_bytes"
	scopeCount      = "trustgate.configsnapshot.scopes"
	entities        = "trustgate.configsnapshot.entities"
)

type refusingMeterProvider struct {
	metric.MeterProvider
	refuse string
}

func (p refusingMeterProvider) Meter(name string, opts ...metric.MeterOption) metric.Meter {
	return refusingMeter{Meter: p.MeterProvider.Meter(name, opts...), refuse: p.refuse}
}

type refusingMeter struct {
	metric.Meter
	refuse string
}

func (m refusingMeter) Int64Gauge(name string, opts ...metric.Int64GaugeOption) (metric.Int64Gauge, error) {
	if name == m.refuse {
		return nil, errors.New("gauge refused")
	}
	return m.Meter.Int64Gauge(name, opts...)
}

func installMeter(t *testing.T, refuse string, opts ...sdkmetric.ManualReaderOption) *sdkmetric.ManualReader {
	t.Helper()
	reader := sdkmetric.NewManualReader(opts...)
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	prev := otel.GetMeterProvider()
	otel.SetMeterProvider(refusingMeterProvider{MeterProvider: mp, refuse: refuse})
	t.Cleanup(func() { otel.SetMeterProvider(prev); _ = mp.Shutdown(context.Background()) })
	return reader
}

func collectGauges(t *testing.T, reader *sdkmetric.ManualReader) map[string]map[string]int64 {
	t.Helper()
	var rm metricdata.ResourceMetrics
	require.NoError(t, reader.Collect(context.Background(), &rm))
	out := map[string]map[string]int64{}
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			gauge, ok := m.Data.(metricdata.Gauge[int64])
			if !ok || len(gauge.DataPoints) == 0 {
				continue
			}
			out[m.Name] = map[string]int64{}
			for _, p := range gauge.DataPoints {
				out[m.Name][p.Attributes.Encoded(attribute.DefaultEncoder())] = p.Value
			}
		}
	}
	return out
}

func metricsDispatcher(gateways appsnapshot.GatewayReader, consumers map[string][]*consumerdomain.Consumer, auths map[string][]*authdomain.Auth, logs *bytes.Buffer) (*appsnapshot.Compiler, *appsnapshot.Dispatcher, *appsnapshot.Holder, *fakeBroadcaster) {
	compiler := appsnapshot.NewCompiler(gateways, fakeConsumers{byGateway: consumers},
		fakeRegistries{byGateway: map[string][]*registrydomain.Registry{}}, fakePolicies{byGateway: map[string][]*policydomain.Policy{}},
		fakeAuths{byGateway: auths}, fakeCatalog{providers: []catalogdomain.Provider{{Code: "openai"}}}, nil)
	holder, broadcaster := appsnapshot.NewHolder(), &fakeBroadcaster{}
	d := appsnapshot.NewDispatcher(compiler, infrasnapshot.NewCodec(), holder, broadcaster, &fakeOutbox{}, slog.New(slog.NewTextHandler(logs, nil)), appsnapshot.DispatcherConfig{})
	return compiler, d, holder, broadcaster
}

func apiKeys(gw ids.GatewayID, owner string, n int) []*authdomain.Auth {
	out := make([]*authdomain.Auth, n)
	for i := range out {
		out[i] = &authdomain.Auth{ID: ids.New[ids.AuthKind](), GatewayID: gw, Name: "key", Type: authdomain.TypeAPIKey, Enabled: true, OwnerID: owner}
	}
	return out
}

func llmConsumers(gw ids.GatewayID, audience consumerdomain.Audience, n int, links ...*authdomain.Auth) []*consumerdomain.Consumer {
	linked := map[ids.AuthID]consumerdomain.AuthLink{}
	for _, auth := range links {
		linked[auth.ID] = consumerdomain.AuthLink{Level: consumerdomain.GrantLevelUser}
	}
	out := make([]*consumerdomain.Consumer, n)
	for i := range out {
		out[i] = &consumerdomain.Consumer{ID: ids.New[ids.ConsumerKind](), GatewayID: gw, Audience: audience, AuthLinks: linked}
	}
	return out
}

func TestDispatchRecordsSnapshotSizesWithoutScopeIdentifiers(t *testing.T) {
	reader := installMeter(t, "")
	gwA, gwB := mustGatewayID(t, metricsGatewayA), mustGatewayID(t, metricsGatewayB)
	three := []*gatewaydomain.Gateway{{ID: gwA}, {ID: gwB}, {ID: mustGatewayID(t, metricsGatewayC)}}
	gateways := &settableGateways{}
	var logs bytes.Buffer
	compiler, d, holder, _ := metricsDispatcher(gateways,
		map[string][]*consumerdomain.Consumer{metricsGatewayA: llmConsumers(gwA, "", 1)},
		map[string][]*authdomain.Auth{metricsGatewayB: apiKeys(gwB, "", 2)}, &logs)
	_, _, catalog, err := compiler.CompileAll(context.Background())
	require.NoError(t, err)
	catalogRaw, err := infrasnapshot.NewCodec().Encode(catalog)
	require.NoError(t, err)

	for _, items := range [][]*gatewaydomain.Gateway{three, three[:2]} {
		gateways.set(items)
		require.NoError(t, d.Dispatch(context.Background()))

		globalRaw, _, ok := holder.Snapshot()
		require.True(t, ok)
		var largestScope string
		var largest, total int
		for _, gw := range items {
			raw, _, ok := holder.SnapshotFor(gw.ID.String())
			require.True(t, ok)
			if len(raw) > largest {
				largestScope, largest = gw.ID.String(), len(raw)
			}
			total += len(raw)
		}
		got := collectGauges(t, reader)
		assert.Equal(t, map[string]int64{
			"flavour=catalog":           int64(len(catalogRaw)),
			"flavour=global":            int64(len(globalRaw)),
			"flavour=scoped,stat=max":   int64(largest),
			"flavour=scoped,stat=total": int64(total),
		}, got[encodedBytes])
		assert.Equal(t, map[string]int64{"": int64(len(items))}, got[scopeCount])
		assert.Contains(t, logs.String(), fmt.Sprintf("scopes=%d largest_scope=%s largest_scope_bytes=%d", len(items), largestScope, largest))
	}
}

func TestDispatchRecordsEntityCounts(t *testing.T) {
	gwA, gwB := mustGatewayID(t, metricsGatewayA), mustGatewayID(t, metricsGatewayB)
	hosted := []*gatewaydomain.Gateway{{ID: gwA}}
	withHybrid := []*gatewaydomain.Gateway{{ID: gwA}, {ID: gwB, Entitlements: gatewaydomain.Entitlements{DataPlane: gatewaydomain.DataPlaneHybrid}}}
	owned, hybridOwned := apiKeys(gwA, "user-1", 2), apiKeys(gwB, "user-2", 1)
	personal := map[string][]*consumerdomain.Consumer{metricsGatewayA: slices.Concat(llmConsumers(gwA, consumerdomain.AudienceApplication, 4),
		llmConsumers(gwA, consumerdomain.AudiencePersonal, 1, owned...), llmConsumers(gwA, consumerdomain.AudiencePersonal, 1, owned[0]))}
	personalAuths := map[string][]*authdomain.Auth{metricsGatewayA: slices.Concat(apiKeys(gwA, "", 3), owned)}
	oss := map[string][]*consumerdomain.Consumer{metricsGatewayA: slices.Concat(llmConsumers(gwA, consumerdomain.AudienceApplication, 1), llmConsumers(gwA, "", 1))}
	ossAuths := map[string][]*authdomain.Auth{metricsGatewayA: apiKeys(gwA, "", 2)}
	hybrid := map[string][]*consumerdomain.Consumer{metricsGatewayA: oss[metricsGatewayA], metricsGatewayB: llmConsumers(gwB, consumerdomain.AudiencePersonal, 1, hybridOwned...)}
	hybridAuths := map[string][]*authdomain.Auth{metricsGatewayA: ossAuths[metricsGatewayA], metricsGatewayB: hybridOwned}

	cases := []struct {
		name                 string
		gateways             []*gatewaydomain.Gateway
		consumers            map[string][]*consumerdomain.Consumer
		auths                map[string][]*authdomain.Auth
		single               bool
		auth, own, per, link int64
	}{
		{"partitioned personal data", hosted, personal, personalAuths, false, 5, 2, 2, 3},
		{"single snapshot personal data", hosted, personal, personalAuths, true, 5, 2, 2, 3},
		{"partitioned oss data", hosted, oss, ossAuths, false, 2, 0, 0, 0},
		{"partitioned with a hybrid gateway", withHybrid, hybrid, hybridAuths, false, 3, 1, 1, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			reader := installMeter(t, "")
			compiler, _, _, _ := metricsDispatcher(fakeGateways{items: tc.gateways}, tc.consumers, tc.auths, &bytes.Buffer{})
			var source appsnapshot.SnapshotCompiler = compiler
			if tc.single {
				source = hookedCompiler{inner: compiler}
			}
			d := appsnapshot.NewDispatcher(source, infrasnapshot.NewCodec(), appsnapshot.NewHolder(), &fakeBroadcaster{}, &fakeOutbox{}, nil, appsnapshot.DispatcherConfig{})

			require.NoError(t, d.Dispatch(context.Background()))

			got := collectGauges(t, reader)
			assert.Equal(t, map[string]int64{"kind=auths": tc.auth, "kind=owned_auths": tc.own, "kind=personal_consumers": tc.per, "kind=personal_links": tc.link}, got[entities])
			if tc.single {
				assert.Equal(t, []string{"flavour=global"}, slices.Collect(maps.Keys(got[encodedBytes])))
				assert.NotContains(t, got, scopeCount)
			}
		})
	}
}

func TestDispatchRecordsOnPublishOnlyAndNeverFailsIt(t *testing.T) {
	cases := []struct {
		name, refuse string
		noop         bool
		want         []string
	}{
		{"sdk meter", "", false, []string{encodedBytes, entities, scopeCount}},
		{"no-op meter provider", "", true, nil},
		{"size gauge refused", encodedBytes, false, []string{entities, scopeCount}},
		{"entity gauge refused", entities, false, []string{encodedBytes, scopeCount}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			reader := installMeter(t, tc.refuse, sdkmetric.WithTemporalitySelector(func(sdkmetric.InstrumentKind) metricdata.Temporality {
				return metricdata.DeltaTemporality
			}))
			if tc.noop {
				otel.SetMeterProvider(noop.NewMeterProvider())
			}
			var logs bytes.Buffer
			_, d, holder, broadcaster := metricsDispatcher(fakeGateways{items: []*gatewaydomain.Gateway{{ID: mustGatewayID(t, metricsGatewayA)}}}, nil, nil, &logs)

			require.NoError(t, d.Dispatch(context.Background()))
			assert.ElementsMatch(t, tc.want, slices.Collect(maps.Keys(collectGauges(t, reader))))
			require.NoError(t, d.Dispatch(context.Background()))
			assert.Empty(t, collectGauges(t, reader), "a dedup records nothing")

			versions := broadcaster.broadcasted()
			require.Len(t, versions, 1)
			_, held, ok := holder.Snapshot()
			require.True(t, ok)
			assert.Equal(t, versions[0], held)
			assert.Len(t, broadcaster.scopedBroadcasted(metricsGatewayA), 1)
			assert.Contains(t, logs.String(), "published config snapshot")
			assert.Equal(t, tc.refuse != "", strings.Contains(logs.String(), "level=WARN msg=\"failed to create config snapshot gauge\""))
			assert.Equal(t, tc.refuse != "", strings.Contains(logs.String(), "instrument="+tc.refuse+" "))
		})
	}
}
