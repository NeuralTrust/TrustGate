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
	"regexp"
	"testing"

	gatewaydomain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric/noop"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

const (
	stageDuration = "trustgate.configsnapshot.compile_stage_duration"
	compileCount  = "trustgate.configsnapshot.compiles"
)

func collectCompileTelemetry(t *testing.T, reader *sdkmetric.ManualReader) (counts map[string]int64, stages map[string]uint64) {
	t.Helper()
	var rm metricdata.ResourceMetrics
	require.NoError(t, reader.Collect(context.Background(), &rm))
	counts, stages = map[string]int64{}, map[string]uint64{}
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			switch m.Name {
			case compileCount:
				sum, ok := m.Data.(metricdata.Sum[int64])
				require.True(t, ok)
				for _, p := range sum.DataPoints {
					counts[p.Attributes.Encoded(attribute.DefaultEncoder())] = p.Value
				}
			case stageDuration:
				hist, ok := m.Data.(metricdata.Histogram[float64])
				require.True(t, ok)
				for _, p := range hist.DataPoints {
					stages[p.Attributes.Encoded(attribute.DefaultEncoder())] = p.Count
				}
			}
		}
	}
	return counts, stages
}

func TestDispatchLogsCompileModeReasonAndStages(t *testing.T) {
	var logs bytes.Buffer
	gateways := &settableGateways{items: []*gatewaydomain.Gateway{{ID: mustGatewayID(t, metricsGatewayA), Slug: "a"}}}
	_, d, _, _ := metricsDispatcher(gateways, nil, nil, &logs)

	require.NoError(t, d.Dispatch(context.Background()))
	first := logs.String()
	assert.Contains(t, first, "mode=full reason=boot dirty=0")
	for _, stage := range []string{"read", "build", "encode", "merge", "hash"} {
		assert.Regexp(t, regexp.MustCompile(`stages\.`+stage+`=[0-9.]+[µnm]?s`), first, "stage %s", stage)
	}
	assert.Regexp(t, regexp.MustCompile(`compile=[0-9.]+[µnm]?s mode=full`), first)

	logs.Reset()
	gateways.set([]*gatewaydomain.Gateway{{ID: mustGatewayID(t, metricsGatewayA), Slug: "renamed"}})
	require.NoError(t, d.Dispatch(context.Background()))
	assert.Contains(t, logs.String(), "mode=full reason=signal dirty=0")
}

func TestDispatchRecordsCompileCountAndStageDurations(t *testing.T) {
	reader := installMeter(t, "")
	_, d, _, _ := metricsDispatcher(fakeGateways{items: []*gatewaydomain.Gateway{{ID: mustGatewayID(t, metricsGatewayA)}}}, nil, nil, &bytes.Buffer{})

	require.NoError(t, d.Dispatch(context.Background()))
	require.NoError(t, d.Dispatch(context.Background()))

	counts, stages := collectCompileTelemetry(t, reader)
	assert.Equal(t, map[string]int64{
		"mode=full,outcome=ok,reason=boot":   1,
		"mode=full,outcome=ok,reason=signal": 1,
	}, counts, "a compile that publishes nothing new is still counted")
	assert.Equal(t, map[string]uint64{
		"mode=full,outcome=ok,stage=read":   2,
		"mode=full,outcome=ok,stage=build":  2,
		"mode=full,outcome=ok,stage=encode": 2,
		"mode=full,outcome=ok,stage=merge":  2,
		"mode=full,outcome=ok,stage=hash":   2,
	}, stages)
}

func TestDispatchRecordsFailedCompileWithoutPublishing(t *testing.T) {
	reader := installMeter(t, "")
	var logs bytes.Buffer
	gateways := fakeGateways{err: errors.New("postgres down")}
	_, d, _, broadcaster := metricsDispatcher(gateways, nil, nil, &logs)

	require.Error(t, d.Dispatch(context.Background()))

	counts, stages := collectCompileTelemetry(t, reader)
	assert.Equal(t, map[string]int64{"mode=full,outcome=failed,reason=boot": 1}, counts)
	assert.Equal(t, map[string]uint64{"mode=full,outcome=failed,stage=read": 1}, stages)
	assert.NotContains(t, logs.String(), "published config snapshot")
	assert.Empty(t, broadcaster.broadcasted())
}

func TestCompileTelemetryNeverChangesTheSnapshot(t *testing.T) {
	gw := []*gatewaydomain.Gateway{{ID: mustGatewayID(t, metricsGatewayA)}, {ID: mustGatewayID(t, metricsGatewayB), Entitlements: gatewaydomain.Entitlements{DataPlane: gatewaydomain.DataPlaneHybrid}}}
	dispatchOnce := func(withMetrics bool) (global []byte, globalVersion string, scoped []byte, scopedVersion string) {
		if withMetrics {
			installMeter(t, "")
		} else {
			prev := otel.GetMeterProvider()
			otel.SetMeterProvider(noop.NewMeterProvider())
			t.Cleanup(func() { otel.SetMeterProvider(prev) })
		}
		_, d, holder, _ := metricsDispatcher(fakeGateways{items: gw}, nil, nil, &bytes.Buffer{})
		require.NoError(t, d.Dispatch(context.Background()))
		global, globalVersion, ok := holder.Snapshot()
		require.True(t, ok)
		scoped, scopedVersion, ok = holder.SnapshotFor(metricsGatewayB)
		require.True(t, ok)
		return global, globalVersion, scoped, scopedVersion
	}

	g1, gv1, s1, sv1 := dispatchOnce(true)
	g2, gv2, s2, sv2 := dispatchOnce(false)
	assert.Equal(t, g2, g1)
	assert.Equal(t, gv2, gv1)
	assert.Equal(t, s2, s1)
	assert.Equal(t, sv2, sv1)
}
