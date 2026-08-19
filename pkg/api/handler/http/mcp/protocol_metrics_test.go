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

package mcp

import (
	"context"
	"encoding/json"
	"testing"

	appmcp "github.com/NeuralTrust/TrustGate/pkg/app/mcp"
	"github.com/NeuralTrust/TrustGate/pkg/infra/trace"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

func TestSubscriptionSourceRecorderUsesOnlyFixedLabels(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	previous := otel.GetMeterProvider()
	otel.SetMeterProvider(provider)
	t.Cleanup(func() {
		otel.SetMeterProvider(previous)
		require.NoError(t, provider.Shutdown(context.Background()))
	})

	recorder := NewSubscriptionSourceRecorder(true)
	require.NotNil(t, recorder)
	ctx := context.Background()
	recorder.ListenerLive(ctx, 1)
	recorder.ListenerLive(ctx, -1)
	recorder.Lifecycle(ctx, trace.SubscriptionSourceLifecycleOpened)
	recorder.Lifecycle(ctx, "origin=https://tenant.example")
	recorder.FanOut(
		ctx,
		appmcp.NotificationToolsListChanged,
		trace.SubscriptionSourceFanOutAuthorized,
	)
	recorder.FanOut(ctx, appmcp.NotificationKind("doc://tenant/private"), "target=registry-a")
	recorder.Reconnect(ctx, trace.SubscriptionSourceReconnectAttempted)
	recorder.Reconnect(ctx, "credential=secret")
	recorder.Queue(
		ctx,
		appmcp.NotificationToolsListChanged,
		trace.SubscriptionSourceQueueEnqueued,
	)
	recorder.Queue(ctx, appmcp.NotificationKind("event-id"), "pool_key=abc")
	recorder.Terminal(ctx, trace.SubscriptionSourceTerminalShutdown)
	recorder.Terminal(ctx, `{"payload":"tenant data"}`)

	var collected metricdata.ResourceMetrics
	require.NoError(t, reader.Collect(ctx, &collected))

	got := make(map[string][]map[string]string)
	values := make(map[string][]int64)
	for _, scope := range collected.ScopeMetrics {
		for _, metric := range scope.Metrics {
			for _, point := range sourceMetricDataPoints(metric.Data) {
				labels := make(map[string]string)
				for _, pair := range point.Attributes.ToSlice() {
					labels[string(pair.Key)] = pair.Value.AsString()
				}
				got[metric.Name] = append(got[metric.Name], labels)
				values[metric.Name] = append(values[metric.Name], point.Value)
			}
		}
	}

	require.Equal(t, []map[string]string{{}},
		got["mcp.upstream.subscriptions.listeners.live"])
	require.Equal(t, []int64{0}, values["mcp.upstream.subscriptions.listeners.live"])
	require.Equal(t, []map[string]string{{"outcome": trace.SubscriptionSourceLifecycleOpened}},
		got["mcp.upstream.subscriptions.listener.lifecycle_total"])
	require.Equal(t, []map[string]string{{
		"kind":    trace.SubscriptionKindTools,
		"outcome": trace.SubscriptionSourceFanOutAuthorized,
	}}, got["mcp.upstream.subscriptions.fanout_total"])
	require.Equal(t, []map[string]string{{"outcome": trace.SubscriptionSourceReconnectAttempted}},
		got["mcp.upstream.subscriptions.reconnect_total"])
	require.Equal(t, []map[string]string{{
		"kind":    trace.SubscriptionKindTools,
		"outcome": trace.SubscriptionSourceQueueEnqueued,
	}}, got["mcp.upstream.subscriptions.queue_total"])
	require.Equal(t, []map[string]string{{"outcome": trace.SubscriptionSourceTerminalShutdown}},
		got["mcp.upstream.subscriptions.listener.terminal_total"])

	encoded, err := json.Marshal(got)
	require.NoError(t, err)
	for _, forbidden := range []string{
		"origin", "target", "pool_key", "subscriber", "gateway", "consumer",
		"principal", "auth_id", "registry", "credential", "pin", "fingerprint",
		"event-id", "request-id", "subscription-id", "payload", "doc://",
	} {
		require.NotContains(t, string(encoded), forbidden)
	}
}

func TestNewSubscriptionSourceRecorderNilWhenOpsMetricsDisabled(t *testing.T) {
	require.Nil(t, NewSubscriptionSourceRecorder(false))
}

func sourceMetricDataPoints(data metricdata.Aggregation) []metricdata.DataPoint[int64] {
	switch typed := data.(type) {
	case metricdata.Sum[int64]:
		return typed.DataPoints
	default:
		return nil
	}
}
