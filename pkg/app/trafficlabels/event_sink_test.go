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

package trafficlabels

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"testing"
	"time"

	gatewaydomain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	telemetrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/telemetry"
	"github.com/NeuralTrust/TrustGate/pkg/domain/trafficlabel"
	"github.com/NeuralTrust/TrustGate/pkg/infra/metrics/events"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeGateways struct {
	gw    *gatewaydomain.Gateway
	err   error
	calls int
}

func (f *fakeGateways) FindByID(context.Context, ids.GatewayID) (*gatewaydomain.Gateway, error) {
	f.calls++
	return f.gw, f.err
}

type capturedLabels struct {
	evt       *events.TrafficLabels
	exporters []telemetrydomain.ExporterConfig
}

type fakePublisher struct{ got []capturedLabels }

func (f *fakePublisher) PublishTrafficLabels(_ context.Context, evt *events.TrafficLabels, exporters []telemetrydomain.ExporterConfig) {
	f.got = append(f.got, capturedLabels{evt: evt, exporters: exporters})
}

func sinkGateway(t *testing.T) *gatewaydomain.Gateway {
	t.Helper()
	gw, err := gatewaydomain.New("acme")
	require.NoError(t, err)
	days := 30
	gw.Metadata = map[string]string{gatewaydomain.MetadataTenantIDKey: "tenant-1"}
	gw.Entitlements.Tier = "enterprise"
	gw.Entitlements.RetentionDays = &days
	gw.Telemetry = &telemetrydomain.Telemetry{Exporters: []telemetrydomain.ExporterConfig{{Name: "customer-otlp", Type: "otlp"}}}
	return gw
}

func TestEventSink_PublishesTheClassification(t *testing.T) {
	t.Parallel()
	gw := sinkGateway(t)
	publisher := &fakePublisher{}
	sink := NewEventSink(&fakeGateways{gw: gw}, publisher).(*eventSink)
	now := time.Date(2026, 9, 28, 10, 0, 5, 0, time.UTC)
	sink.now = func() time.Time { return now }

	received := time.Date(2026, 9, 28, 10, 0, 0, 0, time.UTC)
	req := trafficlabel.NewRequest(trafficlabel.RequestParams{
		GatewayID:  gw.ID.String(),
		ConsumerID: "consumer-1",
		TraceID:    "trace-1",
		Text:       "refund",
		Config:     enabledConfig(),
		LabelSets:  append(slices.Clone(billing), legal...),
		ReceivedAt: received,
	})
	cls := trafficlabel.Classification{
		Results: []trafficlabel.Result{
			{LabelSetID: "set-sentiment", Label: "NEGATIVE"},
			{LabelSetID: "set-topic", Label: "Billing"},
		},
		InputTokens:  150,
		OutputTokens: 12,
		Latency:      420 * time.Millisecond,
	}

	require.NoError(t, sink.Publish(context.Background(), req, cls))

	require.Len(t, publisher.got, 1)
	evt := publisher.got[0].evt
	assert.Equal(t, 2, evt.SchemaVersion, "label sets are version 2 of the payload")
	assert.Equal(t, "trace-1", evt.TraceID)
	assert.Equal(t, gw.ID.String(), evt.GatewayID)
	assert.Equal(t, "consumer-1", evt.ConsumerID)
	assert.Equal(t, "tenant-1", evt.TenantID)
	assert.Equal(t, now.UnixMilli(), evt.OccurredOn)
	assert.Equal(t, received.UnixMilli(), evt.RequestedOn)
	assert.Equal(t, []events.LabelResult{
		{LabelSetID: "set-topic", LabelSetName: "Topic", Label: "Billing"},
		{LabelSetID: "set-sentiment", LabelSetName: "Sentiment", Label: "negative"},
	}, evt.Results, "one result per evaluated set, in the consumer's order, with the catalog's spelling")
	assert.Equal(t, testRegistryID, evt.RegistryID)
	assert.Equal(t, "gpt-4o-mini", evt.Model)
	assert.Equal(t, req.CatalogHash, evt.CatalogHash)
	assert.Equal(t, 150, evt.InputTokens)
	assert.Equal(t, 12, evt.OutputTokens)
	assert.Equal(t, int64(420), evt.LatencyMs)

	require.NotNil(t, evt.Retention)
	assert.Equal(t, "enterprise", evt.Retention.Plan)
	assert.Equal(t, received.Add(30*24*time.Hour).UnixMilli(), evt.Retention.ExpiresAt,
		"the classification expires with its request, counted from when it arrived")

	assert.Equal(t, gw.Telemetry.Exporters, publisher.got[0].exporters, "the gateway's own exporters are used")
}

func TestEventSink_NeverCarriesThePrompt(t *testing.T) {
	t.Parallel()
	gw := sinkGateway(t)
	publisher := &fakePublisher{}
	sink := NewEventSink(&fakeGateways{gw: gw}, publisher)

	const prompt = "my card number is 4111 1111 1111 1111, refund me"
	req := trafficlabel.NewRequest(trafficlabel.RequestParams{
		GatewayID: gw.ID.String(),
		TraceID:   "4bf92f3577b34da6a3ce929d0e0e4736",
		Text:      prompt,
		Config:    enabledConfig(),
		LabelSets: billing,
	})
	require.NoError(t, sink.Publish(context.Background(), req, trafficlabel.Classification{Results: []trafficlabel.Result{{LabelSetID: "set-topic", Label: "Billing"}}}))

	require.Len(t, publisher.got, 1)
	raw, err := json.Marshal(publisher.got[0].evt)
	require.NoError(t, err)
	assert.NotContains(t, string(raw), "4111", "the prompt must not reach the collector")
	assert.NotContains(t, string(raw), req.TextHash, "nor anything derived from it")
	assert.Equal(t, req.TraceID, publisher.got[0].evt.TraceID, "the trace id is what correlates it")
}

func TestEventSink_WithoutRetentionOrExporters(t *testing.T) {
	t.Parallel()
	gw, err := gatewaydomain.New("plain")
	require.NoError(t, err)
	publisher := &fakePublisher{}
	sink := NewEventSink(&fakeGateways{gw: gw}, publisher)

	require.NoError(t, sink.Publish(context.Background(), queued(gw.ID.String(), billing, "hi"), trafficlabel.Classification{}))

	require.Len(t, publisher.got, 1)
	assert.Equal(t, []events.LabelResult{{LabelSetID: "set-topic", LabelSetName: "Topic", Label: ""}}, publisher.got[0].evt.Results,
		"a set without a result is reported unlabeled")
	assert.Nil(t, publisher.got[0].evt.Retention)
	assert.Nil(t, publisher.got[0].exporters)
	assert.NotZero(t, publisher.got[0].evt.RequestedOn, "a request without a receive time is stamped now")
}

func TestEventSink_Errors(t *testing.T) {
	t.Parallel()
	publisher := &fakePublisher{}
	id := ids.New[ids.GatewayKind]().String()

	bad := NewEventSink(&fakeGateways{}, publisher)
	require.ErrorIs(t, bad.Publish(context.Background(), queued("not-an-id", billing, "x"), trafficlabel.Classification{}), ErrUnpublishable)

	gone := NewEventSink(&fakeGateways{err: gatewaydomain.ErrNotFound}, publisher)
	require.ErrorIs(t, gone.Publish(context.Background(), queued(id, billing, "x"), trafficlabel.Classification{}), ErrUnpublishable,
		"a deleted gateway can never be published to")

	down := NewEventSink(&fakeGateways{err: errors.New("connection refused")}, publisher)
	err := down.Publish(context.Background(), queued(id, billing, "x"), trafficlabel.Classification{})
	require.Error(t, err)
	assert.NotErrorIs(t, err, ErrUnpublishable, "a failing lookup is transient and retried")

	assert.Empty(t, publisher.got, "nothing is published without a resolvable gateway")
}

func TestEventSink_RemembersMissingGateways(t *testing.T) {
	t.Parallel()
	gateways := &fakeGateways{err: gatewaydomain.ErrNotFound}
	sink := NewEventSink(gateways, &fakePublisher{})
	id := ids.New[ids.GatewayKind]().String()

	for range 3 {
		require.ErrorIs(t, sink.Publish(context.Background(), queued(id, billing, "x"), trafficlabel.Classification{}), ErrUnpublishable)
	}
	assert.Equal(t, 1, gateways.calls, "a backlog for a deleted gateway does not look it up per request")
}

func TestEventSink_DropsExpiredGateways(t *testing.T) {
	t.Parallel()
	gw := sinkGateway(t)
	sink := NewEventSink(&fakeGateways{gw: gw}, &fakePublisher{}).(*eventSink)
	now := time.Date(2026, 9, 28, 10, 0, 0, 0, time.UTC)
	sink.now = func() time.Time { return now }

	require.NoError(t, sink.Publish(context.Background(), queued(gw.ID.String(), billing, "x"), trafficlabel.Classification{}))
	now = now.Add(gatewayCacheTTL + time.Second)
	sink.remember(ids.New[ids.GatewayKind](), gw, now)

	sink.mu.Lock()
	defer sink.mu.Unlock()
	assert.Len(t, sink.known, 1, "the expired entry is dropped when a new one is stored")
	assert.NotContains(t, sink.known, gw.ID)
}

func TestEventSink_CachesGatewayLookups(t *testing.T) {
	t.Parallel()
	gw := sinkGateway(t)
	gateways := &fakeGateways{gw: gw}
	sink := NewEventSink(gateways, &fakePublisher{}).(*eventSink)
	now := time.Date(2026, 9, 28, 10, 0, 0, 0, time.UTC)
	sink.now = func() time.Time { return now }

	for range 3 {
		require.NoError(t, sink.Publish(context.Background(), queued(gw.ID.String(), billing, "x"), trafficlabel.Classification{}))
	}
	assert.Equal(t, 1, gateways.calls, "one lookup serves every result within the TTL")

	now = now.Add(gatewayCacheTTL + time.Second)
	require.NoError(t, sink.Publish(context.Background(), queued(gw.ID.String(), billing, "x"), trafficlabel.Classification{}))
	assert.Equal(t, 2, gateways.calls, "an expired entry is looked up again")
}
