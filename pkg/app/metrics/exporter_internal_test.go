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

package metrics

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	telemetrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/telemetry"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/NeuralTrust/TrustGate/pkg/infra/metrics/events"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func internalTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

type fakeExporter struct {
	name       string
	publishErr error
	mu         sync.Mutex
	published  int
	closed     bool
}

func (f *fakeExporter) Name() string { return f.name }

func (f *fakeExporter) Publish(_ context.Context, _ *events.Event) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.published++
	return f.publishErr
}

func (f *fakeExporter) Close() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closed = true
}

func (f *fakeExporter) publishedCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.published
}

type fakeFactory struct {
	mu       sync.Mutex
	builds   int
	buildErr error
}

func (f *fakeFactory) Build(cfg telemetrydomain.ExporterConfig) (Exporter, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.builds++
	if f.buildErr != nil {
		return nil, f.buildErr
	}
	return &fakeExporter{name: cfg.Name}, nil
}

func (f *fakeFactory) Validate(_ telemetrydomain.ExporterConfig) error { return nil }

type fakePlaygroundStore struct {
	mu     sync.Mutex
	events []*events.Event
}

func (f *fakePlaygroundStore) Save(_ context.Context, _ *infracontext.RequestContext, evt *events.Event) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.events = append(f.events, evt)
}

func (f *fakePlaygroundStore) saved() []*events.Event {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]*events.Event, len(f.events))
	copy(out, f.events)
	return out
}

func (f *fakeFactory) buildCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.builds
}

func TestExporterCache_DedupesIdenticalConfigs(t *testing.T) {
	factory := &fakeFactory{}
	cache := NewExporterCache(factory, internalTestLogger())

	cfg := telemetrydomain.ExporterConfig{Name: "kafka", Settings: map[string]interface{}{"topic": "a"}}
	out := cache.Resolve([]telemetrydomain.ExporterConfig{cfg, cfg})

	require.Len(t, out, 1)
	assert.Equal(t, 1, factory.buildCount())

	cache.Resolve([]telemetrydomain.ExporterConfig{cfg})
	assert.Equal(t, 1, factory.buildCount(), "second resolve must reuse the cached exporter")
}

func TestExporterCache_CachesBuildFailures(t *testing.T) {
	factory := &fakeFactory{buildErr: errors.New("boom")}
	cache := NewExporterCache(factory, internalTestLogger())

	cfg := telemetrydomain.ExporterConfig{Name: "kafka", Settings: map[string]interface{}{"topic": "a"}}
	out := cache.Resolve([]telemetrydomain.ExporterConfig{cfg})
	require.Empty(t, out)

	cache.Resolve([]telemetrydomain.ExporterConfig{cfg})
	assert.Equal(t, 1, factory.buildCount(), "failed builds must be cached, not retried each request")
}

func TestExporterCache_CloseAllClosesInstances(t *testing.T) {
	factory := &fakeFactory{}
	cache := NewExporterCache(factory, internalTestLogger())

	out := cache.Resolve([]telemetrydomain.ExporterConfig{{Name: "kafka", Settings: map[string]interface{}{"topic": "a"}}})
	require.Len(t, out, 1)
	exporter := out[0].(*fakeExporter)

	cache.CloseAll()
	assert.True(t, exporter.closed)
}

func TestPipeline_ResolveTargetsOverrideByName(t *testing.T) {
	factory := &fakeFactory{}
	cache := NewExporterCache(factory, internalTestLogger())
	defaultKafka := &fakeExporter{name: "kafka"}
	p := NewPipeline(nil, cache, nil, internalTestLogger(), defaultKafka)

	overridden := p.resolveTargets([]telemetrydomain.ExporterConfig{
		{Name: "kafka", Settings: map[string]interface{}{"topic": "other"}},
	})
	require.Len(t, overridden, 1)
	assert.Equal(t, "kafka", overridden[0].Name())
	assert.NotSame(t, defaultKafka, overridden[0], "explicit kafka must replace the default kafka")

	added := p.resolveTargets([]telemetrydomain.ExporterConfig{
		{Name: "other", Settings: map[string]interface{}{"topic": "x"}},
	})
	require.Len(t, added, 2, "a differently-named exporter is added on top of the default")
}

func TestPipeline_OverrideFailureKeepsDefault(t *testing.T) {
	factory := &fakeFactory{buildErr: errors.New("boom")}
	cache := NewExporterCache(factory, internalTestLogger())
	defaultKafka := &fakeExporter{name: "kafka"}
	p := NewPipeline(nil, cache, nil, internalTestLogger(), defaultKafka)

	targets := p.resolveTargets([]telemetrydomain.ExporterConfig{
		{Name: "kafka", Settings: map[string]interface{}{"topic": "bad"}},
	})

	require.Len(t, targets, 1)
	assert.Same(t, defaultKafka, targets[0], "default must survive when the overriding exporter fails to build")
}

func TestPipeline_PublishIsolatesExporterErrors(t *testing.T) {
	builder := NewBuilder(adapter.NewRegistry(), stubPricing{})
	bad := &fakeExporter{name: "bad", publishErr: errors.New("boom")}
	good := &fakeExporter{name: "good"}
	p := NewPipeline(builder, nil, nil, internalTestLogger(), bad, good)

	req := &infracontext.RequestContext{GatewayID: "gw-1", Method: "POST", Path: "/v1/chat/completions"}
	resp := &infracontext.ResponseContext{StatusCode: 200}

	p.publish(nil, req, resp, time.Now(), time.Now(), nil)

	assert.Equal(t, 1, bad.publishedCount())
	assert.Equal(t, 1, good.publishedCount(), "a failing exporter must not prevent the others from publishing")
}

func TestPipeline_PublishCallsPlaygroundStore(t *testing.T) {
	builder := NewBuilder(adapter.NewRegistry(), stubPricing{})
	exporter := &fakeExporter{name: "kafka"}
	store := &fakePlaygroundStore{}
	p := NewPipeline(builder, nil, store, internalTestLogger(), exporter)

	req := &infracontext.RequestContext{GatewayID: "gw-1", Method: "POST", Path: "/v1/chat/completions"}
	resp := &infracontext.ResponseContext{StatusCode: 200}

	p.publish(nil, req, resp, time.Now(), time.Now(), nil)

	assert.Equal(t, 1, exporter.publishedCount())
	saved := store.saved()
	require.Len(t, saved, 1, "playground store must receive the event after the exporters run")
}
