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
	metricsschema "github.com/NeuralTrust/TrustGate/pkg/metrics"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func internalTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

type fakeExporter struct {
	name       string
	class      metricsschema.DataClass
	publishErr error
	mu         sync.Mutex
	published  int
	lastEvent  *events.Event
	closed     bool
}

func (f *fakeExporter) Name() string { return f.name }

func (f *fakeExporter) DataClass() metricsschema.DataClass { return f.class }

func (f *fakeExporter) Publish(_ context.Context, evt *events.Event) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.published++
	f.lastEvent = evt
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
	mu               sync.Mutex
	builds           int
	buildErr         error
	built            []telemetrydomain.ExporterConfig
	publishErrByName map[string]error
	classByName      map[string]metricsschema.DataClass
}

func (f *fakeFactory) Build(cfg telemetrydomain.ExporterConfig) (Exporter, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.builds++
	f.built = append(f.built, cfg)
	if f.buildErr != nil {
		return nil, f.buildErr
	}
	return &fakeExporter{
		name:       cfg.Name,
		class:      f.classByName[cfg.Name],
		publishErr: f.publishErrByName[cfg.Name],
	}, nil
}

func (f *fakeFactory) Validate(_ telemetrydomain.ExporterConfig) error { return nil }

func (f *fakeFactory) builtConfigs() []telemetrydomain.ExporterConfig {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]telemetrydomain.ExporterConfig, len(f.built))
	copy(out, f.built)
	return out
}

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
	p := NewPipeline(nil, cache, nil, internalTestLogger(),
		telemetrydomain.ExporterConfig{Name: "kafka", Settings: map[string]interface{}{"topic": "default"}})

	overridden := p.resolveTargets([]telemetrydomain.ExporterConfig{
		{Name: "kafka", Settings: map[string]interface{}{"topic": "other"}},
	})
	require.Len(t, overridden, 1)
	assert.Equal(t, "kafka", overridden[0].Name())

	built := factory.builtConfigs()
	require.Len(t, built, 1)
	assert.Equal(t, "other", built[0].Settings["topic"], "kafka must be built from the gateway config, not the default")

	added := p.resolveTargets([]telemetrydomain.ExporterConfig{
		{Name: "other", Settings: map[string]interface{}{"topic": "x"}},
	})
	require.Len(t, added, 2, "a differently-named exporter is added on top of the default")
}

func TestPipeline_OverrideFailureSkipsTarget(t *testing.T) {
	factory := &fakeFactory{buildErr: errors.New("boom")}
	cache := NewExporterCache(factory, internalTestLogger())
	p := NewPipeline(nil, cache, nil, internalTestLogger(),
		telemetrydomain.ExporterConfig{Name: "kafka", Settings: map[string]interface{}{"topic": "default"}})

	targets := p.resolveTargets([]telemetrydomain.ExporterConfig{
		{Name: "kafka", Settings: map[string]interface{}{"topic": "bad"}},
	})

	require.Empty(t, targets, "a failed override is skipped with no default fallback")
	assert.Equal(t, 1, factory.buildCount(), "only the single merged kafka config is attempted")
}

func TestPipeline_MergeMatrix(t *testing.T) {
	t.Parallel()
	cfg := func(name string) telemetrydomain.ExporterConfig {
		return telemetrydomain.ExporterConfig{Name: name, Settings: map[string]interface{}{"topic": name}}
	}
	tests := []struct {
		name     string
		defaults []telemetrydomain.ExporterConfig
		explicit []telemetrydomain.ExporterConfig
		want     []string
	}{
		{name: "empty defaults and no gateway exporters yield no targets", defaults: nil, explicit: nil, want: nil},
		{name: "default only", defaults: []telemetrydomain.ExporterConfig{cfg("otlp-a")}, explicit: nil, want: []string{"otlp-a"}},
		{name: "gateway only", defaults: nil, explicit: []telemetrydomain.ExporterConfig{cfg("otlp-a")}, want: []string{"otlp-a"}},
		{name: "override same name gateway wins", defaults: []telemetrydomain.ExporterConfig{cfg("otlp-a")}, explicit: []telemetrydomain.ExporterConfig{cfg("otlp-a")}, want: []string{"otlp-a"}},
		{name: "same type different name both run in file-then-gateway order", defaults: []telemetrydomain.ExporterConfig{cfg("otlp-a")}, explicit: []telemetrydomain.ExporterConfig{cfg("otlp-b")}, want: []string{"otlp-a", "otlp-b"}},
		{name: "override by name keeps other defaults", defaults: []telemetrydomain.ExporterConfig{cfg("otlp-a"), cfg("kafka-x")}, explicit: []telemetrydomain.ExporterConfig{cfg("otlp-a")}, want: []string{"otlp-a", "kafka-x"}},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			factory := &fakeFactory{}
			cache := NewExporterCache(factory, internalTestLogger())
			p := NewPipeline(nil, cache, nil, internalTestLogger(), tt.defaults...)

			targets := p.resolveTargets(tt.explicit)

			if tt.want == nil {
				require.Nil(t, targets)
				return
			}
			got := make([]string, len(targets))
			for i, e := range targets {
				got[i] = e.Name()
			}
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestPipeline_ResolveTargetsDedupesDuplicateExplicitByName(t *testing.T) {
	factory := &fakeFactory{}
	cache := NewExporterCache(factory, internalTestLogger())
	p := NewPipeline(nil, cache, nil, internalTestLogger())

	targets := p.resolveTargets([]telemetrydomain.ExporterConfig{
		{Name: "dup", Settings: map[string]interface{}{"topic": "first"}},
		{Name: "dup", Settings: map[string]interface{}{"topic": "second"}},
	})

	require.Len(t, targets, 1)
	built := factory.builtConfigs()
	require.Len(t, built, 1)
	assert.Equal(t, "second", built[0].Settings["topic"], "the last config for a duplicated name wins")
}

func TestPipeline_PublishIsolatesExporterErrors(t *testing.T) {
	builder := NewBuilder(adapter.NewRegistry(), stubPricing{})
	factory := &fakeFactory{publishErrByName: map[string]error{"bad": errors.New("boom")}}
	cache := NewExporterCache(factory, internalTestLogger())
	p := NewPipeline(builder, cache, nil, internalTestLogger(),
		telemetrydomain.ExporterConfig{Name: "bad"},
		telemetrydomain.ExporterConfig{Name: "good"})

	req := &infracontext.RequestContext{GatewayID: "gw-1", Method: "POST", Path: "/v1/chat/completions"}
	resp := &infracontext.ResponseContext{StatusCode: 200}

	targets := p.resolveTargets(nil)
	require.Len(t, targets, 2)
	byName := make(map[string]*fakeExporter, len(targets))
	for _, tgt := range targets {
		byName[tgt.Name()] = tgt.(*fakeExporter)
	}

	p.publish(nil, req, resp, time.Now(), time.Now(), nil)

	assert.Equal(t, 1, byName["bad"].publishedCount())
	assert.Equal(t, 1, byName["good"].publishedCount(), "a failing exporter must not prevent the others from publishing")
}

func TestPipeline_RoutesByDataClass(t *testing.T) {
	builder := NewBuilder(adapter.NewRegistry(), stubPricing{})
	factory := &fakeFactory{classByName: map[string]metricsschema.DataClass{
		"meta": metricsschema.Metadata,
		"sens": metricsschema.Raw,
	}}
	cache := NewExporterCache(factory, internalTestLogger())
	p := NewPipeline(builder, cache, nil, internalTestLogger(),
		telemetrydomain.ExporterConfig{Name: "meta"},
		telemetrydomain.ExporterConfig{Name: "sens"})

	req := &infracontext.RequestContext{
		GatewayID: "gw-1", Method: "POST", Path: "/v1/chat/completions",
		Body: []byte(`{"model":"gpt","messages":[{"role":"user","content":"secret prompt"}]}`),
	}
	resp := &infracontext.ResponseContext{
		StatusCode: 200,
		Body:       []byte(`{"choices":[{"message":{"content":"secret answer"}}]}`),
	}

	targets := p.resolveTargets(nil)
	require.Len(t, targets, 2)
	byName := make(map[string]*fakeExporter, len(targets))
	for _, tgt := range targets {
		byName[tgt.Name()] = tgt.(*fakeExporter)
	}

	p.publish(nil, req, resp, time.Now(), time.Now(), nil)

	sens := byName["sens"].lastEvent
	require.NotNil(t, sens)
	assert.NotEmpty(t, sens.Request.Body, "sensible exporter must receive the request body")
	require.NotNil(t, sens.Response.Body)
	assert.NotEmpty(t, *sens.Response.Body, "sensible exporter must receive the response body")

	meta := byName["meta"].lastEvent
	require.NotNil(t, meta)
	assert.Empty(t, meta.Request.Body, "metadata exporter must never receive the request body")
	assert.Nil(t, meta.Response.Body, "metadata exporter must never receive the response body")
}

func TestPipeline_PublishCallsPlaygroundStore(t *testing.T) {
	builder := NewBuilder(adapter.NewRegistry(), stubPricing{})
	factory := &fakeFactory{}
	cache := NewExporterCache(factory, internalTestLogger())
	store := &fakePlaygroundStore{}
	p := NewPipeline(builder, cache, store, internalTestLogger(),
		telemetrydomain.ExporterConfig{Name: "kafka"})

	req := &infracontext.RequestContext{GatewayID: "gw-1", Method: "POST", Path: "/v1/chat/completions"}
	resp := &infracontext.ResponseContext{StatusCode: 200}

	targets := p.resolveTargets(nil)
	require.Len(t, targets, 1)
	exporter := targets[0].(*fakeExporter)

	p.publish(nil, req, resp, time.Now(), time.Now(), nil)

	assert.Equal(t, 1, exporter.publishedCount())
	saved := store.saved()
	require.Len(t, saved, 1, "playground store must receive the event after the exporters run")
}

func TestPipeline_PlaygroundPublishesExportersAndStore(t *testing.T) {
	builder := NewBuilder(adapter.NewRegistry(), stubPricing{})
	factory := &fakeFactory{}
	cache := NewExporterCache(factory, internalTestLogger())
	store := &fakePlaygroundStore{}
	p := NewPipeline(builder, cache, store, internalTestLogger(),
		telemetrydomain.ExporterConfig{Name: "kafka"})

	req := &infracontext.RequestContext{
		GatewayID: "gw-1",
		Method:    "POST",
		Path:      "/v1/chat/completions",
		Headers:   map[string][]string{"X-AG-Playground-Token": {"a.jwt.token"}},
	}
	resp := &infracontext.ResponseContext{StatusCode: 200}

	targets := p.resolveTargets(nil)
	require.Len(t, targets, 1)
	exporter := targets[0].(*fakeExporter)

	p.publish(nil, req, resp, time.Now(), time.Now(), nil)

	assert.Equal(t, 1, exporter.publishedCount(), "playground must publish to Activity exporters")
	saved := store.saved()
	require.Len(t, saved, 1, "playground store must still receive the event for the panel")
}
