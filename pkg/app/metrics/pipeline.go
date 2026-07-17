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
	"log/slog"
	"time"

	telemetrydomain 	"github.com/NeuralTrust/TrustGate/pkg/domain/telemetry"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/NeuralTrust/TrustGate/pkg/infra/metrics/events"
	"github.com/NeuralTrust/TrustGate/pkg/infra/trace"
	metricsschema "github.com/NeuralTrust/TrustGate/pkg/metrics"
)

type Exporter interface {
	Name() string
	DataClass() metricsschema.DataClass
	Publish(ctx context.Context, evt *events.Event) error
	Close()
}

// PlaygroundTraceStore persists the metrics Event of playground requests so the
// dashboard can fetch it by TraceID. It runs after the exporters as a
// best-effort side channel and must never block or fail the pipeline.
type PlaygroundTraceStore interface {
	Save(ctx context.Context, req *infracontext.RequestContext, evt *events.Event)
}

type Pipeline struct {
	builder         *Builder
	defaultConfigs  []telemetrydomain.ExporterConfig
	cache           *ExporterCache
	playgroundStore PlaygroundTraceStore
	logger          *slog.Logger
}

func NewPipeline(
	builder *Builder,
	cache *ExporterCache,
	playgroundStore PlaygroundTraceStore,
	logger *slog.Logger,
	defaults ...telemetrydomain.ExporterConfig,
) *Pipeline {
	return &Pipeline{
		builder:         builder,
		defaultConfigs:  defaults,
		cache:           cache,
		playgroundStore: playgroundStore,
		logger:          logger,
	}
}

func (p *Pipeline) publish(
	requestTrace *trace.RequestTrace,
	req *infracontext.RequestContext,
	resp *infracontext.ResponseContext,
	startTime, endTime time.Time,
	explicit []telemetrydomain.ExporterConfig,
) {
	if p == nil || p.builder == nil || req == nil || resp == nil {
		return
	}
	targets := p.resolveTargets(explicit)
	if len(targets) == 0 && p.playgroundStore == nil {
		return
	}
	ctx := context.Background()
	evt := p.builder.Build(ctx, requestTrace, req, resp, startTime, endTime)
	for _, exporter := range targets {
		if err := exporter.Publish(ctx, viewForClass(evt, exporter.DataClass())); err != nil {
			p.logger.Error("failed to publish metrics event",
				slog.String("gateway_id", req.GatewayID),
				slog.String("exporter", exporter.Name()),
				slog.String("error", err.Error()))
		}
	}
	if p.playgroundStore != nil {
		p.playgroundStore.Save(ctx, req, evt)
	}
}

// viewForClass projects the event to the class the exporter is fixed to, so a
// sensible sink only ever sees request/response bodies and every other exporter
// only sees sanitized metadata (ENG-1021).
func viewForClass(evt *events.Event, class metricsschema.DataClass) *events.Event {
	if evt == nil {
		return nil
	}
	if class == metricsschema.Raw {
		v := evt.SensibleView()
		return &v
	}
	v := evt.MetadataView()
	return &v
}

func (p *Pipeline) resolveTargets(explicit []telemetrydomain.ExporterConfig) []Exporter {
	if p.cache == nil {
		return nil
	}
	overrides := make(map[string]telemetrydomain.ExporterConfig, len(explicit))
	for _, e := range explicit {
		overrides[e.Name] = e
	}
	merged := make([]telemetrydomain.ExporterConfig, 0, len(p.defaultConfigs)+len(explicit))
	seen := make(map[string]struct{}, len(p.defaultConfigs)+len(explicit))
	for _, d := range p.defaultConfigs {
		if _, dup := seen[d.Name]; dup {
			continue
		}
		seen[d.Name] = struct{}{}
		if override, ok := overrides[d.Name]; ok {
			merged = append(merged, override)
			continue
		}
		merged = append(merged, d)
	}
	for _, e := range explicit {
		if _, dup := seen[e.Name]; dup {
			continue
		}
		seen[e.Name] = struct{}{}
		merged = append(merged, overrides[e.Name])
	}
	if len(merged) == 0 {
		return nil
	}
	return p.cache.Resolve(merged)
}

func (p *Pipeline) close() {
	if p == nil {
		return
	}
	if p.cache != nil {
		p.cache.CloseAll()
	}
}
