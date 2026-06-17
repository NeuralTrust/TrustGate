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

	telemetrydomain "github.com/NeuralTrust/AgentGateway/pkg/domain/telemetry"
	infracontext "github.com/NeuralTrust/AgentGateway/pkg/infra/context"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/metrics/events"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/trace"
)

type Exporter interface {
	Name() string
	Publish(ctx context.Context, evt *events.Event) error
	Close()
}

// PlaygroundTraceStore persists the metrics Event of playground-originated
// requests so the dashboard can fetch it by TraceID. It is invoked after the
// exporters and is a best-effort side channel: it must never block or fail the
// pipeline.
type PlaygroundTraceStore interface {
	Save(ctx context.Context, req *infracontext.RequestContext, evt *events.Event)
}

type Pipeline struct {
	builder          *Builder
	defaultExporters []Exporter
	cache            *ExporterCache
	playgroundStore  PlaygroundTraceStore
	logger           *slog.Logger
}

func NewPipeline(
	builder *Builder,
	cache *ExporterCache,
	playgroundStore PlaygroundTraceStore,
	logger *slog.Logger,
	defaults ...Exporter,
) *Pipeline {
	return &Pipeline{
		builder:          builder,
		defaultExporters: defaults,
		cache:            cache,
		playgroundStore:  playgroundStore,
		logger:           logger,
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
		if err := exporter.Publish(ctx, evt); err != nil {
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

func (p *Pipeline) resolveTargets(explicit []telemetrydomain.ExporterConfig) []Exporter {
	var resolved []Exporter
	if len(explicit) > 0 && p.cache != nil {
		resolved = p.cache.Resolve(explicit)
	}
	resolvedNames := make(map[string]struct{}, len(resolved))
	for _, e := range resolved {
		resolvedNames[e.Name()] = struct{}{}
	}
	targets := make([]Exporter, 0, len(resolved)+len(p.defaultExporters))
	targets = append(targets, resolved...)
	for _, d := range p.defaultExporters {
		if _, replaced := resolvedNames[d.Name()]; !replaced {
			targets = append(targets, d)
		}
	}
	return targets
}

func (p *Pipeline) close() {
	if p == nil {
		return
	}
	for _, d := range p.defaultExporters {
		d.Close()
	}
	if p.cache != nil {
		p.cache.CloseAll()
	}
}
