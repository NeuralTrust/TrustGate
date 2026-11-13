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
	"encoding/json"
	"log/slog"
	"sync"
	"time"

	appsecretref "github.com/NeuralTrust/TrustGate/pkg/app/secretref"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"

	telemetrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/telemetry"
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

type LabelExporter interface {
	PublishTrafficLabels(ctx context.Context, evt *events.TrafficLabels) error
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

	// secrets resolves the secret references of a gateway's exporters; nil
	// on a plane without stores. resolved keeps, per gateway, the exporters
	// it resolved and the stored configs they came from, until the gateway
	// is invalidated or its configs change.
	secrets  appsecretref.ValuesResolver
	mu       sync.Mutex
	resolved map[string]resolvedExporters
}

type resolvedExporters struct {
	source string
	out    []telemetrydomain.ExporterConfig
}

// SetSecretValues makes the pipeline resolve the secret references of
// gateway exporters with r.
func (p *Pipeline) SetSecretValues(r appsecretref.ValuesResolver) {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.secrets = r
	p.resolved = map[string]resolvedExporters{}
}

// InvalidateGateway drops the exporters resolved for gatewayID, after a
// secret they used changed.
func (p *Pipeline) InvalidateGateway(gatewayID ids.GatewayID) {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.resolved, gatewayID.String())
}

// withSecrets returns explicit with its secret references resolved, reusing
// the last resolution of the gateway while its configs are unchanged.
func (p *Pipeline) withSecrets(ctx context.Context, gatewayID string, explicit []telemetrydomain.ExporterConfig) []telemetrydomain.ExporterConfig {
	p.mu.Lock()
	secrets := p.secrets
	p.mu.Unlock()
	if secrets == nil || len(explicit) == 0 {
		return explicit
	}
	gw, err := ids.Parse[ids.GatewayKind](gatewayID)
	if err != nil {
		return explicit
	}
	raw, _ := json.Marshal(explicit)
	source := string(raw)
	p.mu.Lock()
	if r, ok := p.resolved[gatewayID]; ok && r.source == source {
		p.mu.Unlock()
		return r.out
	}
	p.mu.Unlock()
	out := appsecretref.GatewayExporters(ctx, secrets, gw, explicit)
	p.mu.Lock()
	p.resolved[gatewayID] = resolvedExporters{source: source, out: out}
	p.mu.Unlock()
	return out
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
	p.publishContext(context.Background(), requestTrace, req, resp, startTime, endTime, explicit)
}

func (p *Pipeline) publishContext(
	ctx context.Context,
	requestTrace *trace.RequestTrace,
	req *infracontext.RequestContext,
	resp *infracontext.ResponseContext,
	startTime, endTime time.Time,
	explicit []telemetrydomain.ExporterConfig,
) {
	if p == nil || p.builder == nil || req == nil || resp == nil {
		return
	}
	targets := p.resolveTargets(req.GatewayID, p.withSecrets(ctx, req.GatewayID, explicit))
	if len(targets) == 0 && p.playgroundStore == nil {
		return
	}
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

func (p *Pipeline) PublishTrafficLabels(ctx context.Context, evt *events.TrafficLabels, explicit []telemetrydomain.ExporterConfig) {
	if p == nil || evt == nil {
		return
	}
	for _, exporter := range p.resolveTargets(evt.GatewayID, p.withSecrets(ctx, evt.GatewayID, explicit)) {
		labeler, ok := exporter.(LabelExporter)
		if !ok {
			continue
		}
		if err := labeler.PublishTrafficLabels(ctx, evt); err != nil {
			p.logger.Error("failed to publish traffic labels event",
				slog.String("gateway_id", evt.GatewayID),
				slog.String("exporter", exporter.Name()),
				slog.String("error", err.Error()))
		}
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

func exporterIdentity(cfg telemetrydomain.ExporterConfig) string {
	return cfg.Name + "\x00" + string(cfg.Class)
}

func (p *Pipeline) resolveTargets(gatewayID string, explicit []telemetrydomain.ExporterConfig) []Exporter {
	if p.cache == nil {
		return nil
	}
	overrides := make(map[string]telemetrydomain.ExporterConfig, len(explicit))
	for _, e := range explicit {
		overrides[e.Name] = e
	}
	merged := make([]SourcedExporter, 0)
	seenIdentity := make(map[string]struct{})
	seenName := make(map[string]struct{})
	for _, d := range p.defaultConfigs {
		identity := exporterIdentity(d)
		if _, dup := seenIdentity[identity]; dup {
			continue
		}
		seenIdentity[identity] = struct{}{}
		seenName[d.Name] = struct{}{}
		if override, ok := overrides[d.Name]; ok {
			merged = append(merged, SourcedExporter{Config: override, Tenant: true})
			delete(overrides, d.Name)
			continue
		}
		merged = append(merged, SourcedExporter{Config: d})
	}
	for _, e := range explicit {
		if _, dup := seenName[e.Name]; dup {
			continue
		}
		seenName[e.Name] = struct{}{}
		merged = append(merged, SourcedExporter{Config: overrides[e.Name], Tenant: true})
	}
	if len(merged) == 0 {
		return nil
	}
	return p.cache.ResolveOwned(gatewayID, merged)
}

func (p *Pipeline) close() {
	if p == nil {
		return
	}
	if p.cache != nil {
		p.cache.CloseAll()
	}
}
