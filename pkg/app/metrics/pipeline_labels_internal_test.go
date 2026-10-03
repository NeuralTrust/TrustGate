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
	"sync"
	"testing"

	telemetrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/telemetry"
	"github.com/NeuralTrust/TrustGate/pkg/infra/metrics/events"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type labelAwareExporter struct {
	fakeExporter
	labelErr error
	labelMu  sync.Mutex
	labels   []*events.TrafficLabels
}

func (e *labelAwareExporter) PublishTrafficLabels(_ context.Context, evt *events.TrafficLabels) error {
	e.labelMu.Lock()
	defer e.labelMu.Unlock()
	e.labels = append(e.labels, evt)
	return e.labelErr
}

func (e *labelAwareExporter) labelCount() int {
	e.labelMu.Lock()
	defer e.labelMu.Unlock()
	return len(e.labels)
}

type labelFactory struct {
	labelAware map[string]bool
	labelErr   map[string]error
}

func (f *labelFactory) Build(cfg telemetrydomain.ExporterConfig) (Exporter, error) {
	if f.labelAware[cfg.Name] {
		return &labelAwareExporter{fakeExporter: fakeExporter{name: cfg.Name, class: cfg.Class}, labelErr: f.labelErr[cfg.Name]}, nil
	}
	return &fakeExporter{name: cfg.Name, class: cfg.Class}, nil
}

func (f *labelFactory) Validate(telemetrydomain.ExporterConfig) error { return nil }

func newLabelPipeline(factory *labelFactory, defaults ...telemetrydomain.ExporterConfig) *Pipeline {
	cache := NewExporterCache(factory, internalTestLogger())
	return NewPipeline(NewBuilder(adapter.NewRegistry(), stubPricing{}), cache, nil, internalTestLogger(), defaults...)
}

func targetsByName(p *Pipeline, explicit []telemetrydomain.ExporterConfig) map[string]Exporter {
	out := map[string]Exporter{}
	for _, tgt := range p.resolveTargets(explicit) {
		out[tgt.Name()] = tgt
	}
	return out
}

func TestPipeline_PublishTrafficLabelsReachesOnlyLabelExporters(t *testing.T) {
	t.Parallel()
	factory := &labelFactory{labelAware: map[string]bool{"otlp-default": true, "otlp-gateway": true}}
	p := newLabelPipeline(factory,
		telemetrydomain.ExporterConfig{Name: "otlp-default"},
		telemetrydomain.ExporterConfig{Name: "postgres-default"})
	explicit := []telemetrydomain.ExporterConfig{{Name: "otlp-gateway"}, {Name: "postgres-gateway"}}

	evt := &events.TrafficLabels{TraceID: "trace-1", GatewayID: "gw-1"}
	p.PublishTrafficLabels(context.Background(), evt, explicit)

	targets := targetsByName(p, explicit)
	require.Len(t, targets, 4)
	assert.Equal(t, 1, targets["otlp-default"].(*labelAwareExporter).labelCount())
	assert.Equal(t, 1, targets["otlp-gateway"].(*labelAwareExporter).labelCount(), "the gateway's own collector gets it too")
	for _, name := range []string{"otlp-default", "otlp-gateway", "postgres-default", "postgres-gateway"} {
		var published int
		switch exp := targets[name].(type) {
		case *labelAwareExporter:
			published = exp.publishedCount()
		case *fakeExporter:
			published = exp.publishedCount()
		}
		assert.Zero(t, published, "%s must not receive it as a request event", name)
	}
}

func TestPipeline_PublishTrafficLabelsIsolatesExporterErrors(t *testing.T) {
	t.Parallel()
	factory := &labelFactory{
		labelAware: map[string]bool{"bad": true, "good": true},
		labelErr:   map[string]error{"bad": errors.New("collector down")},
	}
	p := newLabelPipeline(factory, telemetrydomain.ExporterConfig{Name: "bad"}, telemetrydomain.ExporterConfig{Name: "good"})

	p.PublishTrafficLabels(context.Background(), &events.TrafficLabels{GatewayID: "gw"}, nil)

	targets := targetsByName(p, nil)
	assert.Equal(t, 1, targets["bad"].(*labelAwareExporter).labelCount())
	assert.Equal(t, 1, targets["good"].(*labelAwareExporter).labelCount())
}

func TestPipeline_PublishTrafficLabelsNilIsNoOp(t *testing.T) {
	t.Parallel()
	var nilPipeline *Pipeline
	nilPipeline.PublishTrafficLabels(context.Background(), &events.TrafficLabels{}, nil)

	factory := &labelFactory{labelAware: map[string]bool{"otlp": true}}
	p := newLabelPipeline(factory, telemetrydomain.ExporterConfig{Name: "otlp"})
	p.PublishTrafficLabels(context.Background(), nil, nil)
	assert.Zero(t, targetsByName(p, nil)["otlp"].(*labelAwareExporter).labelCount())
}
