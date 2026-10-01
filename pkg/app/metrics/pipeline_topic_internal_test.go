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

type topicAwareExporter struct {
	fakeExporter
	topicErr error
	topicMu  sync.Mutex
	topics   []*events.TopicClassification
}

func (e *topicAwareExporter) PublishTopic(_ context.Context, evt *events.TopicClassification) error {
	e.topicMu.Lock()
	defer e.topicMu.Unlock()
	e.topics = append(e.topics, evt)
	return e.topicErr
}

func (e *topicAwareExporter) topicCount() int {
	e.topicMu.Lock()
	defer e.topicMu.Unlock()
	return len(e.topics)
}

type topicFactory struct {
	topicAware map[string]bool
	topicErr   map[string]error
}

func (f *topicFactory) Build(cfg telemetrydomain.ExporterConfig) (Exporter, error) {
	if f.topicAware[cfg.Name] {
		return &topicAwareExporter{fakeExporter: fakeExporter{name: cfg.Name, class: cfg.Class}, topicErr: f.topicErr[cfg.Name]}, nil
	}
	return &fakeExporter{name: cfg.Name, class: cfg.Class}, nil
}

func (f *topicFactory) Validate(telemetrydomain.ExporterConfig) error { return nil }

func newTopicPipeline(factory *topicFactory, defaults ...telemetrydomain.ExporterConfig) *Pipeline {
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

func TestPipeline_PublishTopicReachesOnlyTopicExporters(t *testing.T) {
	t.Parallel()
	factory := &topicFactory{topicAware: map[string]bool{"otlp-default": true, "otlp-gateway": true}}
	p := newTopicPipeline(factory,
		telemetrydomain.ExporterConfig{Name: "otlp-default"},
		telemetrydomain.ExporterConfig{Name: "postgres-default"})
	explicit := []telemetrydomain.ExporterConfig{{Name: "otlp-gateway"}, {Name: "postgres-gateway"}}

	evt := &events.TopicClassification{TraceID: "trace-1", GatewayID: "gw-1"}
	p.PublishTopic(context.Background(), evt, explicit)

	targets := targetsByName(p, explicit)
	require.Len(t, targets, 4)
	assert.Equal(t, 1, targets["otlp-default"].(*topicAwareExporter).topicCount())
	assert.Equal(t, 1, targets["otlp-gateway"].(*topicAwareExporter).topicCount(), "the gateway's own collector gets it too")
	for _, name := range []string{"otlp-default", "otlp-gateway", "postgres-default", "postgres-gateway"} {
		var published int
		switch exp := targets[name].(type) {
		case *topicAwareExporter:
			published = exp.publishedCount()
		case *fakeExporter:
			published = exp.publishedCount()
		}
		assert.Zero(t, published, "%s must not receive it as a request event", name)
	}
}

func TestPipeline_PublishTopicIsolatesExporterErrors(t *testing.T) {
	t.Parallel()
	factory := &topicFactory{
		topicAware: map[string]bool{"bad": true, "good": true},
		topicErr:   map[string]error{"bad": errors.New("collector down")},
	}
	p := newTopicPipeline(factory, telemetrydomain.ExporterConfig{Name: "bad"}, telemetrydomain.ExporterConfig{Name: "good"})

	p.PublishTopic(context.Background(), &events.TopicClassification{GatewayID: "gw"}, nil)

	targets := targetsByName(p, nil)
	assert.Equal(t, 1, targets["bad"].(*topicAwareExporter).topicCount())
	assert.Equal(t, 1, targets["good"].(*topicAwareExporter).topicCount())
}

func TestPipeline_PublishTopicNilIsNoOp(t *testing.T) {
	t.Parallel()
	var nilPipeline *Pipeline
	nilPipeline.PublishTopic(context.Background(), &events.TopicClassification{}, nil)

	factory := &topicFactory{topicAware: map[string]bool{"otlp": true}}
	p := newTopicPipeline(factory, telemetrydomain.ExporterConfig{Name: "otlp"})
	p.PublishTopic(context.Background(), nil, nil)
	assert.Zero(t, targetsByName(p, nil)["otlp"].(*topicAwareExporter).topicCount())
}
