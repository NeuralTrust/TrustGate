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

package middleware_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/api/middleware"
	appcatalog "github.com/NeuralTrust/TrustGate/pkg/app/catalog"
	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	appgateway "github.com/NeuralTrust/TrustGate/pkg/app/gateway"
	appmetrics "github.com/NeuralTrust/TrustGate/pkg/app/metrics"
	"github.com/NeuralTrust/TrustGate/pkg/config"
	gatewaydomain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	telemetrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/telemetry"
	"github.com/NeuralTrust/TrustGate/pkg/infra/metrics/events"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
	infratelemetry "github.com/NeuralTrust/TrustGate/pkg/infra/telemetry"
	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const defaultTopic = "default-topic"

type eventRecorder struct {
	mu  sync.Mutex
	got map[string][]*events.Event
}

func newEventRecorder() *eventRecorder {
	return &eventRecorder{got: make(map[string][]*events.Event)}
}

func (r *eventRecorder) record(key string, evt *events.Event) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.got[key] = append(r.got[key], evt)
}

func (r *eventRecorder) count(key string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.got[key])
}

func (r *eventRecorder) first(key string) *events.Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.got[key]) == 0 {
		return nil
	}
	return r.got[key][0]
}

type memExporter struct {
	name  string
	topic string
	rec   *eventRecorder
	fail  bool
}

func (e *memExporter) Name() string { return e.name }

func (e *memExporter) Publish(_ context.Context, evt *events.Event) error {
	if e.fail {
		return errors.New("memExporter: forced publish failure")
	}
	e.rec.record(e.name+"/"+e.topic, evt)
	return nil
}

func (e *memExporter) Close() {}

type memTemplate struct {
	name string
	rec  *eventRecorder
	fail bool
}

func (t *memTemplate) Name() string { return t.name }

func (t *memTemplate) ValidateConfig(settings map[string]interface{}) error {
	if topicOf(settings) == "" {
		return errors.New("memTemplate: topic is required")
	}
	return nil
}

func (t *memTemplate) WithSettings(settings map[string]interface{}) (appmetrics.Exporter, error) {
	return &memExporter{name: t.name, topic: topicOf(settings), rec: t.rec, fail: t.fail}, nil
}

func topicOf(settings map[string]interface{}) string {
	topic, _ := settings["topic"].(string)
	return topic
}

type zeroPricing struct{}

func (zeroPricing) Resolve(_ context.Context, _ string, _ string) appcatalog.Pricing {
	return appcatalog.Pricing{}
}

func newMetricsApp(t *testing.T, gw *gatewaydomain.Gateway, rec *eventRecorder) *fiber.App {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	factory := infratelemetry.NewExporterLocator(
		infratelemetry.WithExporter("kafka", &memTemplate{name: "kafka", rec: rec}),
		infratelemetry.WithExporter("memory", &memTemplate{name: "memory", rec: rec}),
		infratelemetry.WithExporter("broken", &memTemplate{name: "broken", rec: rec, fail: true}),
	)
	cache := appmetrics.NewExporterCache(factory, logger)

	builder := appmetrics.NewBuilder(adapter.NewRegistry(), zeroPricing{})
	pipeline := appmetrics.NewPipeline(builder, cache, nil, logger,
		telemetrydomain.ExporterConfig{Name: "kafka", Settings: map[string]interface{}{"topic": defaultTopic}})
	worker := appmetrics.NewWorker(logger, pipeline)
	worker.StartWorkers(2)
	t.Cleanup(worker.Shutdown)

	cfg := &config.Config{}
	cfg.Telemetry.Enabled = true
	mw := middleware.NewMetricsMiddleware(worker, cfg)

	app := fiber.New()
	app.Use(func(c *fiber.Ctx) error {
		ctx := appconsumer.WithGatewayID(c.UserContext(), gw.ID)
		ctx = appgateway.WithGateway(ctx, gw)
		c.SetUserContext(ctx)
		return c.Next()
	})
	app.Use(mw.Middleware())
	app.Post("/v1/chat/completions", func(c *fiber.Ctx) error {
		return c.SendStatus(fiber.StatusOK)
	})
	return app
}

func postChat(t *testing.T, app *fiber.App) {
	t.Helper()
	resp, err := app.Test(httptest.NewRequest(fiber.MethodPost, "/v1/chat/completions", nil))
	require.NoError(t, err)
	require.Equal(t, fiber.StatusOK, resp.StatusCode)
}

func TestMetricsFunctional_DefaultPlusExtraAndTeamID(t *testing.T) {
	rec := newEventRecorder()
	gw := &gatewaydomain.Gateway{
		ID:       ids.New[ids.GatewayKind](),
		Metadata: map[string]string{gatewaydomain.MetadataTeamIDKey: "team-9"},
		Telemetry: &telemetrydomain.Telemetry{
			Exporters: []telemetrydomain.ExporterConfig{
				{Name: "memory", Settings: map[string]interface{}{"topic": "team-metrics"}},
			},
		},
	}
	app := newMetricsApp(t, gw, rec)
	postChat(t, app)

	require.Eventually(t, func() bool {
		return rec.count("kafka/"+defaultTopic) == 1 && rec.count("memory/team-metrics") == 1
	}, 2*time.Second, 10*time.Millisecond)

	assert.Equal(t, "team-9", rec.first("kafka/"+defaultTopic).TeamID)
	assert.Equal(t, "team-9", rec.first("memory/team-metrics").TeamID)
}

func TestMetricsFunctional_OverrideByNameRedirectsDefault(t *testing.T) {
	rec := newEventRecorder()
	gw := &gatewaydomain.Gateway{
		ID: ids.New[ids.GatewayKind](),
		Telemetry: &telemetrydomain.Telemetry{
			Exporters: []telemetrydomain.ExporterConfig{
				{Name: "kafka", Settings: map[string]interface{}{"topic": "custom-topic"}},
			},
		},
	}
	app := newMetricsApp(t, gw, rec)
	postChat(t, app)

	require.Eventually(t, func() bool {
		return rec.count("kafka/custom-topic") == 1
	}, 2*time.Second, 10*time.Millisecond)

	assert.Equal(t, 0, rec.count("kafka/"+defaultTopic), "override by name must redirect the default away from its topic")
}

func TestMetricsFunctional_FailingExporterDoesNotBreakOthers(t *testing.T) {
	rec := newEventRecorder()
	gw := &gatewaydomain.Gateway{
		ID: ids.New[ids.GatewayKind](),
		Telemetry: &telemetrydomain.Telemetry{
			Exporters: []telemetrydomain.ExporterConfig{
				{Name: "broken", Settings: map[string]interface{}{"topic": "whatever"}},
			},
		},
	}
	app := newMetricsApp(t, gw, rec)
	postChat(t, app)

	require.Eventually(t, func() bool {
		return rec.count("kafka/"+defaultTopic) == 1
	}, 2*time.Second, 10*time.Millisecond)
}
