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

package middleware

import (
	"net/url"
	"strings"
	"time"

	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	appgateway "github.com/NeuralTrust/TrustGate/pkg/app/gateway"
	appmetrics "github.com/NeuralTrust/TrustGate/pkg/app/metrics"
	"github.com/NeuralTrust/TrustGate/pkg/config"
	gatewaydomain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	telemetrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/telemetry"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/NeuralTrust/TrustGate/pkg/infra/trace"
	"github.com/gofiber/fiber/v2"
)

type MetricsMiddleware struct {
	worker              appmetrics.Worker
	telemetryEnabled    bool
	enableRequestTraces bool
	enablePluginTraces  bool
}

func NewMetricsMiddleware(worker appmetrics.Worker, cfg *config.Config) *MetricsMiddleware {
	return &MetricsMiddleware{
		worker:              worker,
		telemetryEnabled:    cfg.Telemetry.Enabled,
		enableRequestTraces: cfg.Telemetry.EnableRequestTraces,
		enablePluginTraces:  cfg.Telemetry.EnablePluginTraces,
	}
}

func (m *MetricsMiddleware) Middleware() fiber.Handler {
	return func(c *fiber.Ctx) error {
		if !m.enabled() {
			return c.Next()
		}

		startTime := time.Now()
		gatewayID := gatewayIDFromContext(c)
		gw := gatewayFromContext(c)
		exporters := gatewayExporters(gw)

		traceID := newTraceID()
		c.Set(HeaderTraceID, traceID)
		requestTrace := trace.New(traceID, m.buildTraceMetadata(c, gatewayID, gw))
		// Gating is set once here, before the trace is shared with any
		// downstream goroutine (forwarder, plugins, finalizer).
		requestTrace.SetGating(m.enableRequestTraces, m.enablePluginTraces)
		m.attachTrace(c, requestTrace)

		req := m.buildRequestContext(c, gatewayID)

		streamed := false
		c.Locals(infracontext.StreamMetricsFinalizerKey, m.streamFinalizer(requestTrace, startTime, gatewayID, exporters))

		defer func() {
			if streamed {
				return
			}
			resp := m.buildResponseContext(c, gatewayID)
			endTime := time.Now()
			requestTrace.OnComplete(func() {
				m.worker.Process(requestTrace, req, resp, startTime, endTime, exporters)
			})
			requestTrace.Done()
		}()

		err := c.Next()

		if owned, _ := c.Locals(infracontext.StreamMetricsOwnedKey).(bool); owned {
			streamed = true
		}
		return err
	}
}

// streamFinalizer returns the StreamMetricsFinalizer the proxy stream writer
// calls after a streamed response is fully written.
func (m *MetricsMiddleware) streamFinalizer(
	requestTrace *trace.RequestTrace,
	startTime time.Time,
	gatewayID string,
	exporters []telemetrydomain.ExporterConfig,
) infracontext.StreamMetricsFinalizer {
	return func(req *infracontext.RequestContext, output []byte, statusCode int, headers map[string][]string) {
		resp := &infracontext.ResponseContext{
			GatewayID:  gatewayID,
			RegistryID: req.RegistryID,
			Headers:    cloneStreamHeaders(headers),
			Body:       append([]byte(nil), output...),
			StatusCode: statusCode,
			Streaming:  true,
		}
		endTime := time.Now()
		requestTrace.OnComplete(func() {
			m.worker.Process(requestTrace, req, resp, startTime, endTime, exporters)
		})
		requestTrace.Done()
	}
}

func (m *MetricsMiddleware) enabled() bool {
	return m.telemetryEnabled
}

func (m *MetricsMiddleware) attachTrace(c *fiber.Ctx, requestTrace *trace.RequestTrace) {
	c.SetUserContext(trace.NewContext(c.UserContext(), requestTrace))
}

func (m *MetricsMiddleware) buildTraceMetadata(c *fiber.Ctx, gatewayID string, gw *gatewaydomain.Gateway) trace.Metadata {
	meta := trace.Metadata{
		GatewayID: gatewayID,
		TenantID:  gw.TenantID(),
		Path:      strings.Clone(c.Path()),
		Method:    strings.Clone(c.Method()),
		IP:        strings.Clone(c.IP()),
	}
	if window, ok := gw.RetentionWindow(); ok {
		meta.RetentionWindow = window
		meta.RetentionPlan = gw.Entitlements.Tier
	}
	if sessionID, ok := c.Locals(string(infracontext.SessionContextKey)).(string); ok {
		meta.SessionID = strings.Clone(sessionID)
	}
	return meta
}

func (m *MetricsMiddleware) buildRequestContext(c *fiber.Ctx, gatewayID string) *infracontext.RequestContext {
	headers := make(map[string][]string)
	for key, value := range c.Request().Header.All() {
		name := string(key)
		headers[name] = append(headers[name], string(value))
	}

	query := url.Values{}
	for key, value := range c.Context().QueryArgs().All() {
		query.Add(string(key), string(value))
	}

	req := &infracontext.RequestContext{
		GatewayID: gatewayID,
		Headers:   headers,
		Method:    strings.Clone(c.Method()),
		Path:      strings.Clone(c.Path()),
		Query:     query,
		Body:      append([]byte(nil), c.Body()...),
		IP:        strings.Clone(c.IP()),
	}
	stampRequestTarget(c, req)
	return req
}

func gatewayIDFromContext(c *fiber.Ctx) string {
	if id, ok := appconsumer.GatewayIDFromContext(c.UserContext()); ok {
		return id.String()
	}
	return ""
}

func gatewayFromContext(c *fiber.Ctx) *gatewaydomain.Gateway {
	gw, ok := appgateway.FromContext(c.UserContext())
	if !ok {
		return nil
	}
	return gw
}

func gatewayExporters(gw *gatewaydomain.Gateway) []telemetrydomain.ExporterConfig {
	if gw == nil || gw.Telemetry == nil {
		return nil
	}
	return gw.Telemetry.Exporters
}

func (m *MetricsMiddleware) buildResponseContext(c *fiber.Ctx, gatewayID string) *infracontext.ResponseContext {
	headers := make(map[string][]string)
	for key, value := range c.Response().Header.All() {
		name := string(key)
		headers[name] = append(headers[name], string(value))
	}

	return &infracontext.ResponseContext{
		GatewayID:  gatewayID,
		Headers:    headers,
		Body:       append([]byte(nil), c.Response().Body()...),
		StatusCode: c.Response().StatusCode(),
		Streaming:  false,
	}
}

func cloneStreamHeaders(headers map[string][]string) map[string][]string {
	owned := make(map[string][]string, len(headers))
	for name, values := range headers {
		key := strings.Clone(name)
		for _, value := range values {
			owned[key] = append(owned[key], strings.Clone(value))
		}
	}
	return owned
}
