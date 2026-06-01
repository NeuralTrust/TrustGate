package middleware

import (
	"context"
	"net/url"
	"time"

	appconsumer "github.com/NeuralTrust/AgentGateway/pkg/app/consumer"
	appmetrics "github.com/NeuralTrust/AgentGateway/pkg/app/metrics"
	"github.com/NeuralTrust/AgentGateway/pkg/config"
	infracontext "github.com/NeuralTrust/AgentGateway/pkg/infra/context"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/metrics"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/metrics/metric_events"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
)

// headerGatewayID is the interim gateway identity header read by the auth
// middleware's skeleton IdentityResolver. The metrics middleware sources the
// gateway from the request context (attached by the auth middleware) instead.
const headerGatewayID = "X-Gateway-Id"

type MetricsMiddleware struct {
	worker              appmetrics.Worker
	telemetryEnabled    bool
	hasDefaultExporters bool
}

func NewMetricsMiddleware(worker appmetrics.Worker, cfg *config.Config) *MetricsMiddleware {
	return &MetricsMiddleware{
		worker:              worker,
		telemetryEnabled:    cfg.Telemetry.Enabled,
		hasDefaultExporters: worker.HasDefaultExporters(),
	}
}

func (m *MetricsMiddleware) Middleware() fiber.Handler {
	return func(c *fiber.Ctx) error {
		if !m.enabled() {
			return c.Next()
		}

		startTime := time.Now()
		collector := m.newCollector(c)
		m.attachCollector(c, collector)

		gatewayID := gatewayIDFromContext(c)
		req := m.buildRequestContext(c, gatewayID)

		streamed := false
		c.Locals(infracontext.StreamMetricsFinalizerKey, m.streamFinalizer(collector, startTime, gatewayID))

		defer func() {
			if streamed {
				return
			}
			m.emit(collector, req, m.buildResponseContext(c, gatewayID), startTime, time.Now())
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
	collector *metrics.Collector,
	startTime time.Time,
	gatewayID string,
) infracontext.StreamMetricsFinalizer {
	return func(req *infracontext.RequestContext, output []byte, statusCode int, headers map[string][]string) {
		resp := &infracontext.ResponseContext{
			Context:    context.Background(),
			GatewayID:  gatewayID,
			BackendID:  req.BackendID,
			Headers:    headers,
			Body:       output,
			StatusCode: statusCode,
			Streaming:  true,
		}
		m.emit(collector, req, resp, startTime, time.Now())
	}
}

// emit synthesizes a base trace event when nothing was collected and hands the
// captured exchange to the worker for asynchronous export.
func (m *MetricsMiddleware) emit(
	collector *metrics.Collector,
	req *infracontext.RequestContext,
	resp *infracontext.ResponseContext,
	startTime, endTime time.Time,
) {
	// A future forwarder/plugin emitter may populate the collector itself; only
	// synthesize a base trace event when nothing was emitted.
	if len(collector.GetEvents()) == 0 {
		collector.Emit(metric_events.NewTraceEvent())
	}
	m.worker.Process(collector, nil, req, resp, startTime, endTime)
}

func (m *MetricsMiddleware) enabled() bool {
	return m.telemetryEnabled || m.hasDefaultExporters
}

func (m *MetricsMiddleware) newCollector(c *fiber.Ctx) *metrics.Collector {
	traceID := c.Get(fiber.HeaderXRequestID)
	if traceID == "" {
		traceID = uuid.New().String()
	}
	cfg := &metrics.Config{
		EnablePluginTraces:  false,
		EnableRequestTraces: true,
	}
	opts := []metrics.Option{metrics.WithTraceID(traceID)}
	if fpID, ok := c.Locals(string(infracontext.FingerprintIDContextKey)).(string); ok && fpID != "" {
		opts = append(opts, metrics.WithFingerprintID(fpID))
	}
	return metrics.NewCollector(cfg, opts...)
}

func (m *MetricsMiddleware) attachCollector(c *fiber.Ctx, collector *metrics.Collector) {
	c.Locals(string(metrics.CollectorKey), collector)
	ctx := context.WithValue(c.UserContext(), metrics.CollectorKey, collector)
	c.SetUserContext(ctx)
}

func (m *MetricsMiddleware) buildRequestContext(c *fiber.Ctx, gatewayID string) *infracontext.RequestContext {
	headers := make(map[string][]string)
	for key, values := range c.GetReqHeaders() {
		headers[key] = append(headers[key], values...)
	}

	query := url.Values{}
	c.Context().QueryArgs().VisitAll(func(key, value []byte) {
		query.Add(string(key), string(value))
	})

	return &infracontext.RequestContext{
		Context:   context.Background(),
		GatewayID: gatewayID,
		Headers:   headers,
		Method:    c.Method(),
		Path:      c.Path(),
		Query:     query,
		Body:      append([]byte(nil), c.Body()...),
		IP:        c.IP(),
	}
}

func gatewayIDFromContext(c *fiber.Ctx) string {
	if id, ok := appconsumer.GatewayIDFromContext(c.UserContext()); ok {
		return id.String()
	}
	return ""
}

func (m *MetricsMiddleware) buildResponseContext(c *fiber.Ctx, gatewayID string) *infracontext.ResponseContext {
	headers := make(map[string][]string)
	for key, values := range c.GetRespHeaders() {
		headers[key] = append(headers[key], values...)
	}

	return &infracontext.ResponseContext{
		Context:    context.Background(),
		GatewayID:  gatewayID,
		Headers:    headers,
		Body:       append([]byte(nil), c.Response().Body()...),
		StatusCode: c.Response().StatusCode(),
		Streaming:  false,
	}
}
