package middleware

import (
	"context"
	"net/url"
	"time"

	appconsumer "github.com/NeuralTrust/AgentGateway/pkg/app/consumer"
	appmetrics "github.com/NeuralTrust/AgentGateway/pkg/app/metrics"
	"github.com/NeuralTrust/AgentGateway/pkg/config"
	infracontext "github.com/NeuralTrust/AgentGateway/pkg/infra/context"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/trace"
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
	enableRequestTraces bool
	enablePluginTraces  bool
}

func NewMetricsMiddleware(worker appmetrics.Worker, cfg *config.Config) *MetricsMiddleware {
	return &MetricsMiddleware{
		worker:              worker,
		telemetryEnabled:    cfg.Telemetry.Enabled,
		hasDefaultExporters: worker.HasDefaultExporters(),
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

		traceID := m.resolveTraceID(c)
		requestTrace := trace.New(traceID, m.buildTraceMetadata(c, gatewayID))
		// Gating is set once here, before the trace is shared with any
		// downstream goroutine (forwarder, plugins, finalizer).
		requestTrace.SetGating(m.enableRequestTraces, m.enablePluginTraces)
		m.attachTrace(c, requestTrace)

		req := m.buildRequestContext(c, gatewayID)

		streamed := false
		c.Locals(infracontext.StreamMetricsFinalizerKey, m.streamFinalizer(requestTrace, startTime, gatewayID))

		defer func() {
			if streamed {
				return
			}
			resp := m.buildResponseContext(c, gatewayID)
			endTime := time.Now()
			requestTrace.OnComplete(func() {
				m.worker.Process(nil, requestTrace, req, resp, startTime, endTime)
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
		endTime := time.Now()
		requestTrace.OnComplete(func() {
			m.worker.Process(nil, requestTrace, req, resp, startTime, endTime)
		})
		requestTrace.Done()
	}
}

func (m *MetricsMiddleware) enabled() bool {
	return m.telemetryEnabled || m.hasDefaultExporters
}

func (m *MetricsMiddleware) resolveTraceID(c *fiber.Ctx) string {
	traceID := c.Get(fiber.HeaderXRequestID)
	if traceID == "" {
		traceID = uuid.New().String()
	}
	return traceID
}

func (m *MetricsMiddleware) attachTrace(c *fiber.Ctx, requestTrace *trace.RequestTrace) {
	c.SetUserContext(trace.NewContext(c.UserContext(), requestTrace))
}

func (m *MetricsMiddleware) buildTraceMetadata(c *fiber.Ctx, gatewayID string) trace.Metadata {
	meta := trace.Metadata{
		GatewayID: gatewayID,
		Path:      c.Path(),
		Method:    c.Method(),
		IP:        c.IP(),
	}
	if sessionID, ok := c.Locals(string(infracontext.SessionContextKey)).(string); ok {
		meta.SessionID = sessionID
	}
	if fpID, ok := c.Locals(string(infracontext.FingerprintIDContextKey)).(string); ok {
		meta.FingerprintID = fpID
	}
	return meta
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
