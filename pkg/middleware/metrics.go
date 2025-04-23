package middleware

import (
	"context"
	"net/url"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/common"
	"github.com/NeuralTrust/TrustGate/pkg/infra/metrics"
	"github.com/NeuralTrust/TrustGate/pkg/types"
	"github.com/NeuralTrust/TrustGate/pkg/utils"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

const (
	ServiceIDKey = "service_id"
	RouteIDKey   = "route_id"
)

type metricsMiddleware struct {
	logger *logrus.Logger
	worker metrics.Worker
}

func NewMetricsMiddleware(logger *logrus.Logger, worker metrics.Worker) Middleware {
	return &metricsMiddleware{
		logger: logger,
		worker: worker,
	}
}

func (m *metricsMiddleware) Middleware() fiber.Handler {
	return func(c *fiber.Ctx) error {
		gatewayID, ok := c.Locals(common.GatewayContextKey).(string)
		if !ok || gatewayID == "" {
			m.logger.Error("Gateway ID not found in context")
			return c.Next()
		}
		gatewayData, ok := c.Locals(common.GatewayDataContextKey).(*types.GatewayData)
		if !ok {
			m.logger.
				WithField("gatewayID", gatewayID).
				Error("gateway data not found in context (metrics middleware)")
			return c.Next()
		}

		metricsCollector := m.getMetricsCollector(gatewayData)

		c.Locals(metrics.CollectorKey, metricsCollector)
		ctx := context.WithValue(c.Context(), metrics.CollectorKey, metricsCollector)
		c.SetUserContext(ctx)

		userAgentInfo := utils.ParseUserAgent(m.getUserAgent(c), m.getAcceptLanguage(c))

		m.setTelemetryHeaders(c, gatewayData)
		inputRequest := m.transformToRequestContext(c, gatewayID, userAgentInfo)

		startTime, ok := c.Locals(common.LatencyContextKey).(time.Time)
		if !ok {
			m.logger.Error("start_time not found in context")
			startTime = time.Now()
		}

		err := c.Next()
		endTime := time.Now()
		outputResponse := m.transformToResponseContext(c, gatewayID)

		var exporters []types.Exporter
		if gatewayData.Gateway.Telemetry != nil {
			exporters = gatewayData.Gateway.Telemetry.Exporters
		}
		m.worker.Process(
			metricsCollector,
			exporters,
			inputRequest,
			outputResponse,
			startTime,
			endTime,
		)
		return err
	}
}

func (m *metricsMiddleware) getMetricsCollector(gatewayData *types.GatewayData) *metrics.Collector {
	metricsCollector := metrics.NewCollector(
		uuid.New().String(),
		&metrics.Config{
			EnablePluginTraces:  false,
			EnableRequestTraces: false,
			ExtraParams:         nil,
		},
	)
	if gatewayData.Gateway.Telemetry != nil {
		metricsCollector = metrics.NewCollector(
			uuid.New().String(),
			&metrics.Config{
				EnablePluginTraces:  gatewayData.Gateway.Telemetry.EnablePluginTraces,
				EnableRequestTraces: gatewayData.Gateway.Telemetry.EnableRequestTraces,
				ExtraParams:         gatewayData.Gateway.Telemetry.ExtraParams,
			})
	}
	return metricsCollector
}

func (m *metricsMiddleware) getUserAgent(ctx *fiber.Ctx) string {
	return ctx.Get("User-Agent")
}

func (m *metricsMiddleware) getAcceptLanguage(ctx *fiber.Ctx) string {
	return ctx.Get("Accept-Language")
}

func (m *metricsMiddleware) transformToRequestContext(
	c *fiber.Ctx,
	gatewayID string,
	userAgentInfo *utils.UserAgentInfo,
) *types.RequestContext {
	now := time.Now()
	reqCtx := &types.RequestContext{
		Context:   context.Background(),
		GatewayID: gatewayID,
		Headers:   make(map[string][]string),
		Method:    c.Method(),
		Path:      c.Path(),
		Query:     m.getQueryParams(c),
		Metadata: map[string]interface{}{
			"user_agent_info": userAgentInfo,
		},
		Body:      c.Request().Body(),
		ProcessAt: &now,
		IP:        utils.ExtractIP(c),
	}
	for key, values := range c.GetReqHeaders() {
		reqCtx.Headers[key] = values
	}

	if conversationID, ok := c.Locals(common.ConversationIDHeader).(string); ok && conversationID != "" {
		reqCtx.Headers[common.ConversationIDHeader] = []string{conversationID}
	}
	if interactionID, ok := c.Locals(common.InteractionIDHeader).(string); ok && interactionID != "" {
		reqCtx.Headers[common.InteractionIDHeader] = []string{interactionID}
	}

	return reqCtx
}

func (m *metricsMiddleware) transformToResponseContext(c *fiber.Ctx, gatewayID string) *types.ResponseContext {
	now := time.Now()
	reqCtx := &types.ResponseContext{
		Context:    context.Background(),
		GatewayID:  gatewayID,
		Headers:    make(map[string][]string),
		Metadata:   nil,
		Body:       c.Response().Body(),
		StatusCode: c.Response().StatusCode(),
		ProcessAt:  &now,
	}
	for key, values := range c.GetRespHeaders() {
		reqCtx.Headers[key] = values
	}
	return reqCtx
}

func (m *metricsMiddleware) getQueryParams(c *fiber.Ctx) url.Values {
	queryParams := make(url.Values)
	c.Request().URI().QueryArgs().VisitAll(func(k, v []byte) {
		queryParams.Set(string(k), string(v))
	})
	return queryParams
}

func (m *metricsMiddleware) setTelemetryHeaders(c *fiber.Ctx, gatewayData *types.GatewayData) {
	mapping := make(map[string]string)
	if gatewayData.Gateway != nil &&
		gatewayData.Gateway.Telemetry != nil &&
		gatewayData.Gateway.Telemetry.HeaderMapping != nil {
		mapping = gatewayData.Gateway.Telemetry.HeaderMapping
	}

	setHeaderLocal := func(mappingKey, defaultHeader string) {
		headerKey, ok := mapping[mappingKey]
		if !ok {
			headerKey = defaultHeader
		}
		if value := c.Get(headerKey); value != "" {
			c.Locals(defaultHeader, value)
		}
	}

	setHeaderLocal("conversation_id", common.ConversationIDHeader)

	interactionIDHeaderKey, ok := mapping["interaction_id"]
	if !ok {
		interactionIDHeaderKey = common.InteractionIDHeader
	}

	if value := c.Get(interactionIDHeaderKey); value != "" {
		c.Locals(common.InteractionIDHeader, value)
	} else {
		c.Locals(common.InteractionIDHeader, uuid.New().String())
	}
}
