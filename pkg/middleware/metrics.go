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

		metricsCollector := metrics.NewCollector(
			uuid.New().String(),
			&metrics.Config{
				EnablePluginTraces:  gatewayData.Gateway.Telemetry.EnablePluginTraces,
				EnableRequestTraces: gatewayData.Gateway.Telemetry.EnableRequestTraces,
				ExtraParams:         gatewayData.Gateway.Telemetry.ExtraParams,
			})

		c.Locals(metrics.CollectorKey, metricsCollector)
		ctx := context.WithValue(c.Context(), metrics.CollectorKey, metricsCollector)
		c.SetUserContext(ctx)

		userAgentInfo := utils.ParseUserAgent(m.getUserAgent(c), m.getAcceptLanguage(c))

		inputRequest := m.transformToRequestContext(c, gatewayID, userAgentInfo)

		startTime, ok := c.Locals(common.LatencyContextKey).(time.Time)
		if !ok {
			m.logger.Error("start_time not found in context")
			startTime = time.Now()
		}

		err := c.Next()
		endTime := time.Now()
		outputResponse := m.transformToResponseContext(c, gatewayID)

		m.worker.Process(
			metricsCollector,
			gatewayData.Gateway.Telemetry.Exporters,
			inputRequest,
			outputResponse,
			startTime,
			endTime,
		)

		return err
	}
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
