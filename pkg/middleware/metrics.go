package middleware

import (
	"context"
	"fmt"
	"net/url"
	"strconv"
	"time"

	appTelemetry "github.com/NeuralTrust/TrustGate/pkg/app/telemetry"
	"github.com/NeuralTrust/TrustGate/pkg/common"
	"github.com/NeuralTrust/TrustGate/pkg/metrics"
	"github.com/NeuralTrust/TrustGate/pkg/types"
	"github.com/NeuralTrust/TrustGate/pkg/utils"
	"github.com/gofiber/fiber/v2"
	"github.com/sirupsen/logrus"
)

const (
	ServiceIDKey = "service_id"
	RouteIDKey   = "route_id"
)

type metricsMiddleware struct {
	logger           *logrus.Logger
	providersBuilder appTelemetry.ProvidersBuilder
	taskChan         chan func()
}

func NewMetricsMiddleware(logger *logrus.Logger, providersBuilder appTelemetry.ProvidersBuilder) Middleware {
	m := &metricsMiddleware{
		logger:           logger,
		providersBuilder: providersBuilder,
		taskChan:         make(chan func(), 1000),
	}
	go m.startWorkers(5)
	return m
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

		userAgentInfo := utils.ParseUserAgent(m.getUserAgent(c), m.getAcceptLanguage(c))
		inputRequest := m.transformToRequestContext(c, gatewayID, userAgentInfo)

		err := c.Next()

		outputResponse := m.transformToResponseContext(c, gatewayID)
		method := c.Method()
		statusCode := c.Response().StatusCode()

		m.taskChan <- func() {
			m.registryMetricsToPrometheus(method, gatewayID, statusCode)
		}
		m.taskChan <- func() {
			m.executeMetricsHandlers(gatewayData, inputRequest, outputResponse)
		}
		return err
	}
}

func (m *metricsMiddleware) getUserAgent(ctx *fiber.Ctx) string {
	return ctx.Get("User-Agent")
}

func (m *metricsMiddleware) getAcceptLanguage(ctx *fiber.Ctx) string {
	return ctx.Get("Accept-Language")
}

func (m *metricsMiddleware) startWorkers(n int) {
	for i := 0; i < n; i++ {
		go func() {
			for task := range m.taskChan {
				task()
			}
		}()
	}
}

// GetStatusClass returns either the specific status code or its class (e.g., "2xx")
func (m *metricsMiddleware) getStatusClass(status string) string {
	code, err := strconv.Atoi(status)
	if err != nil {
		return "5xx" // Return server error class if status code is invalid
	}
	return fmt.Sprintf("%dxx", code/100)
}

func (m *metricsMiddleware) executeMetricsHandlers(
	gatewayData *types.GatewayData,
	req *types.RequestContext,
	resp *types.ResponseContext,
) {
	providers, err := m.providersBuilder.Build(gatewayData.Gateway.Telemetry.Configs)
	if err != nil {
		m.logger.WithError(err).Error("failed to build telemetry providers")
		return
	}
	for _, provider := range providers {
		err := provider.Handle(context.Background(), req, resp)
		if err != nil {
			m.logger.
				WithField("gatewayID", gatewayData.Gateway.ID).
				WithError(err).Error(fmt.Sprintf("failed to provide metrics to %s", provider.Name()))
		}
		m.logger.
			WithField("gatewayID", gatewayData.Gateway.ID).
			Info(fmt.Sprintf("metrics sent to provider %s", provider.Name()))
	}
}

func (m *metricsMiddleware) registryMetricsToPrometheus(method, gatewayID string, statusCode int) {
	if metrics.Config.EnableConnections {
		metrics.GatewayConnections.WithLabelValues(gatewayID, "active").Inc()
	}
	status := m.getStatusClass(strconv.Itoa(statusCode))
	metrics.GatewayRequestTotal.WithLabelValues(
		gatewayID,
		method,
		status,
	).Inc()
	if metrics.Config.EnableConnections {
		metrics.GatewayConnections.WithLabelValues(gatewayID, "active").Dec()
	}
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
