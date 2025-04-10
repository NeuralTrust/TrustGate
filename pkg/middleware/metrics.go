package middleware

import (
	"context"
	"fmt"
	"net/url"
	"strconv"
	"time"

	appTelemetry "github.com/NeuralTrust/TrustGate/pkg/app/telemetry"
	"github.com/NeuralTrust/TrustGate/pkg/common"
	"github.com/NeuralTrust/TrustGate/pkg/infra/metrics"
	"github.com/NeuralTrust/TrustGate/pkg/infra/prometheus"
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
	logger           *logrus.Logger
	providersBuilder appTelemetry.ExportersBuilder
	taskChan         chan func()
	elapsedTime      time.Duration
}

func NewMetricsMiddleware(logger *logrus.Logger, providersBuilder appTelemetry.ExportersBuilder) Middleware {
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

		m.elapsedTime = time.Since(startTime)

		outputResponse := m.transformToResponseContext(c, gatewayID)
		method := c.Method()
		statusCode := c.Response().StatusCode()

		m.enqueueTask(func() {
			m.registryMetricsToPrometheus(method, gatewayID, statusCode)
		}, gatewayID)
		m.enqueueTask(func() {
			m.executeMetricsHandlers(metricsCollector, gatewayData, inputRequest, outputResponse)
		}, gatewayID)

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

func (m *metricsMiddleware) getStatusClass(status string) string {
	code, err := strconv.Atoi(status)
	if err != nil {
		return "5xx" // Return server error class if status code is invalid
	}
	return fmt.Sprintf("%dxx", code/100)
}

func (m *metricsMiddleware) executeMetricsHandlers(
	collector *metrics.Collector,
	gatewayData *types.GatewayData,
	req *types.RequestContext,
	resp *types.ResponseContext,
) {
	exporters, err := m.providersBuilder.Build(gatewayData.Gateway.Telemetry.Exporters)
	if err != nil {
		m.logger.WithError(err).Error("failed to build telemetry providers")
		return
	}

	events := collector.Flush()

	for _, exporter := range exporters {
		for _, metricsEvent := range events {
			err = exporter.Handle(context.Background(), m.feedEvent(metricsEvent, req, resp))
			if err != nil {
				m.logger.
					WithField("gatewayID", gatewayData.Gateway.ID).
					WithError(err).
					Error(fmt.Sprintf("failed to provide metrics to %s", exporter.Name()))
			}
		}
	}

	m.logger.WithFields(logrus.Fields{
		"gatewayID":  gatewayData.Gateway.ID,
		"eventCount": len(events),
		"exporters":  len(exporters),
	}).Debug("all metrics processed")
}

func (m *metricsMiddleware) feedEvent(
	evt *metrics.Event,
	req *types.RequestContext,
	resp *types.ResponseContext,
) *metrics.Event {
	evt.Latency = m.elapsedTime.Milliseconds()
	return evt
}

func (m *metricsMiddleware) registryMetricsToPrometheus(method, gatewayID string, statusCode int) {
	if prometheus.Config.EnableConnections {
		prometheus.GatewayConnections.WithLabelValues(gatewayID, "active").Inc()
	}
	status := m.getStatusClass(strconv.Itoa(statusCode))
	prometheus.GatewayRequestTotal.WithLabelValues(
		gatewayID,
		method,
		status,
	).Inc()
	if prometheus.Config.EnableConnections {
		prometheus.GatewayConnections.WithLabelValues(gatewayID, "active").Dec()
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

func (m *metricsMiddleware) enqueueTask(task func(), gatewayID string) {
	select {
	case m.taskChan <- task:
	default:
		m.logger.WithField("gatewayID", gatewayID).
			Warn("taskChan is full, dropping metrics task")
	}
}
