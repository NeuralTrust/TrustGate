package middleware

import (
	"bytes"
	"context"
	"net/url"
	"strings"
	"sync"
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
		gatewayData, ok := c.Locals(string(common.GatewayDataContextKey)).(*types.GatewayData)
		if !ok {
			m.logger.
				WithField("gatewayID", gatewayID).
				Error("gateway data not found in context (metrics middleware)")
			return c.Next()
		}

		streamResponse := make(chan []byte)
		streamMode := make(chan bool, 1)
		defer close(streamMode)

		var streamResponseBody bytes.Buffer
		var streamDetected bool

		metricsCollector := m.getMetricsCollector(gatewayData)

		c.Locals(common.StreamResponseContextKey, streamResponse)
		c.Locals(common.StreamModeContextKey, streamMode)
		c.Locals(string(metrics.CollectorKey), metricsCollector)
		ctx := context.WithValue(c.Context(), string(metrics.CollectorKey), metricsCollector) //nolint
		ctx = context.WithValue(ctx, common.StreamResponseContextKey, streamResponse)
		ctx = context.WithValue(ctx, common.StreamModeContextKey, streamMode)
		c.SetUserContext(ctx)

		userAgentInfo := utils.ParseUserAgent(m.getUserAgent(c), m.getAcceptLanguage(c))

		m.setTelemetryHeaders(c, gatewayData)
		inputRequest := m.transformToRequestContext(c, gatewayID, userAgentInfo)

		startTime, ok := c.Locals(common.LatencyContextKey).(time.Time)
		if !ok {
			m.logger.Error("start_time not found in context")
			startTime = time.Now()
		}

		// TODO metrics for websockets
		if strings.Contains(c.Path(), "/ws/") {
			return c.Next()
		}

		wg := &sync.WaitGroup{}
		wg.Add(1)
		go func() {
			defer wg.Done()
			select {
			case mode := <-streamMode:
				if mode {
					streamDetected = true
				}
			case <-time.After(30 * time.Second):
				m.logger.Warn("timeout waiting for stream mode signal")
			}
		}()

		err := c.Next()

		var sessionID string
		sessionID, ok = ctx.Value(common.SessionContextKey).(string)
		if !ok || sessionID == "" {
			m.logger.Error("session ID not found in context")
		}

		inputRequest.SessionID = sessionID

		rule, ok := ctx.Value(common.MatchedRuleContextKey).(*types.ForwardingRule)
		if !ok || rule == nil {
			m.logger.Error("failed to get matched rule from context")
			rule = &types.ForwardingRule{}
		}

		var exporters []types.Exporter
		if gatewayData.Gateway.Telemetry != nil {
			exporters = gatewayData.Gateway.Telemetry.Exporters
		}

		headers := make(map[string][]string)
		for key, values := range c.GetRespHeaders() {
			headers[key] = values
		}
		statusCode := c.Response().StatusCode()
		wg.Wait()

		endTime := time.Now()
		var once sync.Once
		if streamDetected {
			go func() {
				startTimeStream := time.Now()
				var lastLine []byte
				for line := range streamResponse {
					if len(line) > 0 {
						lastLine = line
						_, err := streamResponseBody.Write(line)
						if err != nil {
							m.logger.WithError(err).Error("error writing to stream buffer")
						}
					}
				}
				streamDuration := float64(time.Since(startTimeStream).Microseconds()) / 1000
				once.Do(func() {
					m.logger.Debug("stream channel closed")
					now := time.Now()
					m.worker.Process(
						metricsCollector,
						exporters,
						inputRequest,
						types.ResponseContext{
							Context:   context.Background(),
							GatewayID: gatewayID,
							Headers:   headers,
							Metadata: map[string]interface{}{
								"lastOutputLine": lastLine,
							},
							Body:          streamResponseBody.Bytes(),
							StatusCode:    statusCode,
							ProcessAt:     &now,
							Rule:          rule, // rule is already checked for nil above
							TargetLatency: streamDuration,
							Streaming:     true,
						},
						startTime,
						time.Now(),
					)
				})
			}()
			return err
		}

		outputResponse := m.transformToResponseContext(c, gatewayID, *rule)
		m.logger.Debug("processing metrics as non stream mode")
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
) types.RequestContext {
	now := time.Now()
	reqCtx := types.RequestContext{
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

func (m *metricsMiddleware) transformToResponseContext(
	c *fiber.Ctx,
	gatewayID string,
	rule types.ForwardingRule,
) types.ResponseContext {
	now := time.Now()
	reqCtx := types.ResponseContext{
		Context:    context.Background(),
		GatewayID:  gatewayID,
		Headers:    make(map[string][]string),
		Metadata:   nil,
		Body:       c.Response().Body(),
		StatusCode: c.Response().StatusCode(),
		Rule:       &rule,
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
