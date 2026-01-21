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
	ServiceIDKey      = "service_id"
	RouteIDKey        = "route_id"
	streamModeTimeout = 30 * time.Second
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
		gatewayID, gatewayData, err := m.extractGatewayContext(c)
		if err != nil {
			return c.Next()
		}

		// Skip metrics for websockets
		if strings.Contains(c.Path(), "/ws/") {
			return c.Next()
		}

		ctx := m.initializeContext(c, gatewayData)
		telemetryEnabled := m.isTelemetryEnabled(gatewayData)

		var (
			inputRequest types.RequestContext
			startTime    time.Time
		)

		if telemetryEnabled {
			m.setTelemetryHeaders(c, gatewayData)
			inputRequest = m.buildRequestContext(c, gatewayID)
			startTime = m.getStartTime(c)
		}

		stream := m.initStreamState(c)
		defer stream.cleanup()

		go stream.waitForMode(m.logger)

		nextErr := c.Next()

		stream.wait()

		if stream.isStreaming() {
			m.handleStreamResponse(ctx, gatewayID, gatewayData, inputRequest, c, startTime, stream, telemetryEnabled)
			return nextErr
		}

		if telemetryEnabled {
			m.handleNonStreamResponse(ctx, gatewayID, gatewayData, inputRequest, c, startTime)
		}

		return nextErr
	}
}

// extractGatewayContext retrieves gateway ID and data from the fiber context
func (m *metricsMiddleware) extractGatewayContext(c *fiber.Ctx) (string, *types.GatewayData, error) {
	gatewayID, ok := c.Locals(common.GatewayContextKey).(string)
	if !ok || gatewayID == "" {
		m.logger.Error("gatewayDTO ID not found in context")
		return "", nil, fiber.ErrNotFound
	}
	gatewayData, ok := c.Locals(string(common.GatewayDataContextKey)).(*types.GatewayData)
	if !ok {
		m.logger.WithField("gatewayID", gatewayID).Error("gateway data not found in context (metrics middleware)")
		return "", nil, fiber.ErrNotFound
	}
	return gatewayID, gatewayData, nil
}

// initializeContext sets up the trace ID, metrics collector, and stream channels in the context
func (m *metricsMiddleware) initializeContext(c *fiber.Ctx, gatewayData *types.GatewayData) context.Context {
	traceID := uuid.New().String()
	fingerprintID, _ := c.Locals(common.FingerprintIdContextKey).(string)
	collector := m.createMetricsCollector(traceID, fingerprintID, gatewayData)

	streamResponse := make(chan []byte)
	streamMode := make(chan bool, 1)

	c.Locals(common.TraceIdKey, traceID)
	c.Locals(common.StreamResponseContextKey, streamResponse)
	c.Locals(common.StreamModeContextKey, streamMode)
	c.Locals(string(metrics.CollectorKey), collector)

	ctx := context.WithValue(c.Context(), string(metrics.CollectorKey), collector) //nolint
	ctx = context.WithValue(ctx, common.StreamResponseContextKey, streamResponse)
	ctx = context.WithValue(ctx, common.StreamModeContextKey, streamMode)
	ctx = context.WithValue(ctx, common.TraceIdKey, traceID)

	c.SetUserContext(ctx)

	return ctx
}

// createMetricsCollector creates a metrics collector with the appropriate configuration
func (m *metricsMiddleware) createMetricsCollector(traceID, fingerprintID string, gatewayData *types.GatewayData) *metrics.Collector {
	if traceID == "" {
		traceID = uuid.New().String()
	}

	config := &metrics.Config{
		EnablePluginTraces:  false,
		EnableRequestTraces: false,
		ExtraParams:         nil,
	}

	if gatewayData.Gateway.Telemetry != nil {
		config.EnablePluginTraces = gatewayData.Gateway.Telemetry.EnablePluginTraces
		config.EnableRequestTraces = gatewayData.Gateway.Telemetry.EnableRequestTraces
		config.ExtraParams = gatewayData.Gateway.Telemetry.ExtraParams
	}

	return metrics.NewCollector(
		config,
		metrics.WithTraceID(traceID),
		metrics.WithFingerprintID(fingerprintID),
	)
}

// isTelemetryEnabled checks if telemetry is enabled for the gateway
func (m *metricsMiddleware) isTelemetryEnabled(gatewayData *types.GatewayData) bool {
	if gatewayData.Gateway == nil || gatewayData.Gateway.Telemetry == nil {
		return false
	}

	telemetry := gatewayData.Gateway.Telemetry
	return telemetry.EnablePluginTraces ||
		telemetry.EnableRequestTraces ||
		len(telemetry.Exporters) > 0
}

// getStartTime retrieves the start time from context or returns current time
func (m *metricsMiddleware) getStartTime(c *fiber.Ctx) time.Time {
	startTime, ok := c.Locals(common.LatencyContextKey).(time.Time)
	if !ok {
		m.logger.Error("start_time not found in context")
		return time.Now()
	}
	return startTime
}

// buildRequestContext creates a RequestContext from the fiber context
func (m *metricsMiddleware) buildRequestContext(c *fiber.Ctx, gatewayID string) types.RequestContext {
	userAgentInfo := utils.ParseUserAgent(c.Get("User-Agent"), c.Get("Accept-Language"))
	now := time.Now()

	reqCtx := types.RequestContext{
		Context:   context.Background(),
		GatewayID: gatewayID,
		Headers:   m.copyHeaders(c.GetReqHeaders()),
		Method:    c.Method(),
		Path:      string([]byte(c.Path())), // clone to avoid mutation
		Query:     m.getQueryParams(c),
		Metadata: map[string]interface{}{
			"user_agent_info": userAgentInfo,
		},
		Body:      append([]byte(nil), c.Request().Body()...),
		ProcessAt: &now,
		IP:        utils.ExtractIP(c),
	}

	if conversationID, ok := c.Locals(common.ConversationIDHeader).(string); ok && conversationID != "" {
		reqCtx.Headers[common.ConversationIDHeader] = []string{conversationID}
	}
	if interactionID, ok := c.Locals(common.InteractionIDHeader).(string); ok && interactionID != "" {
		reqCtx.Headers[common.InteractionIDHeader] = []string{interactionID}
	}

	return reqCtx
}

// handleStreamResponse processes metrics for streaming responses
func (m *metricsMiddleware) handleStreamResponse(
	ctx context.Context,
	gatewayID string,
	gatewayData *types.GatewayData,
	inputRequest types.RequestContext,
	c *fiber.Ctx,
	startTime time.Time,
	state *streamState,
	telemetryEnabled bool,
) {
	if !telemetryEnabled {
		return
	}

	inputRequest.SessionID = m.getSessionID(ctx)
	exporters := gatewayData.Gateway.Telemetry.Exporters
	rule := m.getMatchedRule(ctx)
	headers := m.copyHeaders(c.GetRespHeaders())
	statusCode := c.Response().StatusCode()
	collector := m.getCollectorFromContext(c)

	go func() {
		streamStartTime := time.Now()
		responseBody, lastLine := state.collectStreamData(m.logger)
		streamDuration := float64(time.Since(streamStartTime).Microseconds()) / 1000

		m.logger.Debug("stream channel closed")
		now := time.Now()

		m.worker.Process(
			collector,
			exporters,
			inputRequest,
			types.ResponseContext{
				Context:   context.Background(),
				GatewayID: gatewayID,
				Headers:   headers,
				Metadata: map[string]interface{}{
					"lastOutputLine": lastLine,
				},
				Body:          responseBody,
				StatusCode:    statusCode,
				ProcessAt:     &now,
				Rule:          rule,
				TargetLatency: streamDuration,
				Streaming:     true,
			},
			startTime,
			time.Now(),
		)
	}()
}

// handleNonStreamResponse processes metrics for non-streaming responses
func (m *metricsMiddleware) handleNonStreamResponse(
	ctx context.Context,
	gatewayID string,
	gatewayData *types.GatewayData,
	inputRequest types.RequestContext,
	c *fiber.Ctx,
	startTime time.Time,
) {
	inputRequest.SessionID = m.getSessionID(ctx)
	rule := m.getMatchedRule(ctx)
	collector := m.getCollectorFromContext(c)

	outputResponse := m.buildResponseContext(c, gatewayID, rule)

	m.logger.Debug("processing metrics as non stream mode")
	m.worker.Process(
		collector,
		gatewayData.Gateway.Telemetry.Exporters,
		inputRequest,
		outputResponse,
		startTime,
		time.Now(),
	)
}

// buildResponseContext creates a ResponseContext from the fiber context
func (m *metricsMiddleware) buildResponseContext(
	c *fiber.Ctx,
	gatewayID string,
	rule *types.ForwardingRuleDTO,
) types.ResponseContext {
	now := time.Now()
	return types.ResponseContext{
		Context:    context.Background(),
		GatewayID:  gatewayID,
		Headers:    m.copyHeaders(c.GetRespHeaders()),
		Metadata:   nil,
		Body:       append([]byte(nil), c.Response().Body()...),
		StatusCode: c.Response().StatusCode(),
		Rule:       rule,
		ProcessAt:  &now,
	}
}

// getSessionID retrieves the session ID from context
func (m *metricsMiddleware) getSessionID(ctx context.Context) string {
	sessionID, ok := ctx.Value(common.SessionContextKey).(string)
	if !ok || sessionID == "" {
		m.logger.Debug("session ID not found in context")
		return ""
	}
	return sessionID
}

// getMatchedRule retrieves the matched rule from context
func (m *metricsMiddleware) getMatchedRule(ctx context.Context) *types.ForwardingRuleDTO {
	rule, ok := ctx.Value(string(common.MatchedRuleContextKey)).(*types.ForwardingRuleDTO)
	if !ok || rule == nil {
		m.logger.Error("failed to get matched rule from context")
		return &types.ForwardingRuleDTO{}
	}
	return rule
}

// getCollectorFromContext retrieves the metrics collector from fiber context
func (m *metricsMiddleware) getCollectorFromContext(c *fiber.Ctx) *metrics.Collector {
	collector, _ := c.Locals(string(metrics.CollectorKey)).(*metrics.Collector)
	return collector
}

// copyHeaders creates a deep copy of headers map
func (m *metricsMiddleware) copyHeaders(headers map[string][]string) map[string][]string {
	result := make(map[string][]string, len(headers))
	for key, values := range headers {
		copyValues := make([]string, len(values))
		copy(copyValues, values)
		result[key] = copyValues
	}
	return result
}

// getQueryParams extracts query parameters from the request
func (m *metricsMiddleware) getQueryParams(c *fiber.Ctx) url.Values {
	queryParams := make(url.Values)
	c.Request().URI().QueryArgs().VisitAll(func(k, v []byte) {
		queryParams.Set(string(k), string(v))
	})
	return queryParams
}

// setTelemetryHeaders sets conversation and interaction ID headers from request
func (m *metricsMiddleware) setTelemetryHeaders(c *fiber.Ctx, gatewayData *types.GatewayData) {
	mapping := m.getHeaderMapping(gatewayData)

	// Set conversation ID
	conversationIDKey := mapping["conversation_id"]
	if conversationIDKey == "" {
		conversationIDKey = common.ConversationIDHeader
	}
	if value := c.Get(conversationIDKey); value != "" {
		c.Locals(common.ConversationIDHeader, value)
	}

	// Set interaction ID (generate if not present)
	interactionIDKey := mapping["interaction_id"]
	if interactionIDKey == "" {
		interactionIDKey = common.InteractionIDHeader
	}
	if value := c.Get(interactionIDKey); value != "" {
		c.Locals(common.InteractionIDHeader, value)
	} else {
		c.Locals(common.InteractionIDHeader, uuid.New().String())
	}
}

// getHeaderMapping retrieves the header mapping configuration
func (m *metricsMiddleware) getHeaderMapping(gatewayData *types.GatewayData) map[string]string {
	if gatewayData.Gateway != nil &&
		gatewayData.Gateway.Telemetry != nil &&
		gatewayData.Gateway.Telemetry.HeaderMapping != nil {
		return gatewayData.Gateway.Telemetry.HeaderMapping
	}
	return make(map[string]string)
}

// streamState manages the state of stream detection and data collection
type streamState struct {
	responseChan chan []byte
	modeChan     chan bool
	wg           *sync.WaitGroup
	streaming    bool
	mu           sync.Mutex
}

func (m *metricsMiddleware) initStreamState(c *fiber.Ctx) *streamState {
	responseChan := c.Locals(common.StreamResponseContextKey).(chan []byte)
	modeChan := c.Locals(common.StreamModeContextKey).(chan bool)

	return &streamState{
		responseChan: responseChan,
		modeChan:     modeChan,
		wg:           &sync.WaitGroup{},
	}
}

func (s *streamState) waitForMode(logger *logrus.Logger) {
	s.wg.Add(1)
	defer s.wg.Done()

	select {
	case mode := <-s.modeChan:
		s.mu.Lock()
		s.streaming = mode
		s.mu.Unlock()
	case <-time.After(streamModeTimeout):
		logger.Warn("timeout waiting for stream mode signal")
	}
}

func (s *streamState) wait() {
	s.wg.Wait()
}

func (s *streamState) isStreaming() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.streaming
}

func (s *streamState) cleanup() {
	close(s.modeChan)
}

func (s *streamState) collectStreamData(logger *logrus.Logger) ([]byte, []byte) {
	var buffer bytes.Buffer
	var lastLine []byte

	for line := range s.responseChan {
		if len(line) > 0 {
			lastLine = line
			if _, err := buffer.Write(line); err != nil {
				logger.WithError(err).Error("error writing to stream buffer")
			}
		}
	}

	return buffer.Bytes(), lastLine
}
