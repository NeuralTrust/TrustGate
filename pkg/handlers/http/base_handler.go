package http

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/cache"
	"github.com/NeuralTrust/TrustGate/pkg/common"
	"github.com/NeuralTrust/TrustGate/pkg/config"
	domainUpstream "github.com/NeuralTrust/TrustGate/pkg/domain/upstream"
	infraCache "github.com/NeuralTrust/TrustGate/pkg/infra/cache"
	"github.com/NeuralTrust/TrustGate/pkg/infra/metrics"
	"github.com/NeuralTrust/TrustGate/pkg/infra/metrics/metric_events"
	"github.com/NeuralTrust/TrustGate/pkg/infra/prometheus"
	"github.com/NeuralTrust/TrustGate/pkg/plugins"
	"github.com/NeuralTrust/TrustGate/pkg/types"
	"github.com/gofiber/fiber/v2"
	"github.com/sirupsen/logrus"
	"github.com/valyala/fasthttp"
)

type BaseHandler struct {
	logger         *logrus.Logger
	cache          *cache.Cache
	pluginManager  plugins.Manager
	cfg            *config.Config
	client         *fasthttp.Client
	tlsClientCache *infraCache.TLSClientCache
}

func NewBaseHandler(
	logger *logrus.Logger,
	cache *cache.Cache,
	pluginManager plugins.Manager,
	cfg *config.Config,
) *BaseHandler {
	client := &fasthttp.Client{
		ReadTimeout:                   60 * time.Second,
		WriteTimeout:                  60 * time.Second,
		MaxConnsPerHost:               16384,
		MaxIdleConnDuration:           120 * time.Second,
		ReadBufferSize:                32768,
		WriteBufferSize:               32768,
		NoDefaultUserAgentHeader:      true,
		DisableHeaderNamesNormalizing: true,
		DisablePathNormalizing:        true,
	}

	return &BaseHandler{
		logger:         logger,
		cache:          cache,
		pluginManager:  pluginManager,
		cfg:            cfg,
		client:         client,
		tlsClientCache: infraCache.NewTLSClientCache(),
	}
}

func (h *BaseHandler) HandleErrorResponse(c *fiber.Ctx, status int, message fiber.Map) error {
	streamMode, ok := c.Locals(common.StreamModeContextKey).(chan bool)
	if !ok {
		h.logger.Error("failed to get stream mode channel")
		return fmt.Errorf("failed to get stream mode channel")
	}
	select {
	case streamMode <- false:
		h.logger.Debug("stream mode disabled")
	default:
	}
	return c.Status(status).JSON(message)
}

func (h *BaseHandler) HandleSuccessResponse(c *fiber.Ctx, status int, message []byte) error {
	streamMode, ok := c.Locals(common.StreamModeContextKey).(chan bool)
	if !ok {
		h.logger.Error("failed to get stream mode channel")
		return fmt.Errorf("failed to get stream mode channel")
	}
	select {
	case streamMode <- false:
		h.logger.Debug("stream mode disabled")
	default:
	}
	return c.Status(status).Send(message)
}

func (h *BaseHandler) HandleSuccessJSONResponse(c *fiber.Ctx, status int, message interface{}) error {
	streamMode, ok := c.Locals(common.StreamModeContextKey).(chan bool)
	if !ok {
		h.logger.Error("failed to get stream mode channel")
		return fmt.Errorf("failed to get stream mode channel")
	}
	select {
	case streamMode <- false:
		h.logger.Debug("stream mode disabled")
	default:
	}
	return c.Status(status).JSON(message)
}

func (h *BaseHandler) PrepareRequestContext(c *fiber.Ctx) (*types.RequestContext, *types.ResponseContext, *metrics.Collector, string, error) {
	startTime := time.Now()

	gatewayIDAny := c.Locals(common.GatewayContextKey)
	if gatewayIDAny == "" {
		h.logger.Error("gateway ID not found in Fiber context")
		return nil, nil, nil, "", fmt.Errorf("gateway ID not found")
	}

	gatewayID, ok := gatewayIDAny.(string)
	if !ok {
		h.logger.Error("gateway ID not found in Fiber context")
		return nil, nil, nil, "", fmt.Errorf("gateway ID not found")
	}

	metricsCollector, ok := c.Locals(string(metrics.CollectorKey)).(*metrics.Collector)
	if !ok || metricsCollector == nil {
		h.logger.Error("failed to retrieve metrics collector from context")
		return nil, nil, nil, "", fmt.Errorf("metrics collector not found")
	}

	// Get metadata from fiber context
	var metadata map[string]interface{}
	if md := c.Locals(common.MetadataKey); md != nil {
		if m, ok := md.(map[string]interface{}); ok {
			metadata = m
		}
	}

	if metadata == nil {
		metadata = make(map[string]interface{})
		apiKey := c.Locals(common.ApiKeyContextKey)
		if apiKey != "" {
			metadata[string(common.ApiKeyContextKey)] = apiKey
		}
	}

	// Create the RequestContext
	reqCtx := &types.RequestContext{
		C:         c,
		Context:   c.Context(),
		GatewayID: gatewayID,
		Headers:   make(map[string][]string),
		Method:    c.Method(),
		Path:      c.Path(),
		Query:     h.getQueryParams(c),
		Metadata:  metadata,
		Body:      c.Body(),
	}

	// Copy request headers
	for key, values := range c.GetReqHeaders() {
		reqCtx.Headers[key] = values
	}

	if interactionId, ok := c.Locals(common.InteractionIDHeader).(string); ok && interactionId != "" {
		reqCtx.Headers[common.InteractionIDHeader] = []string{interactionId}
	}

	// Create the ResponseContext
	respCtx := &types.ResponseContext{
		Context:   c.Context(),
		GatewayID: gatewayID,
		Headers:   make(map[string][]string),
		Metadata:  make(map[string]interface{}),
	}

	// get gateway data set in plugin_chain middleware
	gatewayData, ok := c.Locals(string(common.GatewayDataContextKey)).(*types.GatewayData)
	if !ok {
		h.logger.Error("failed to get gateway data in handler")
		return nil, nil, nil, "", fmt.Errorf("gateway data not found")
	}

	reqCtx.Metadata[string(common.GatewayDataContextKey)] = gatewayData
	c.Locals("start_time", startTime)

	return reqCtx, respCtx, metricsCollector, gatewayID, nil
}

func (h *BaseHandler) ExecutePreRequestStage(
	ctx context.Context,
	gatewayID string,
	reqCtx *types.RequestContext,
	respCtx *types.ResponseContext,
	metricsCollector *metrics.Collector,
	c *fiber.Ctx,
) error {
	if _, err := h.pluginManager.ExecuteStage(
		ctx,
		types.PreRequest,
		gatewayID,
		reqCtx,
		respCtx,
		metricsCollector,
	); err != nil {
		var pluginErr *types.PluginError
		if errors.As(err, &pluginErr) {
			for k, values := range respCtx.Headers {
				for _, v := range values {
					c.Set(k, v)
				}
			}
			h.RegistryFailedEvent(
				metricsCollector,
				pluginErr.StatusCode,
				pluginErr.Err,
				respCtx,
			)
			return h.HandleErrorResponse(c, pluginErr.StatusCode, fiber.Map{
				"error":       pluginErr.Message,
				"retry_after": respCtx.Metadata["retry_after"],
			})
		}

		if respCtx.StopProcessing {
			for k, values := range respCtx.Headers {
				for _, v := range values {
					c.Set(k, v)
				}
			}
			return h.HandleSuccessResponse(c, respCtx.StatusCode, respCtx.Body)
		}
		if !h.cfg.Plugins.IgnoreErrors {
			return h.HandleErrorResponse(c, fiber.StatusInternalServerError, fiber.Map{"error": "Plugin execution failed"})
		}
	}
	return nil
}

func (h *BaseHandler) ExecutePreResponseStage(
	ctx context.Context,
	gatewayID string,
	reqCtx *types.RequestContext,
	respCtx *types.ResponseContext,
	metricsCollector *metrics.Collector,
	c *fiber.Ctx,
) error {
	if _, err := h.pluginManager.ExecuteStage(
		ctx,
		types.PreResponse,
		gatewayID,
		reqCtx,
		respCtx,
		metricsCollector,
	); err != nil {
		var pluginErr *types.PluginError
		if errors.As(err, &pluginErr) {
			// Copy headers from response context
			for k, values := range respCtx.Headers {
				for _, v := range values {
					c.Set(k, v)
				}
			}
			h.RegistryFailedEvent(metricsCollector, pluginErr.StatusCode, pluginErr.Err, respCtx)
			return h.HandleErrorResponse(c, pluginErr.StatusCode, fiber.Map{
				"error":       pluginErr.Message,
				"retry_after": respCtx.Metadata["retry_after"],
			})
		}

		if !h.cfg.Plugins.IgnoreErrors {
			return h.HandleErrorResponse(c, fiber.StatusInternalServerError, fiber.Map{"error": "Plugin execution failed"})
		}
	}
	return nil
}

func (h *BaseHandler) ExecutePostResponseStage(
	ctx context.Context,
	gatewayID string,
	reqCtx *types.RequestContext,
	respCtx *types.ResponseContext,
	metricsCollector *metrics.Collector,
	c *fiber.Ctx,
) error {
	if _, err := h.pluginManager.ExecuteStage(
		ctx,
		types.PostResponse,
		gatewayID,
		reqCtx,
		respCtx,
		metricsCollector,
	); err != nil {
		var pluginErr *types.PluginError
		if errors.As(err, &pluginErr) {
			// Copy headers from response context
			h.logger.WithFields(logrus.Fields{
				"headers": respCtx.Headers,
			}).Debug("Plugin response headers")

			for k, values := range respCtx.Headers {
				for _, v := range values {
					c.Set(k, v)
				}
			}
			h.RegistryFailedEvent(metricsCollector, pluginErr.StatusCode, pluginErr.Err, respCtx)
			return h.HandleErrorResponse(c, pluginErr.StatusCode, fiber.Map{
				"error":       pluginErr.Message,
				"retry_after": respCtx.Metadata["retry_after"],
			})
		}
		if !h.cfg.Plugins.IgnoreErrors {
			return h.HandleErrorResponse(c, fiber.StatusInternalServerError, fiber.Map{"error": "Plugin execution failed"})
		}

	}
	return nil
}

func (h *BaseHandler) RecordPrometheusMetrics(gatewayID, serviceID, ruleID string, duration int64) {
	if prometheus.Config.EnableLatency {
		prometheus.GatewayRequestLatency.WithLabelValues(
			gatewayID,
			serviceID,
		).Observe(float64(duration))
	}

	if prometheus.Config.EnablePerRoute {
		prometheus.GatewayDetailedLatency.WithLabelValues(
			gatewayID,
			serviceID,
			ruleID,
		).Observe(float64(duration))
	}
}

func (h *BaseHandler) RegistryFailedEvent(
	collector *metrics.Collector,
	status int,
	err error,
	rsp *types.ResponseContext,
) {
	evt := metric_events.NewTraceEvent()
	if err != nil {
		evt.Error = err.Error()
	}
	evt.StatusCode = status
	if rsp != nil {
		if rsp.Target != nil {
			evt.Upstream.Target = metric_events.TargetEvent{
				Path:     rsp.Target.Path,
				Host:     rsp.Target.Host,
				Port:     rsp.Target.Port,
				Protocol: rsp.Target.Provider,
				Provider: rsp.Target.Provider,
				Headers:  rsp.Target.Headers,
			}
		}
	}
	collector.Emit(evt)
}

func (h *BaseHandler) RegistrySuccessEvent(
	collector *metrics.Collector,
	rsp *types.ResponseContext,
) {
	evt := metric_events.NewTraceEvent()
	evt.StatusCode = rsp.StatusCode
	if rsp.Target != nil {
		evt.Upstream = &metric_events.UpstreamEvent{}
		evt.Upstream.Target = metric_events.TargetEvent{
			Path:     rsp.Target.Path,
			Host:     rsp.Target.Host,
			Port:     rsp.Target.Port,
			Protocol: rsp.Target.Provider,
			Provider: rsp.Target.Provider,
			Headers:  rsp.Target.Headers,
			Latency:  int64(rsp.TargetLatency),
		}
	}
	collector.Emit(evt)
}

func (h *BaseHandler) getQueryParams(c *fiber.Ctx) url.Values {
	queryParams := make(url.Values)
	c.Request().URI().QueryArgs().VisitAll(func(k, v []byte) {
		queryParams.Set(string(k), string(v))
	})
	return queryParams
}

func (h *BaseHandler) ConfigureRulePlugins(gatewayID string, rule *types.ForwardingRule) error {
	if rule != nil && len(rule.PluginChain) > 0 {
		if err := h.pluginManager.SetPluginChain(gatewayID, rule.PluginChain); err != nil {
			return fmt.Errorf("failed to configure rule plugins: %w", err)
		}
	}
	return nil
}

func (h *BaseHandler) PrepareClient(tlsConfig map[string]types.ClientTLSConfig, target *types.UpstreamTarget, proxy *domainUpstream.Proxy) (*fasthttp.Client, error) {
	tlsConf, hasTLS := tlsConfig[target.Host]
	proxyAddr := ""
	if proxy != nil {
		proxyAddr = fmt.Sprintf("%s:%s", proxy.Host, proxy.Port)
		h.logger.Debug("using proxy " + proxyAddr)
	}

	switch {
	case hasTLS:
		if target.InsecureSSL {
			tlsConf.AllowInsecureConnections = true
		}
		conf, err := config.BuildTLSConfigFromClientConfig(tlsConf)
		if err != nil {
			return nil, fmt.Errorf("failed to build TLS config: %w", err)
		}
		return h.tlsClientCache.GetOrCreate(target.ID, conf, proxyAddr), nil

	case target.InsecureSSL:
		conf, err := config.BuildTLSConfigFromClientConfig(types.ClientTLSConfig{AllowInsecureConnections: true})
		if err != nil {
			return nil, fmt.Errorf("failed to build insecure TLS config: %w", err)
		}
		return h.tlsClientCache.GetOrCreate(target.ID+"-insecure", conf, proxyAddr), nil

	case proxyAddr != "":
		return h.tlsClientCache.GetOrCreate(target.ID+"-proxy", nil, proxyAddr), nil

	default:
		return h.client, nil
	}
}
