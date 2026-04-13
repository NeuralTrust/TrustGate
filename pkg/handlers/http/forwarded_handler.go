package http

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/app/routing"
	"github.com/NeuralTrust/TrustGate/pkg/app/service"
	"github.com/NeuralTrust/TrustGate/pkg/app/upstream"
	"github.com/NeuralTrust/TrustGate/pkg/common"
	"github.com/NeuralTrust/TrustGate/pkg/config"
	domainService "github.com/NeuralTrust/TrustGate/pkg/domain/service"
	domainUpstream "github.com/NeuralTrust/TrustGate/pkg/domain/upstream"
	"github.com/NeuralTrust/TrustGate/pkg/infra/auth/oauth"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache"
	infrahttpx "github.com/NeuralTrust/TrustGate/pkg/infra/httpx"
	"github.com/NeuralTrust/TrustGate/pkg/infra/loadbalancer"
	"github.com/NeuralTrust/TrustGate/pkg/infra/metrics"
	"github.com/NeuralTrust/TrustGate/pkg/infra/metrics/metric_events"
	"github.com/NeuralTrust/TrustGate/pkg/infra/plugins"
	plugintypes "github.com/NeuralTrust/TrustGate/pkg/infra/plugins/types"
	"github.com/NeuralTrust/TrustGate/pkg/infra/prometheus"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/factory"
	infraTLS "github.com/NeuralTrust/TrustGate/pkg/infra/tls"
	"github.com/NeuralTrust/TrustGate/pkg/types"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/valyala/fasthttp"
	"github.com/valyala/fastjson"
)

type forwardedRequestDTO struct {
	tlsConfig      map[string]types.ClientTLSConfigDTO
	req            *types.RequestContext
	rule           *types.ForwardingRuleDTO
	target         *types.UpstreamTargetDTO
	proxy          *domainUpstream.Proxy
	streamResponse chan []byte
	gatewayID      string
}

var responseBodyPool = sync.Pool{
	New: func() interface{} {
		return new([]byte)
	},
}

type forwardedHandler struct {
	logger              *logrus.Logger
	cache               cache.Client
	gatewayCache        *cache.TTLMap
	loadBalancerCache   *cache.TTLMap
	upstreamFinder      upstream.Finder
	serviceFinder       service.Finder
	pluginManager       plugins.Manager
	client              *fasthttp.Client
	loadBalancerFactory loadbalancer.Factory
	cfg                 *config.Config
	tlsClientCache      *cache.TLSClientCache
	providerLocator     factory.ProviderLocator
	tokenClient         oauth.TokenClient
	ruleMatcher         routing.RuleMatcher
	tlsCertWriter       infraTLS.CertWriter
	adapterRegistry     *adapter.Registry
}

// ForwardedHandlerDeps contains all dependencies for ForwardedHandler.
type ForwardedHandlerDeps struct {
	Logger              *logrus.Logger
	Cache               cache.Client
	UpstreamFinder      upstream.Finder
	ServiceFinder       service.Finder
	PluginManager       plugins.Manager
	LoadBalancerFactory loadbalancer.Factory
	Cfg                 *config.Config
	ProviderLocator     factory.ProviderLocator
	TokenClient         oauth.TokenClient
	RuleMatcher         routing.RuleMatcher
	TLSCertWriter       infraTLS.CertWriter
	AdapterRegistry     *adapter.Registry
}

func NewForwardedHandler(deps ForwardedHandlerDeps) Handler {
	readTimeout := deps.Cfg.Upstream.ReadTimeout
	writeTimeout := deps.Cfg.Upstream.WriteTimeout

	client := &fasthttp.Client{
		ReadTimeout:                   readTimeout,
		WriteTimeout:                  writeTimeout,
		MaxConnsPerHost:               16384,
		MaxIdleConnDuration:           120 * time.Second,
		ReadBufferSize:                32768,
		WriteBufferSize:               32768,
		NoDefaultUserAgentHeader:      true,
		DisableHeaderNamesNormalizing: true,
		DisablePathNormalizing:        true,
	}

	return &forwardedHandler{
		logger:              deps.Logger,
		cache:               deps.Cache,
		gatewayCache:        deps.Cache.GetTTLMap(cache.GatewayTTLName),
		loadBalancerCache:   deps.Cache.GetTTLMap(cache.LoadBalancerTTLName),
		upstreamFinder:      deps.UpstreamFinder,
		serviceFinder:       deps.ServiceFinder,
		pluginManager:       deps.PluginManager,
		client:              client,
		loadBalancerFactory: deps.LoadBalancerFactory,
		cfg:                 deps.Cfg,
		tlsClientCache:      cache.NewTLSClientCache(deps.Logger),
		providerLocator:     deps.ProviderLocator,
		tokenClient:         deps.TokenClient,
		ruleMatcher:         deps.RuleMatcher,
		tlsCertWriter:       deps.TLSCertWriter,
		adapterRegistry:     deps.AdapterRegistry,
	}
}

type RequestData struct {
	Headers map[string][]string
	Body    []byte
	Uri     string
	Host    string
	Method  string
}

func (h *forwardedHandler) handleErrorResponse(c *fiber.Ctx, status int, message fiber.Map) error {
	streamMode, ok := c.Locals(common.StreamModeContextKey).(chan bool)
	if !ok {
		h.logger.Error("failed to get stream mode channel")
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{
			"error": "failed to get stream mode channel",
		})

	}
	select {
	case streamMode <- false:
		h.logger.Debug("stream mode disabled")
	default:
	}

	if traceId, ok := c.Locals(common.TraceIdKey).(string); ok && traceId != "" {
		c.Set("X-Trace-ID", traceId)
	}

	return c.Status(status).JSON(message)
}

func (h *forwardedHandler) handleSuccessResponse(c *fiber.Ctx, status int, message []byte) error {
	streamMode, ok := c.Locals(common.StreamModeContextKey).(chan bool)
	if !ok {
		h.logger.Error("failed to get stream mode channel")
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{
			"error": "failed to get stream mode channel",
		})

	}
	select {
	case streamMode <- false:
		h.logger.Debug("stream mode disabled")
	default:
	}

	if traceId, ok := c.Locals(common.TraceIdKey).(string); ok && traceId != "" {
		c.Set("X-Trace-ID", traceId)
	}

	return c.Status(status).Send(message)
}

func (h *forwardedHandler) handleSuccessJSONResponse(c *fiber.Ctx, status int, message interface{}) error {
	streamMode, ok := c.Locals(common.StreamModeContextKey).(chan bool)
	if !ok {
		h.logger.Error("failed to get stream mode channel")
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{
			"error": "failed to get stream mode channel",
		})

	}
	select {
	case streamMode <- false:
		h.logger.Debug("stream mode disabled")
	default:
	}

	if traceId, ok := c.Locals(common.TraceIdKey).(string); ok && traceId != "" {
		c.Set("X-Trace-ID", traceId)
	}

	return c.Status(status).JSON(message)
}

func (h *forwardedHandler) Handle(c *fiber.Ctx) error {

	reqData := RequestData{
		Headers: c.GetReqHeaders(),
		Body:    c.Body(),
		Uri:     c.OriginalURL(),
		Host:    c.Hostname(),
		Method:  c.Method(),
	}

	gatewayIDAny := c.Locals(common.GatewayContextKey)

	startTime := time.Now()

	if gatewayIDAny == "" {
		h.logger.Error("gateway ID not found in Fiber context")
		return h.handleErrorResponse(c, fiber.StatusInternalServerError, fiber.Map{"error": "Internal server error"})
	}

	gatewayID, ok := gatewayIDAny.(string)
	if !ok {
		h.logger.Error("gateway ID not found in Fiber context")
		return h.handleErrorResponse(c, fiber.StatusInternalServerError, fiber.Map{"error": "Internal server error"})
	}

	metricsCollector, ok := c.Locals(string(metrics.CollectorKey)).(*metrics.Collector)
	if !ok || metricsCollector == nil {
		h.logger.Error("failed to retrieve metrics collector from context")
		return h.handleErrorResponse(c, fiber.StatusInternalServerError, fiber.Map{"error": "internal server error"})
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

	gatewayData, ok := c.Locals(string(common.GatewayDataContextKey)).(*types.GatewayData)
	if !ok {
		h.logger.Error("failed to get gateway data in handler")
		return h.handleErrorResponse(c, fiber.StatusInternalServerError, fiber.Map{"error": "internal server error"})
	}

	matchingRule, ok := c.Locals(string(common.MatchedRuleContextKey)).(*types.ForwardingRuleDTO)
	if !ok {
		h.logger.Error("failed to get matched rule from context")
		return h.handleErrorResponse(c, fiber.StatusInternalServerError, fiber.Map{"error": "internal server error"})
	}

	upstreamModel, err := h.getUpstream(c.Context(), matchingRule)
	if err != nil {
		h.logger.WithError(err).Error("failed to get upstream")
		return h.handleErrorResponse(c, fiber.StatusInternalServerError, fiber.Map{"error": "failed to get upstream"})
	}

	reqCtx := &types.RequestContext{
		C:         c,
		Context:   c.Context(),
		GatewayID: gatewayID,
		Headers:   make(map[string][]string),
		Method:    reqData.Method,
		Path:      c.Path(),
		Query:     h.getQueryParams(c),
		Metadata:  metadata,
		Body:      c.Body(),
		RuleID:    matchingRule.ID,
	}

	if sessionID, ok := c.Locals(common.SessionContextKey).(string); ok && sessionID != "" {
		reqCtx.SessionID = sessionID
	}

	lb, err := h.getOrCreateLoadBalancer(upstreamModel)
	if err != nil {
		h.logger.WithError(err).Error("failed to get load balancer")
		return h.handleErrorResponse(c, fiber.StatusInternalServerError, fiber.Map{"error": "failed to get load balancer"})
	}

	var preselectedTarget *types.UpstreamTargetDTO
	preselectedTarget, err = h.preselectTarget(reqCtx, lb)
	if err != nil {
		h.logger.WithError(err).Warn("failed to pre-select target, will select during forwardRequest")
	}

	if preselectedTarget != nil && preselectedTarget.Provider != "" {
		reqCtx.Provider = preselectedTarget.Provider
		reqCtx.SourceFormat = string(adapter.DetectFormat(reqCtx.Body))
		reqCtx.TargetFormat = string(adapter.ResolveTargetFormat(preselectedTarget.Provider, preselectedTarget.ProviderOptions))
		reqCtx.SetAdapterRegistry(h.adapterRegistry)
	}

	for key, values := range c.GetReqHeaders() {
		if strings.EqualFold(key, common.TrustgateAuthHeader) {
			continue
		}
		reqCtx.Headers[key] = values
	}

	if interactionId, ok := c.Locals(common.InteractionIDHeader).(string); ok && interactionId != "" {
		reqCtx.Headers[common.InteractionIDHeader] = []string{interactionId}
	}

	respCtx := &types.ResponseContext{
		Context:   c.Context(),
		GatewayID: gatewayID,
		Headers:   make(map[string][]string),
		Metadata:  make(map[string]interface{}),
	}

	if err := h.configureRulePlugins(gatewayID, matchingRule); err != nil {
		h.logger.WithError(err).Error("Failed to configure plugins")
		return h.handleErrorResponse(c, fiber.StatusNotFound, fiber.Map{"error": "failed to configure plugins"})
	}

	if _, err := h.pluginManager.ExecuteStage(
		c.Context(),
		plugintypes.PreRequest,
		gatewayID,
		reqCtx,
		respCtx,
		metricsCollector,
	); err != nil {
		if pluginErr, typeErr := errors.AsType[*plugintypes.PluginError](err); typeErr {
			for k, values := range respCtx.Headers {
				for _, v := range values {
					c.Set(k, v)
				}
			}
			if pluginErr.Headers != nil {
				for k, values := range pluginErr.Headers {
					for _, v := range values {
						c.Set(k, v)
					}
				}
			}
			status := safeStatusCode(pluginErr.StatusCode, http.StatusInternalServerError)
			h.registryFailedEvent(
				metricsCollector,
				status,
				pluginErr.Err,
				respCtx,
			)
			return h.handleErrorResponse(c, status, fiber.Map{
				"error":       pluginErr.Message,
				"retry_after": respCtx.Metadata["retry_after"],
			})
		}
		if !h.cfg.Plugins.IgnoreErrors {
			return h.handleErrorResponse(c, fiber.StatusInternalServerError, fiber.Map{"error": "Plugin execution failed"})
		}
		if respCtx.StopProcessing {
			for k, values := range respCtx.Headers {
				for _, v := range values {
					c.Set(k, v)
				}
			}
			return h.handleSuccessResponse(c, safeStatusCode(respCtx.StatusCode, http.StatusOK), respCtx.Body)
		}
	}

	if respCtx.StopProcessing {
		for k, values := range respCtx.Headers {
			for _, v := range values {
				c.Set(k, v)
			}
		}
		h.registrySuccessEvent(metricsCollector, respCtx)
		return h.handleSuccessResponse(c, safeStatusCode(respCtx.StatusCode, http.StatusOK), respCtx.Body)
	}

	// Create plugin channels before forwarding so the stream writers can pick them up.
	streamPluginData := make(chan []byte, 512)
	pluginsDone := make(chan struct{})
	c.Locals(string(common.StreamDoneContextKey), streamPluginData)
	c.Locals(string(common.PluginsDoneContextKey), pluginsDone)

	// Forward the request
	upstreamStartTime := time.Now()
	response, err := h.forwardRequest(
		reqCtx,
		matchingRule,
		upstreamModel,
		gatewayData.Gateway.TlS,
		preselectedTarget,
		lb,
	)
	if err != nil {
		close(streamPluginData)
		close(pluginsDone)

		if adapter.IsRequestDecodeError(err) {
			h.logger.WithError(err).Warn("Invalid request body")
			h.registryFailedEvent(metricsCollector, fiber.StatusBadRequest, err, respCtx)
			return h.handleErrorResponse(c, fiber.StatusBadRequest, fiber.Map{
				"error": "invalid request body: the payload does not match the expected API format for the configured upstream",
			})
		}

		h.logger.WithError(err).Error("Failed to forward request")
		h.registryFailedEvent(metricsCollector, fiber.StatusInternalServerError, err, respCtx)
		return h.handleErrorResponse(c, fiber.StatusBadGateway, fiber.Map{
			"error":   "failed to forward request",
			"message": err.Error(),
		})
	}

	upstreamLatency := float64(time.Since(upstreamStartTime).Microseconds()) / 1000
	// Record upstream latency if available
	if prometheus.Config.EnableUpstreamLatency {
		prometheus.GatewayUpstreamLatency.WithLabelValues(
			gatewayID,
			matchingRule.ServiceID,
			matchingRule.ID,
		).Observe(upstreamLatency)
	}

	// Copy response to response context
	respCtx.StatusCode = response.StatusCode
	respCtx.Body = response.Body
	respCtx.Target = response.Target

	for k, v := range response.Headers {
		respCtx.Headers[k] = v
	}
	respCtx.TargetLatency = upstreamLatency

	if reqCtx.Provider != "" {
		respCtx.SourceFormat = reqCtx.SourceFormat
		respCtx.SetAdapterRegistry(h.adapterRegistry)
	}

	if response.Streaming {
		respCtx.Streaming = true

		go func() {
			defer close(pluginsDone)
			var buf bytes.Buffer
			for chunk := range streamPluginData {
				if len(chunk) > 0 {
					buf.Write(chunk)
					buf.WriteByte('\n')
				}
			}
			if buf.Len() > 0 {
				respCtx.Body = buf.Bytes()
				if _, err := h.pluginManager.ExecuteStage(
					context.Background(), plugintypes.PostResponse,
					gatewayID, reqCtx, respCtx, metricsCollector,
				); err != nil {
					h.logger.WithError(err).Warn("post-stream PostResponse plugin error")
				}
			}
			h.registrySuccessEvent(metricsCollector, respCtx)
		}()

		return nil
	}

	// Non-streaming: no plugin goroutine needed, clean up channels immediately.
	close(streamPluginData)
	close(pluginsDone)

	if response.StatusCode >= http.StatusBadRequest {
		for k, values := range respCtx.Headers {
			for _, v := range values {
				c.Set(k, v)
			}
		}
		var jsonBody interface{}
		if err := json.Unmarshal(response.Body, &jsonBody); err == nil {
			return h.handleSuccessJSONResponse(c, response.StatusCode, jsonBody)
		}
		return h.handleErrorResponse(c, response.StatusCode, fiber.Map{
			"error": string(response.Body),
		})
	}

	// Execute pre-response plugins
	if _, err := h.pluginManager.ExecuteStage(
		c.Context(),
		plugintypes.PreResponse,
		gatewayID,
		reqCtx,
		respCtx,
		metricsCollector,
	); err != nil {
		if pluginErr, typeErr := errors.AsType[*plugintypes.PluginError](err); typeErr {
			for k, values := range respCtx.Headers {
				for _, v := range values {
					c.Set(k, v)
				}
			}
			status := safeStatusCode(pluginErr.StatusCode, http.StatusInternalServerError)
			h.registryFailedEvent(metricsCollector, status, pluginErr.Err, respCtx)
			return h.handleErrorResponse(c, status, fiber.Map{
				"error":       pluginErr.Message,
				"retry_after": respCtx.Metadata["retry_after"],
			})
		}

		if !h.cfg.Plugins.IgnoreErrors {
			return h.handleErrorResponse(c, fiber.StatusInternalServerError, fiber.Map{"error": "Plugin execution failed"})
		}
	}

	// Execute post-response plugins
	if _, err := h.pluginManager.ExecuteStage(
		c.Context(),
		plugintypes.PostResponse,
		gatewayID,
		reqCtx,
		respCtx,
		metricsCollector,
	); err != nil {
		if pluginErr, typeErr := errors.AsType[*plugintypes.PluginError](err); typeErr {
			h.logger.WithFields(logrus.Fields{
				"headers": respCtx.Headers,
			}).Debug("Plugin response headers")

			for k, values := range respCtx.Headers {
				for _, v := range values {
					c.Set(k, v)
				}
			}
			status := safeStatusCode(pluginErr.StatusCode, http.StatusInternalServerError)
			h.registryFailedEvent(metricsCollector, status, pluginErr.Err, respCtx)
			return h.handleErrorResponse(c, status, fiber.Map{
				"error":       pluginErr.Message,
				"retry_after": respCtx.Metadata["retry_after"],
			})
		}
		if !h.cfg.Plugins.IgnoreErrors {
			return h.handleErrorResponse(c, fiber.StatusInternalServerError, fiber.Map{"error": "Plugin execution failed"})
		}
	}

	// Copy all headers from response context to client response
	for k, values := range respCtx.Headers {
		for _, v := range values {
			c.Set(k, v)
		}
	}

	duration := time.Since(startTime).Milliseconds()

	if prometheus.Config.EnableLatency {
		prometheus.GatewayRequestLatency.WithLabelValues(
			gatewayID,
			c.Path(),
		).Observe(float64(duration))
	}

	if prometheus.Config.EnablePerRoute {
		prometheus.GatewayDetailedLatency.WithLabelValues(
			gatewayID,
			matchingRule.ServiceID,
			matchingRule.ID,
		).Observe(float64(duration))
	}

	h.registrySuccessEvent(metricsCollector, respCtx)
	// Write the response body
	return h.handleSuccessResponse(c, respCtx.StatusCode, respCtx.Body)

}

func (h *forwardedHandler) configureRulePlugins(gatewayID string, rule *types.ForwardingRuleDTO) error {
	if rule != nil && len(rule.PluginChain) > 0 {
		if err := h.pluginManager.SetPluginChain(gatewayID, rule.PluginChain); err != nil {
			return fmt.Errorf("failed to configure rule plugins: %w", err)
		}
	}
	return nil
}

func (h *forwardedHandler) preselectTarget(
	reqCtx *types.RequestContext,
	lb *loadbalancer.LoadBalancer,
) (*types.UpstreamTargetDTO, error) {
	target, err := lb.NextTarget(reqCtx)
	if err != nil {
		return nil, fmt.Errorf("failed to select target: %w", err)
	}
	return target, nil
}

func (h *forwardedHandler) getUpstream(
	ctx context.Context,
	rule *types.ForwardingRuleDTO,
) (*domainUpstream.Upstream, error) {
	serviceEntity, err := h.serviceFinder.Find(ctx, rule.GatewayID, rule.ServiceID)
	if err != nil {
		return nil, fmt.Errorf("service not found: %w", err)
	}
	if serviceEntity.Type != domainService.TypeUpstream {
		return nil, fmt.Errorf("service is not an upstream: %w", err)
	}
	upstreamModel, err := h.upstreamFinder.Find(ctx, serviceEntity.GatewayID, serviceEntity.UpstreamID)
	if err != nil {
		return nil, fmt.Errorf("upstream not found: %w", err)
	}
	return upstreamModel, nil
}

func (h *forwardedHandler) forwardRequest(
	req *types.RequestContext,
	rule *types.ForwardingRuleDTO,
	upstreamModel *domainUpstream.Upstream,
	tlsConfig map[string]types.ClientTLSConfigDTO,
	preselectedTarget *types.UpstreamTargetDTO,
	lb *loadbalancer.LoadBalancer,
) (*types.ResponseContext, error) {

	streamResponse, ok := req.C.Locals(common.StreamResponseContextKey).(chan []byte)
	if !ok || streamResponse == nil {
		h.logger.Error("failed to get stream response channel")
		return nil, fmt.Errorf("failed to make read response channel")
	}

	streamMode, ok := req.C.Locals(common.StreamModeContextKey).(chan bool)
	if !ok {
		h.logger.Error("failed to get stream mode channel")
		return nil, fmt.Errorf("failed to get stream mode channel")
	}

	maxRetries := rule.RetryAttempts
	if maxRetries == 0 {
		maxRetries = 2
	}

	var reqErr error
	for attempt := 0; attempt <= maxRetries; attempt++ {
		var (
			target *types.UpstreamTargetDTO
			err    error
		)

		if attempt == 0 && preselectedTarget != nil {
			target = preselectedTarget
		} else {
			target, err = lb.NextTarget(req)
			if err != nil {
				if attempt == maxRetries {
					return nil, fmt.Errorf("failed to get target after retries: %w", err)
				}
				reqErr = err
				continue
			}
		}

		if req.Provider != target.Provider {
			if attempt > 0 {
				h.logger.WithFields(logrus.Fields{
					"old_provider": req.Provider,
					"new_provider": target.Provider,
					"attempt":      attempt + 1,
				}).Debug("provider changed during retry")
			}
			req.Provider = target.Provider
		}

		h.logger.WithFields(logrus.Fields{
			"attempt":   attempt + 1,
			"provider":  target.Provider,
			"stream":    target.Stream,
			"target_id": target.ID,
		}).Debug("Attempting request")

		if err := h.applyTargetOAuth(req, target, upstreamModel); err != nil {
			h.logger.WithError(err).Error("failed to obtain oauth token for target")
			return nil, fmt.Errorf("failed to obtain oauth token: %w", err)
		}

		// Drain any stale value from a previous attempt before sending the current one.
		select {
		case <-streamMode:
		default:
		}
		select {
		case streamMode <- target.Stream:
		default:
			h.logger.Warn("stream mode channel not ready, skipping")
		}

		response, err := h.doForwardRequest(
			req.C.Context(),
			&forwardedRequestDTO{
				req:            req,
				rule:           rule,
				target:         target,
				tlsConfig:      tlsConfig,
				streamResponse: streamResponse,
				proxy:          upstreamModel.Proxy,
				gatewayID:      rule.GatewayID,
			},
		)
		reqErr = err
		if err == nil {
			if !target.Stream {
				close(streamResponse)
			}
			response.Target = target
			lb.ReportSuccess(target)
			return response, nil
		}

		if ue, ok := domainUpstream.IsUpstreamError(err); ok && h.cfg.Upstream.ErrorPassthrough {
			if !target.Stream {
				close(streamResponse)
			}
			return &types.ResponseContext{
				StatusCode: ue.StatusCode,
				Body:       ue.Body,
				Headers:    map[string][]string{"Content-Type": {"application/json"}},
				Target:     target,
			}, nil
		}

		lb.ReportFailure(target, err)
	}

	select {
	case <-streamResponse:
	default:
		close(streamResponse)
	}
	return nil, fmt.Errorf("%w", reqErr)
}

func (h *forwardedHandler) applyTargetOAuth(
	req *types.RequestContext,
	target *types.UpstreamTargetDTO,
	upstreamModel *domainUpstream.Upstream,
) error {
	if upstreamModel == nil || target == nil {
		return nil
	}
	var domainTarget *domainUpstream.Target
	for i := range upstreamModel.Targets {
		if upstreamModel.Targets[i].ID == target.ID {
			domainTarget = &upstreamModel.Targets[i]
			break
		}
	}
	if domainTarget == nil || domainTarget.Auth == nil || domainTarget.Auth.Type != domainUpstream.AuthTypeOAuth2 || domainTarget.Auth.OAuth == nil {
		return nil
	}
	cfg := domainTarget.Auth.OAuth
	dto := oauth.TokenRequestDTO{
		TokenURL:     cfg.TokenURL,
		GrantType:    oauth.GrantType(cfg.GrantType),
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		UseBasicAuth: cfg.UseBasicAuth,
		Scopes:       cfg.Scopes,
		Audience:     cfg.Audience,
		Code:         cfg.Code,
		RedirectURI:  cfg.RedirectURI,
		CodeVerifier: cfg.CodeVerifier,
		RefreshToken: cfg.RefreshToken,
		Username:     cfg.Username,
		Password:     cfg.Password,
		Extra:        cfg.Extra,
	}
	accessToken, _, err := h.tokenClient.GetToken(req.Context, dto)
	if err != nil {
		return err
	}
	target.Credentials.ApiKey = accessToken
	if req.Headers == nil {
		req.Headers = make(map[string][]string)
	}
	req.Headers["Authorization"] = []string{"Bearer " + accessToken}
	if target.Headers == nil {
		target.Headers = make(map[string]string)
	}
	target.Headers["Authorization"] = "Bearer " + accessToken
	return nil
}

func (h *forwardedHandler) getOrCreateLoadBalancer(upstream *domainUpstream.Upstream) (*loadbalancer.LoadBalancer, error) {
	upstreamID := upstream.ID.String()
	if h.loadBalancerCache == nil {
		h.loadBalancerCache = h.cache.CreateTTLMap(cache.LoadBalancerTTLName, common.LoadBalancerCacheTTL)
	}
	if lbValue, ok := h.loadBalancerCache.Get(upstreamID); ok {
		if lb, ok := lbValue.(*loadbalancer.LoadBalancer); ok {
			return lb, nil
		}
	}

	lb, err := loadbalancer.NewLoadBalancer(h.loadBalancerFactory, upstream, h.logger, h.cache)
	if err != nil {
		return nil, err
	}

	h.loadBalancerCache.Set(upstreamID, lb)
	return lb, nil
}

func (h *forwardedHandler) handlerProviderResponse(
	req *types.RequestContext,
	target *types.UpstreamTargetDTO,
) (*types.ResponseContext, error) {
	providerClient, err := h.providerLocator.Get(target.Provider)
	if err != nil {
		return nil, fmt.Errorf("failed to get streaming provider client: %w", err)
	}

	sourceFormat := adapter.Format(req.SourceFormat)
	targetFormat := adapter.ResolveTargetFormat(target.Provider, target.ProviderOptions)

	// Adapt request if cross-provider.
	body := req.Body
	if !adapter.IsSameWireFormat(sourceFormat, targetFormat) {
		body, err = h.adapterRegistry.AdaptRequest(req.Body, sourceFormat, targetFormat)
		if err != nil {
			return nil, fmt.Errorf("failed to adapt request (%s->%s): %w", sourceFormat, targetFormat, err)
		}
	}

	if adapter.IsSameWireFormat(targetFormat, adapter.FormatOpenAI) {
		body = adapter.NormalizeOpenAIRequest(body)
	}

	body, _, err = adapter.ValidateModel(body, target.Models, target.DefaultModel)
	if err != nil {
		h.logger.WithError(err).Warn("model validation failed, proceeding with original body")
		body = req.Body
	}

	responseBody, err := providerClient.Completions(
		req.C.Context(),
		&providers.Config{
			Options:       target.ProviderOptions,
			AllowedModels: target.Models,
			DefaultModel:  target.DefaultModel,
			Credentials: providers.Credentials{
				ApiKey: target.Credentials.ApiKey,
				AwsBedrock: &providers.AwsBedrock{
					Region:       target.Credentials.AWSRegion,
					SecretKey:    target.Credentials.AWSSecretAccessKey,
					AccessKey:    target.Credentials.AWSAccessKeyID,
					SessionToken: target.Credentials.AWSSessionToken,
					UseRole:      target.Credentials.AWSUseRole,
					RoleARN:      target.Credentials.AWSRole,
				},
				Azure: &providers.Azure{
					Endpoint:    target.Credentials.AzureEndpoint,
					ApiVersion:  target.Credentials.AzureVersion,
					UseIdentity: target.Credentials.AzureUseManagedIdentity,
				},
			},
		},
		body,
	)
	if err != nil {
		if ue, ok := domainUpstream.IsUpstreamError(err); ok && h.cfg.Upstream.ErrorPassthrough {
			return &types.ResponseContext{
				StatusCode: ue.StatusCode,
				Body:       ue.Body,
				Headers:    map[string][]string{"Content-Type": {"application/json"}},
			}, nil
		}
		return nil, fmt.Errorf("failed to get completions: %w", err)
	}

	// Adapt response back to source format if cross-provider.
	if !adapter.IsSameWireFormat(sourceFormat, targetFormat) {
		responseBody, err = h.adapterRegistry.AdaptResponse(responseBody, sourceFormat, targetFormat)
		if err != nil {
			h.logger.WithError(err).Warn("failed to adapt response, returning raw")
		}
	}

	req.C.Set("X-Selected-Provider", target.Provider)
	req.C.Set("Content-Type", "application/json")

	return &types.ResponseContext{
		StatusCode: http.StatusOK,
		Headers:    map[string][]string{"X-Selected-Provider": {target.Provider}},
		Body:       responseBody,
	}, nil

}

func (h *forwardedHandler) doForwardRequest(ctx context.Context, dto *forwardedRequestDTO) (*types.ResponseContext, error) {
	if dto.target.Provider != "" {
		if dto.req.SourceFormat == "" {
			dto.req.SourceFormat = string(adapter.DetectFormat(dto.req.Body))
		}
		if dto.target.Stream {
			return h.handleStreamingResponseByProvider(dto.req, dto.target, dto.streamResponse)
		}
		return h.handlerProviderResponse(dto.req, dto.target)
	}

	if dto.target.Stream {
		httpClient, err := h.prepareHTTPClient(dto)
		if err != nil {
			return nil, err
		}
		return h.handleStreamingRequest(dto, httpClient)
	}

	client, err := h.prepareClient(ctx, dto)
	if err != nil {
		return nil, err
	}

	targetURL := h.rewriteTargetURL(dto)
	req := fasthttp.AcquireRequest()
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseRequest(req)
	defer fasthttp.ReleaseResponse(resp)

	h.buildFastHTTPRequest(req, dto, targetURL)

	h.logger.Debug("sending request to " + targetURL)

	if err := client.DoRedirects(req, resp, 3); err != nil {
		return nil, fmt.Errorf("request failed to %s: %w", targetURL, err)
	}

	return h.processUpstreamResponse(resp, dto)
}

func (h *forwardedHandler) rewriteTargetURL(dto *forwardedRequestDTO) string {
	pathParams := h.getPathParamsFromContext(dto.req.Context)
	l := h.buildUpstreamTargetUrl(dto.target, pathParams)
	if dto.rule != nil && dto.rule.StripPath {
		matchedPath := dto.rule.MatchedPath
		if matchedPath == "" {
			matchedPath = dto.rule.Path
		}
		remainingPath := h.ruleMatcher.ExtractPathAfterMatch(dto.req.Path, matchedPath)
		if remainingPath != dto.req.Path {
			l = strings.TrimSuffix(l, "/") + remainingPath
		}
	}

	if len(dto.req.Query) > 0 {
		queryString := dto.req.Query.Encode()
		if queryString != "" {
			if strings.Contains(l, "?") {
				l += "&" + queryString
			} else {
				l += "?" + queryString
			}
		}
	}

	return l
}

func (h *forwardedHandler) buildFastHTTPRequest(req *fasthttp.Request, dto *forwardedRequestDTO, targetURL string) {
	req.SetRequestURI(targetURL)
	req.Header.SetMethod(dto.req.Method)
	if len(dto.req.Body) > 0 {
		req.SetBodyRaw(dto.req.Body)
	}
	for k, vals := range dto.req.Headers {
		if strings.EqualFold(k, "Host") {
			continue
		}
		for _, v := range vals {
			req.Header.Add(k, v)
		}
	}
	for k, v := range dto.target.Headers {
		req.Header.Set(k, v)
	}
	if len(req.Header.Peek("Accept-Encoding")) == 0 {
		// Offer modern encodings; order by preference
		req.Header.Set("Accept-Encoding", "zstd, br, gzip, deflate")
	}
	h.applyAuthentication(req, &dto.target.Credentials, dto.req.Body)
}

func (h *forwardedHandler) processUpstreamResponse(
	resp *fasthttp.Response,
	dto *forwardedRequestDTO,
) (*types.ResponseContext, error) {
	respBodyPtr, ok := responseBodyPool.Get().(*[]byte)
	if !ok {
		return nil, errors.New("failed to get response body from pool")
	}

	body := make([]byte, len(resp.Body()))
	copy(body, resp.Body())

	if decoded, changed, err := infrahttpx.DecodeChain(resp, body); err != nil {
		responseBodyPool.Put(respBodyPtr)
		return nil, fmt.Errorf("failed to decode compressed response: %w", err)
	} else if changed {
		body = decoded
		// Remove compression-related headers since body is now decoded
		resp.Header.Del("Content-Encoding")
		resp.Header.Del("Content-Length")
	}
	*respBodyPtr = body

	status := resp.StatusCode()
	if status <= 0 || status >= 600 {
		responseBodyPool.Put(respBodyPtr)
		return nil, fmt.Errorf("invalid status code received: %d", status)
	}

	if dto.target.Provider != "" {
		go h.logger.WithField("provider", dto.target.Provider).Debug("Selected provider")
	}

	response := h.createResponse(resp, *respBodyPtr)
	responseBodyPool.Put(respBodyPtr)
	return response, nil
}

func (h *forwardedHandler) prepareClient(ctx context.Context, dto *forwardedRequestDTO) (*fasthttp.Client, error) {
	tlsConf, hasTLS := dto.tlsConfig[dto.target.Host]
	proxyAddr := ""
	proxyProtocol := ""
	if dto.proxy != nil {
		proxyAddr = fmt.Sprintf("%s:%s", dto.proxy.Host, dto.proxy.Port)
		proxyProtocol = dto.proxy.Protocol
		h.logger.Debug("using proxy " + proxyAddr + " with protocol " + proxyProtocol)
	}

	switch {
	case hasTLS:
		if dto.target.InsecureSSL {
			tlsConf.AllowInsecureConnections = true
		}
		// Ensure cert files exist, recovering from DB if needed
		if h.tlsCertWriter != nil && dto.gatewayID != "" {
			gatewayUUID, err := parseUUID(dto.gatewayID)
			if err == nil {
				certPaths := &infraTLS.CertPaths{
					CACertPath:     tlsConf.CACerts,
					ClientCertPath: tlsConf.ClientCerts.Certificate,
					ClientKeyPath:  tlsConf.ClientCerts.PrivateKey,
				}
				if err := h.tlsCertWriter.EnsureCertFiles(ctx, gatewayUUID, dto.target.Host, certPaths); err != nil {
					h.logger.WithError(err).Warn("failed to ensure TLS cert files exist")
				}
			}
		}
		conf, err := config.BuildTLSConfigFromClientConfig(tlsConf)
		if err != nil {
			return nil, fmt.Errorf("failed to build TLS config: %w", err)
		}
		return h.tlsClientCache.GetOrCreate(dto.target.ID, conf, proxyAddr, proxyProtocol), nil

	case dto.target.InsecureSSL:
		conf, err := config.BuildTLSConfigFromClientConfig(types.ClientTLSConfigDTO{AllowInsecureConnections: true})
		if err != nil {
			return nil, fmt.Errorf("failed to build insecure TLS config: %w", err)
		}
		return h.tlsClientCache.GetOrCreate(dto.target.ID+"-insecure", conf, proxyAddr, proxyProtocol), nil

	case proxyAddr != "":
		return h.tlsClientCache.GetOrCreate(dto.target.ID+"-proxy", nil, proxyAddr, proxyProtocol), nil

	default:
		return h.client, nil
	}
}

func parseUUID(s string) (uuid.UUID, error) {
	return uuid.Parse(s)
}

func (h *forwardedHandler) prepareHTTPClient(dto *forwardedRequestDTO) (*http.Client, error) {
	transport := &http.Transport{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 100,
		IdleConnTimeout:     90 * time.Second,
	}

	tlsConf, hasTLS := dto.tlsConfig[dto.target.Host]

	if dto.proxy != nil {
		proxyURL, err := url.Parse(fmt.Sprintf("%s://%s:%s", dto.proxy.Protocol, dto.proxy.Host, dto.proxy.Port))
		if err != nil {
			return nil, fmt.Errorf("failed to parse proxy URL: %w", err)
		}
		transport.Proxy = http.ProxyURL(proxyURL)
		h.logger.Debug("using proxy " + proxyURL.String())
	}

	switch {
	case hasTLS:
		if dto.target.InsecureSSL {
			tlsConf.AllowInsecureConnections = true
		}
		tlsConfig, err := config.BuildTLSConfigFromClientConfig(tlsConf)
		if err != nil {
			return nil, fmt.Errorf("failed to build TLS config: %w", err)
		}
		transport.TLSClientConfig = tlsConfig

	case dto.target.InsecureSSL:
		transport.TLSClientConfig = &tls.Config{
			InsecureSkipVerify: true, //#nosec G402
		}
	}

	return &http.Client{
		Timeout:   h.cfg.Upstream.StreamTimeout,
		Transport: transport,
	}, nil
}

func (h *forwardedHandler) applyAuthentication(req *fasthttp.Request, creds *types.CredentialsDTO, body []byte) {
	if creds == nil {
		return
	}

	if creds.HeaderName != "" && creds.HeaderValue != "" {
		req.Header.Set(creds.HeaderName, creds.HeaderValue)
	}

	if creds.ParamName == "" || creds.ParamValue == "" {
		return
	}

	switch creds.ParamLocation {
	case "query":
		req.URI().QueryArgs().Set(creds.ParamName, creds.ParamValue)
	case "body":
		if len(body) == 0 {
			return
		}

		var p fastjson.Parser
		parsedBody, err := p.ParseBytes(body)
		if err != nil {
			h.logger.WithError(err).Error("Failed to parse request body")
			return
		}

		parsedBody.GetObject().Set(creds.ParamName, fastjson.MustParse(fmt.Sprintf(`"%s"`, creds.ParamValue)))
		req.SetBodyRaw(parsedBody.MarshalTo(nil))
	}
}

func (h *forwardedHandler) handleStreamingRequest(dto *forwardedRequestDTO, client *http.Client) (*types.ResponseContext, error) {
	return h.handleStreamingResponse(dto, client)
}

func (h *forwardedHandler) handleStreamingResponse(dto *forwardedRequestDTO, client *http.Client) (*types.ResponseContext, error) {
	upstreamURL := h.rewriteTargetURL(dto)
	return infrahttpx.HandleHTTPStream(h.logger, client, upstreamURL, dto.req, dto.target, dto.streamResponse)
}

func (h *forwardedHandler) buildUpstreamTargetUrl(target *types.UpstreamTargetDTO, pathParams map[string]string) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("%s://%s", target.Protocol, target.Host))
	if (target.Protocol == "https" && target.Port != 443) || (target.Protocol == "http" && target.Port != 80) {
		sb.WriteString(fmt.Sprintf(":%d", target.Port))
	}

	targetPath := target.Path
	if len(pathParams) > 0 {
		targetPath = h.replacePathParams(targetPath, pathParams)
	}

	sb.WriteString(targetPath)
	return sb.String()
}

func (h *forwardedHandler) replacePathParams(path string, pathParams map[string]string) string {
	result := path
	for paramName, paramValue := range pathParams {
		paramPlaceholder := "{" + paramName + "}"
		if strings.Contains(result, paramPlaceholder) {
			result = strings.ReplaceAll(result, paramPlaceholder, paramValue)
		}
	}
	return result
}

func (h *forwardedHandler) getPathParamsFromContext(ctx context.Context) map[string]string {
	if pathParams := ctx.Value(common.PathParamsKey); pathParams != nil {
		if params, ok := pathParams.(map[string]string); ok {
			return params
		}
	}
	return nil
}

func (h *forwardedHandler) handleStreamingResponseByProvider(
	req *types.RequestContext,
	target *types.UpstreamTargetDTO,
	streamResponse chan []byte,
) (*types.ResponseContext, error) {
	return infrahttpx.HandleProviderStream(h.logger, h.providerLocator, h.adapterRegistry, req, target, streamResponse, h.cfg.Upstream.ErrorPassthrough)
}

func (h *forwardedHandler) getQueryParams(c *fiber.Ctx) url.Values {
	queryParams := make(url.Values)
	c.Request().URI().QueryArgs().VisitAll(func(k, v []byte) {
		queryParams.Set(string(k), string(v))
	})
	return queryParams
}

func (h *forwardedHandler) createResponse(resp *fasthttp.Response, body []byte) *types.ResponseContext {
	response := &types.ResponseContext{
		StatusCode: resp.StatusCode(),
		Headers:    make(map[string][]string, resp.Header.Len()),
		Body:       body,
	}
	resp.Header.VisitAll(func(key, value []byte) {
		k := string(key)
		response.Headers[k] = append(response.Headers[k], string(value))
	})
	return response
}

func (h *forwardedHandler) registryFailedEvent(
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
				Protocol: rsp.Target.Protocol,
				Provider: rsp.Target.Provider,
				Headers:  rsp.Target.Headers,
			}
		}
	}
	collector.Emit(evt)
}

func (h *forwardedHandler) registrySuccessEvent(
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
			Protocol: rsp.Target.Protocol,
			Provider: rsp.Target.Provider,
			Headers:  rsp.Target.Headers,
			Latency:  int64(rsp.TargetLatency),
		}
	}
	collector.Emit(evt)
}

func safeStatusCode(status, fallback int) int {
	if status > 0 {
		return status
	}
	return fallback
}
