package http

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/app/service"
	"github.com/NeuralTrust/TrustGate/pkg/app/upstream"
	"github.com/NeuralTrust/TrustGate/pkg/cache"
	"github.com/NeuralTrust/TrustGate/pkg/common"
	"github.com/NeuralTrust/TrustGate/pkg/config"
	domainService "github.com/NeuralTrust/TrustGate/pkg/domain/service"
	domainUpstream "github.com/NeuralTrust/TrustGate/pkg/domain/upstream"
	"github.com/NeuralTrust/TrustGate/pkg/infra/auth/oauth"
	infraCache "github.com/NeuralTrust/TrustGate/pkg/infra/cache"
	infrahttpx "github.com/NeuralTrust/TrustGate/pkg/infra/httpx"
	"github.com/NeuralTrust/TrustGate/pkg/infra/metrics"
	"github.com/NeuralTrust/TrustGate/pkg/infra/metrics/metric_events"
	"github.com/NeuralTrust/TrustGate/pkg/infra/prometheus"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/factory"
	"github.com/NeuralTrust/TrustGate/pkg/loadbalancer"
	"github.com/NeuralTrust/TrustGate/pkg/plugins"
	"github.com/NeuralTrust/TrustGate/pkg/types"
	"github.com/gofiber/fiber/v2"
	"github.com/sirupsen/logrus"
	"github.com/valyala/fasthttp"
	"github.com/valyala/fastjson"
)

type forwardedRequestDTO struct {
	tlsConfig      map[string]types.ClientTLSConfig
	req            *types.RequestContext
	rule           *types.ForwardingRule
	target         *types.UpstreamTarget
	proxy          *domainUpstream.Proxy
	streamResponse chan []byte
}

var responseBodyPool = sync.Pool{
	New: func() interface{} {
		return new([]byte)
	},
}

type forwardedHandler struct {
	logger              *logrus.Logger
	cache               *cache.Cache
	gatewayCache        *common.TTLMap
	upstreamFinder      upstream.Finder
	serviceFinder       service.Finder
	pluginManager       plugins.Manager
	loadBalancers       sync.Map
	client              *fasthttp.Client
	loadBalancerFactory loadbalancer.Factory
	cfg                 *config.Config
	tlsClientCache      *infraCache.TLSClientCache
	providerLocator     factory.ProviderLocator
	tokenClient         oauth.TokenClient
}

func NewForwardedHandler(
	logger *logrus.Logger,
	c *cache.Cache,
	upstreamFinder upstream.Finder,
	serviceFinder service.Finder,
	pluginManager plugins.Manager,
	loadBalancerFactory loadbalancer.Factory,
	cfg *config.Config,
	providerLocator factory.ProviderLocator,
	tokenClient oauth.TokenClient,
) Handler {

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

	return &forwardedHandler{
		logger:              logger,
		cache:               c,
		gatewayCache:        c.GetTTLMap(cache.GatewayTTLName),
		upstreamFinder:      upstreamFinder,
		serviceFinder:       serviceFinder,
		pluginManager:       pluginManager,
		client:              client,
		loadBalancerFactory: loadBalancerFactory,
		cfg:                 cfg,
		tlsClientCache:      infraCache.NewTLSClientCache(logger),
		providerLocator:     providerLocator,
		tokenClient:         tokenClient,
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

	matchingRule, ok := c.Locals(string(common.MatchedRuleContextKey)).(*types.ForwardingRule)
	if !ok {
		h.logger.Error("failed to get matched rule from context")
		return h.handleErrorResponse(c, fiber.StatusInternalServerError, fiber.Map{"error": "internal server error"})
	}

	// Create the RequestContext
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
			// Also copy headers from the pluginErr if present
			if pluginErr.Headers != nil {
				for k, values := range pluginErr.Headers {
					for _, v := range values {
						c.Set(k, v)
					}
				}
			}
			h.registryFailedEvent(
				metricsCollector,
				pluginErr.StatusCode,
				pluginErr.Err,
				respCtx,
			)
			return h.handleErrorResponse(c, pluginErr.StatusCode, fiber.Map{
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
			return h.handleSuccessResponse(c, respCtx.StatusCode, respCtx.Body)
		}
		if !h.cfg.Plugins.IgnoreErrors {
			return h.handleErrorResponse(c, fiber.StatusInternalServerError, fiber.Map{"error": "Plugin execution failed"})
		}
	}

	if respCtx.StopProcessing {
		for k, values := range respCtx.Headers {
			for _, v := range values {
				c.Set(k, v)
			}
		}
		return h.handleSuccessResponse(c, respCtx.StatusCode, respCtx.Body)
	}
	// Forward the request
	upstreamStartTime := time.Now()
	response, err := h.forwardRequest(
		reqCtx,
		matchingRule,
		gatewayData.Gateway.TlS,
	)
	if err != nil {
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

	if response.Streaming {
		respCtx.Streaming = true
		h.registrySuccessEvent(metricsCollector, respCtx)
		return nil
	}

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
			h.registryFailedEvent(metricsCollector, pluginErr.StatusCode, pluginErr.Err, respCtx)
			return h.handleErrorResponse(c, pluginErr.StatusCode, fiber.Map{
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
			h.registryFailedEvent(metricsCollector, pluginErr.StatusCode, pluginErr.Err, respCtx)
			return h.handleErrorResponse(c, pluginErr.StatusCode, fiber.Map{
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

func (h *forwardedHandler) configureRulePlugins(gatewayID string, rule *types.ForwardingRule) error {
	// The last call SetPluginChain is here
	if rule != nil && len(rule.PluginChain) > 0 {
		if err := h.pluginManager.SetPluginChain(gatewayID, rule.PluginChain); err != nil {
			return fmt.Errorf("failed to configure rule plugins: %w", err)
		}
	}
	return nil
}

func (h *forwardedHandler) forwardRequest(
	req *types.RequestContext,
	rule *types.ForwardingRule,
	tlsConfig map[string]types.ClientTLSConfig,
) (*types.ResponseContext, error) {
	serviceEntity, err := h.serviceFinder.Find(req.Context, rule.GatewayID, rule.ServiceID)
	if err != nil {
		return nil, fmt.Errorf("service not found: %w", err)
	}
	switch serviceEntity.Type {
	case domainService.TypeUpstream:
		return h.handleUpstreamRequest(req, rule, serviceEntity, tlsConfig)
	case domainService.TypeEndpoint:
		return h.handleEndpointRequest(req, rule, serviceEntity, tlsConfig)
	default:
		return nil, fmt.Errorf("unsupported service type: %s", serviceEntity.Type)
	}
}
func (h *forwardedHandler) handleUpstreamRequest(
	req *types.RequestContext,
	rule *types.ForwardingRule,
	serviceEntity *domainService.Service,
	tlsConfig map[string]types.ClientTLSConfig,
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

	upstreamModel, err := h.upstreamFinder.Find(req.Context, serviceEntity.GatewayID, serviceEntity.UpstreamID)
	if err != nil {
		return nil, fmt.Errorf("upstream not found: %w", err)
	}

	lb, err := h.getOrCreateLoadBalancer(upstreamModel)
	if err != nil {
		return nil, fmt.Errorf("failed to get load balancer: %w", err)
	}

	maxRetries := rule.RetryAttempts
	if maxRetries == 0 {
		maxRetries = 2
	}

	var reqErr error
	for attempt := 0; attempt <= maxRetries; attempt++ {
		target, err := lb.NextTarget(req)
		if err != nil {
			if attempt == maxRetries {
				return nil, fmt.Errorf("failed to get target after retries: %w", err)
			}
			continue
		}
		h.logger.WithFields(logrus.Fields{
			"attempt":   attempt + 1,
			"provider":  target.Provider,
			"target_id": target.ID,
		}).Debug("Attempting request")

		if err := h.applyTargetOAuth(req, target, upstreamModel); err != nil {
			h.logger.WithError(err).Error("failed to obtain oauth token for target")
			return nil, fmt.Errorf("failed to obtain oauth token: %w", err)
		}

		select {
		case streamMode <- target.Stream:
		default:
			h.logger.Warn("stream mode channel not ready, skipping")
		}

		response, err := h.doForwardRequest(
			&forwardedRequestDTO{
				req:            req,
				rule:           rule,
				target:         target,
				tlsConfig:      tlsConfig,
				streamResponse: streamResponse,
				proxy:          upstreamModel.Proxy,
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
		lb.ReportFailure(target, err)
	}
	select {
	case <-streamResponse:
	default:
		close(streamResponse)
	}
	return nil, fmt.Errorf("%v", reqErr)
}

func (h *forwardedHandler) applyTargetOAuth(req *types.RequestContext, target *types.UpstreamTarget, upstreamModel *domainUpstream.Upstream) error {
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

func (h *forwardedHandler) handleEndpointRequest(
	req *types.RequestContext,
	rule *types.ForwardingRule,
	serviceEntity *domainService.Service,
	tlsConfig map[string]types.ClientTLSConfig,
) (*types.ResponseContext, error) {
	streamResponse, ok := req.C.Locals(common.StreamResponseContextKey).(chan []byte)
	if !ok || streamResponse == nil {
		h.logger.Error("failed to get stream response channel")
		return nil, fmt.Errorf("failed to make read response channel")
	}

	target := &types.UpstreamTarget{
		Host:        serviceEntity.Host,
		Port:        serviceEntity.Port,
		Protocol:    serviceEntity.Protocol,
		Path:        serviceEntity.Path,
		Headers:     serviceEntity.Headers,
		Credentials: serviceEntity.Credentials,
		Stream:      serviceEntity.Stream,
	}
	rsp, err := h.doForwardRequest(&forwardedRequestDTO{
		req:            req,
		rule:           rule,
		target:         target,
		tlsConfig:      tlsConfig,
		streamResponse: streamResponse,
	})
	if err != nil {
		h.logger.WithError(err).Error("failed to forward request")
		select {
		case <-streamResponse:
			// Channel already closed, skip
		default:
			close(streamResponse)
		}
		return nil, fmt.Errorf("failed to forward request: %w", err)
	}
	if !target.Stream {
		close(streamResponse)
	}
	rsp.Target = target
	return rsp, nil
}

func (h *forwardedHandler) getOrCreateLoadBalancer(upstream *domainUpstream.Upstream) (*loadbalancer.LoadBalancer, error) {
	if lb, ok := h.loadBalancers.Load(upstream.ID); ok {
		if lb, ok := lb.(*loadbalancer.LoadBalancer); ok {
			return lb, nil
		}
	}

	lb, err := loadbalancer.NewLoadBalancer(h.loadBalancerFactory, upstream, h.logger, h.cache)
	if err != nil {
		return nil, err
	}

	h.loadBalancers.Store(upstream.ID, lb)
	return lb, nil
}

func (h *forwardedHandler) handlerProviderResponse(
	req *types.RequestContext,
	target *types.UpstreamTarget,
) (*types.ResponseContext, error) {
	providerClient, err := h.providerLocator.Get(target.Provider)
	if err != nil {
		return nil, fmt.Errorf("failed to get streaming provider client: %w", err)
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
		req.Body,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to get completions: %w", err)
	}

	req.C.Set("X-Selected-Provider", target.Provider)
	req.C.Set("Content-Type", "application/json")

	return &types.ResponseContext{
		StatusCode: http.StatusOK,
		Headers:    map[string][]string{"X-Selected-Provider": {target.Provider}},
		Body:       responseBody,
	}, nil

}

func (h *forwardedHandler) doForwardRequest(dto *forwardedRequestDTO) (*types.ResponseContext, error) {
	if dto.target.Provider != "" {
		if dto.target.Stream {
			return h.handleStreamingResponseByProvider(dto.req, dto.target, dto.streamResponse)
		}
		return h.handlerProviderResponse(dto.req, dto.target)
	}

	client, err := h.prepareClient(dto)
	if err != nil {
		return nil, err
	}

	if dto.target.Stream {
		return h.handleStreamingRequest(dto.req, dto.target, dto.streamResponse)
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
	l := h.buildUpstreamTargetUrl(dto.target)
	if dto.rule != nil && dto.rule.StripPath && strings.HasPrefix(dto.req.Path, dto.rule.Path) {
		return strings.TrimSuffix(l, "/") + dto.req.Path[len(dto.rule.Path):]
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

func (h *forwardedHandler) prepareClient(dto *forwardedRequestDTO) (*fasthttp.Client, error) {
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
		conf, err := config.BuildTLSConfigFromClientConfig(tlsConf)
		if err != nil {
			return nil, fmt.Errorf("failed to build TLS config: %w", err)
		}
		return h.tlsClientCache.GetOrCreate(dto.target.ID, conf, proxyAddr, proxyProtocol), nil

	case dto.target.InsecureSSL:
		conf, err := config.BuildTLSConfigFromClientConfig(types.ClientTLSConfig{AllowInsecureConnections: true})
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

func (h *forwardedHandler) applyAuthentication(req *fasthttp.Request, creds *types.Credentials, body []byte) {
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

func (h *forwardedHandler) handleStreamingRequest(
	req *types.RequestContext,
	target *types.UpstreamTarget,
	streamResponse chan []byte,
) (*types.ResponseContext, error) {
	return h.handleStreamingResponse(req, target, streamResponse)
}

func (h *forwardedHandler) buildUpstreamTargetUrl(target *types.UpstreamTarget) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("%s://%s", target.Protocol, target.Host))
	if (target.Protocol == "https" && target.Port != 443) || (target.Protocol == "http" && target.Port != 80) {
		sb.WriteString(fmt.Sprintf(":%d", target.Port))
	}
	sb.WriteString(target.Path)
	return sb.String()
}

func (h *forwardedHandler) handleStreamingResponseByProvider(
	req *types.RequestContext,
	target *types.UpstreamTarget,
	streamResponse chan []byte,
) (*types.ResponseContext, error) {

	providerClient, err := h.providerLocator.Get(target.Provider)
	if err != nil {
		return nil, fmt.Errorf("failed to get streaming provider client: %w", err)
	}

	streamChan := make(chan []byte)
	errChan := make(chan error, 1)
	breakChan := make(chan struct{}, 1)

	req.C.Set("Content-Type", "text/event-stream")
	req.C.Set("Cache-Control", "no-cache")
	req.C.Set("Connection", "keep-alive")
	req.C.Set("X-Accel-Buffering", "no")
	req.C.Set("X-Selected-Provider", target.Provider)

	go func() {
		defer close(streamChan)
		err := providerClient.CompletionsStream(
			req,
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
				},
			},
			req.Body,
			streamChan,
			breakChan,
		)
		if err != nil {
			h.logger.WithError(err).Error("failed to stream request")
			errChan <- err
			return
		}
		close(errChan)
	}()

	select {
	case err := <-errChan:
		if err != nil {
			return nil, fmt.Errorf("failed to stream request: %w", err)
		}
	case <-req.C.Context().Done():
		return nil, fmt.Errorf("request cancelled: %w", req.C.Context().Err())
	case <-breakChan:
		break
	case <-time.After(30 * time.Second):
		break
	}

	req.C.Context().SetBodyStreamWriter(func(w *bufio.Writer) {
		defer close(streamResponse)
		for msg := range streamChan {
			if len(msg) > 0 {
				streamResponse <- msg
				_, _ = fmt.Fprintf(w, "data: %s\n\n", msg)
				_ = w.Flush()
			}
		}
	})

	return &types.ResponseContext{
		StatusCode: http.StatusOK,
		Streaming:  true,
		Metadata:   req.Metadata,
		Target:     target,
	}, nil
}

func (h *forwardedHandler) handleStreamingResponse(
	req *types.RequestContext,
	target *types.UpstreamTarget,
	streamResponse chan []byte,
) (*types.ResponseContext, error) {

	upstreamURL := h.buildUpstreamTargetUrl(target)

	httpReq, err := http.NewRequestWithContext(req.Context, req.Method, upstreamURL, bytes.NewReader(req.Body))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	for k, values := range req.Headers {
		if k != "Host" {
			for _, v := range values {
				httpReq.Header.Add(k, v)
			}
		}
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "text/event-stream")
	httpReq.Header.Set("Cache-Control", "no-cache")
	httpReq.Header.Set("Connection", "keep-alive")

	if target.Credentials.HeaderValue != "" {
		httpReq.Header.Set(target.Credentials.HeaderName, target.Credentials.HeaderValue)
	}
	for k, v := range target.Headers {
		httpReq.Header.Set(k, v)
	}
	client := &http.Client{
		Timeout: 60 * time.Second,
	}
	resp, err := client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to make streaming request: %w", err)
	}

	if resp.StatusCode > 299 {
		return nil, fmt.Errorf("failed to make streaming request: %s", resp.Status)
	}

	responseHeaders := make(map[string][]string)

	for key, values := range resp.Header {
		responseHeaders[key] = values
		for _, v := range values {
			req.C.Set(key, v)
		}
	}

	if rateLimitHeaders, ok := req.Metadata["rate_limit_headers"].(map[string][]string); ok {
		for k, v := range rateLimitHeaders {
			responseHeaders[k] = v
		}
	}

	req.C.Set("Content-Type", "text/event-stream")
	req.C.Set("Cache-Control", "no-cache")
	req.C.Set("Connection", "keep-alive")
	req.C.Set("X-Accel-Buffering", "no")

	req.C.Context().SetBodyStreamWriter(func(w *bufio.Writer) {
		defer resp.Body.Close()
		defer close(streamResponse)
		reader := bufio.NewReader(resp.Body)
		for {
			line, err := reader.ReadBytes('\n')
			if err != nil {
				if err == io.EOF {
					break
				}
				h.logger.WithError(err).Error("error reading streaming response")
				break
			}

			if bytes.HasPrefix(line, []byte("data: ")) {
				line = bytes.TrimPrefix(line, []byte("data: "))
			}

			if len(line) > 1 {
				var parsed map[string]interface{}
				var buffer bytes.Buffer

				if err := json.Unmarshal(line, &parsed); err != nil {
					streamResponse <- line
					fmt.Fprintf(w, "data: %s\n", string(line))
					_ = w.Flush()
				} else {
					encoder := json.NewEncoder(&buffer)
					encoder.SetEscapeHTML(false)

					if err := encoder.Encode(parsed); err != nil {
						fmt.Println("Error encoding:", err)
						return
					}
					streamResponse <- buffer.Bytes()
					fmt.Fprintf(w, "data: %s\n", buffer.String())
					_ = w.Flush()
				}
			}
		}
	})

	return &types.ResponseContext{
		StatusCode: resp.StatusCode,
		Headers:    responseHeaders,
		Streaming:  true,
		Metadata:   req.Metadata,
		Target:     target,
	}, nil
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
