package http

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strconv"
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
	infraCache "github.com/NeuralTrust/TrustGate/pkg/infra/cache"
	"github.com/NeuralTrust/TrustGate/pkg/infra/metrics"
	"github.com/NeuralTrust/TrustGate/pkg/infra/metrics/metric_events"
	"github.com/NeuralTrust/TrustGate/pkg/infra/prometheus"
	"github.com/NeuralTrust/TrustGate/pkg/loadbalancer"
	"github.com/NeuralTrust/TrustGate/pkg/middleware"
	"github.com/NeuralTrust/TrustGate/pkg/plugins"
	"github.com/NeuralTrust/TrustGate/pkg/types"
	"github.com/gofiber/fiber/v2"
	"github.com/sirupsen/logrus"
	"github.com/valyala/bytebufferpool"
	"github.com/valyala/fasthttp"
	"github.com/valyala/fastjson"
)

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
	providers           map[string]config.ProviderConfig
	pluginManager       plugins.Manager
	loadBalancers       sync.Map
	client              *fasthttp.Client
	loadBalancerFactory loadbalancer.Factory
	cfg                 *config.Config
	tlsClientCache      *infraCache.TLSClientCache
}

func NewForwardedHandler(
	logger *logrus.Logger,
	c *cache.Cache,
	upstreamFinder upstream.Finder,
	serviceFinder service.Finder,
	providers map[string]config.ProviderConfig,
	pluginManager plugins.Manager,
	loadBalancerFactory loadbalancer.Factory,
	cfg *config.Config,
) Handler {

	client := &fasthttp.Client{
		ReadTimeout:                   30 * time.Second,
		WriteTimeout:                  30 * time.Second,
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
		providers:           providers,
		pluginManager:       pluginManager,
		client:              client,
		loadBalancerFactory: loadBalancerFactory,
		cfg:                 cfg,
		tlsClientCache:      infraCache.NewTLSClientCache(),
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
		return fmt.Errorf("failed to get stream mode channel")
	}
	select {
	case streamMode <- false:
		h.logger.Debug("stream mode disabled")
	default:
	}
	return c.Status(status).JSON(message)
}

func (h *forwardedHandler) handleSuccessResponse(c *fiber.Ctx, status int, message []byte) error {
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

func (h *forwardedHandler) handleSuccessJSONResponse(c *fiber.Ctx, status int, message interface{}) error {
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
		return h.handleErrorResponse(c, fiber.StatusInternalServerError, fiber.Map{"error": "internal server error"})
	}

	reqCtx.Metadata[string(common.GatewayDataContextKey)] = gatewayData

	// Find matching rule
	var matchingRule *types.ForwardingRule
	for _, rule := range gatewayData.Rules {
		if !rule.Active {
			continue
		}
		// Check if method is allowed
		methodAllowed := false
		for _, m := range rule.Methods {
			if m == reqData.Method {
				methodAllowed = true
				break
			}
		}
		if !methodAllowed {
			continue
		}

		if c.Path() == rule.Path {
			matchingRule = &rule
			// Store rule and service info in context for metrics
			c.Set(middleware.RouteIDKey, rule.ID)
			c.Set(middleware.ServiceIDKey, rule.ServiceID)
			reqCtx.RuleID = rule.ID
			break
		}
	}

	if matchingRule == nil {
		h.logger.WithFields(logrus.Fields{
			"path":   c.Path(),
			"method": reqData.Method,
		}).Debug("no matching rule found")
		return h.handleErrorResponse(c, fiber.StatusNotFound, fiber.Map{"error": "no matching rule found"})
	}

	c.Locals(common.MatchedRuleContextKey, matchingRule)
	ctx := context.WithValue(c.Context(), common.MatchedRuleContextKey, matchingRule)
	c.SetUserContext(ctx)

	// Configure plugins for this request
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

	if response.Streaming {
		h.registrySuccessEvent(metricsCollector, respCtx)
		return nil
	}

	// Record upstream latency if available
	if prometheus.Config.EnableUpstreamLatency {
		upstreamLatency := float64(time.Since(startTime).Milliseconds())
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
		go h.logger.WithFields(logrus.Fields{
			"attempt":   attempt + 1,
			"provider":  target.Provider,
			"target_id": target.ID,
		}).Debug("Attempting request")

		select {
		case streamMode <- target.Stream:
		default:
			h.logger.Warn("stream mode channel not ready, skipping")
		}

		response, err := h.doForwardRequest(tlsConfig, req, rule, target, streamResponse)
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
		// Already closed, do nothing
	default:
		close(streamResponse)
	}
	return nil, fmt.Errorf("%v", reqErr)
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
	rsp, err := h.doForwardRequest(tlsConfig, req, rule, target, streamResponse)
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

func (h *forwardedHandler) doForwardRequest(
	tlsConfig map[string]types.ClientTLSConfig,
	req *types.RequestContext,
	rule *types.ForwardingRule,
	target *types.UpstreamTarget,
	streamResponse chan []byte,
) (*types.ResponseContext, error) {

	client := h.client
	tls, ok := tlsConfig[target.Host]
	if ok {
		conf, err := config.BuildTLSConfigFromClientConfig(tls)
		if err != nil {
			return nil, fmt.Errorf("failed to build TLS config: %w", err)
		}
		client = h.tlsClientCache.GetOrCreate(target.ID, conf)
	}

	targetURL, err := h.buildTargetURL(target)
	if err != nil {
		return nil, err
	}

	if rule.StripPath {
		targetURL = strings.TrimSuffix(targetURL, "/") + strings.TrimPrefix(req.Path, rule.Path)
	}

	fastHttpReq := fasthttp.AcquireRequest()
	defer fasthttp.ReleaseRequest(fastHttpReq)

	fastHttpResp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseResponse(fastHttpResp)

	fastHttpReq.SetRequestURI(targetURL)
	fastHttpReq.Header.SetMethod(req.Method)

	if target.Stream {
		return h.handleStreamingRequest(req, target, streamResponse)
	}

	if len(req.Body) > 0 {
		if target.Provider != "" {
			transformedBody, err := h.transformRequestBodyToProvider(req.Body, target)
			if err != nil {
				return nil, fmt.Errorf("failed to transform request body: %w", err)
			}
			fastHttpReq.SetBody(transformedBody)
		} else {
			fastHttpReq.SetBodyRaw(req.Body)
		}
	}

	for k, vals := range req.Headers {
		if len(vals) == 1 {
			fastHttpReq.Header.Set(k, vals[0])
		} else {
			for _, val := range vals {
				fastHttpReq.Header.Add(k, val)
			}
		}
	}
	for k, v := range target.Headers {
		fastHttpReq.Header.Set(k, v)
	}

	h.applyAuthentication(fastHttpReq, &target.Credentials, req.Body)

	err = client.DoTimeout(fastHttpReq, fastHttpResp, 30*time.Second)
	if err != nil {
		return nil, fmt.Errorf("request failed to %s", targetURL)
	}

	respBodyPtr, ok := responseBodyPool.Get().(*[]byte)
	if !ok {
		return nil, errors.New("failed to get response body from pool")
	}
	*respBodyPtr = fastHttpResp.Body()

	statusCode := fastHttpResp.StatusCode()
	if statusCode <= 0 || statusCode >= 600 {
		responseBodyPool.Put(respBodyPtr)
		return nil, fmt.Errorf("invalid status code received: %d", statusCode)
	}
	if statusCode < 200 || statusCode >= 300 {
		responseBodyPool.Put(respBodyPtr)
		return nil, fmt.Errorf("upstream returned status code %d: %s", statusCode, string(*respBodyPtr))
	}

	if target.Provider != "" {
		go h.logger.WithFields(logrus.Fields{
			"provider": target.Provider,
		}).Debug("Selected provider")
	}

	response := h.createResponse(fastHttpResp, *respBodyPtr)
	responseBodyPool.Put(respBodyPtr)

	return response, nil
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
	var providerConfig *config.ProviderConfig
	if target.Provider != "" {
		pConf, ok := h.providers[target.Provider]
		if !ok {
			return nil, fmt.Errorf("unsupported provider: %s", target.Provider)
		}
		providerConfig = &pConf
		transformedBody, err := h.transformRequestBodyToProvider(req.Body, target)
		if err != nil {
			return nil, fmt.Errorf("failed to transform streaming request: %w", err)
		}
		req.Body = transformedBody
	}
	return h.handleStreamingResponse(req, target, providerConfig, streamResponse)
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

func (h *forwardedHandler) buildTargetURL(target *types.UpstreamTarget) (string, error) {
	if target.Provider == "" {
		return h.buildUpstreamTargetUrl(target), nil
	}
	providerConfig, ok := h.providers[target.Provider]
	if !ok {
		return "", fmt.Errorf("unsupported provider: %s", target.Provider)
	}
	endpointConfig, ok := providerConfig.Endpoints[target.Path]
	if !ok {
		return "", fmt.Errorf("unsupported endpoint path: %s", target.Path)
	}
	return fmt.Sprintf("%s%s", providerConfig.BaseURL, endpointConfig.Path), nil
}

func (h *forwardedHandler) handleStreamingResponse(
	req *types.RequestContext,
	target *types.UpstreamTarget,
	providerConfig *config.ProviderConfig,
	streamResponse chan []byte,
) (*types.ResponseContext, error) {

	upstreamURL := h.buildUpstreamTargetUrl(target)
	if providerConfig != nil {
		if endpointConfig, ok := providerConfig.Endpoints[target.Path]; ok {
			upstreamURL = fmt.Sprintf("%s%s", providerConfig.BaseURL, endpointConfig.Path)
		} else {
			return nil, fmt.Errorf("unsupported endpoint path: %s", target.Path)
		}
	}

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
	for k, v := range resp.Header {
		responseHeaders[k] = v
	}
	if target.Provider != "" {
		req.C.Set("X-Selected-Provider", target.Provider)
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

func (h *forwardedHandler) transformRequestBodyToProvider(body []byte, target *types.UpstreamTarget) ([]byte, error) {
	if len(body) == 0 {
		return body, nil
	}

	var parser fastjson.Parser
	parsedBody, err := parser.ParseBytes(body)
	if err != nil {
		return nil, fmt.Errorf("failed to parse request body: %w", err)
	}

	targetEndpointConfig, ok := h.providers[target.Provider].Endpoints[target.Path]
	if !ok || targetEndpointConfig.Schema == nil {
		return nil, fmt.Errorf("missing schema for target provider %s endpoint %s", target.Provider, target.Path)
	}

	obj := parsedBody.GetObject()
	modelName := obj.Get("model")
	if modelName != nil && modelName.Type() == fastjson.TypeString {
		if !slices.Contains(target.Models, string(modelName.GetStringBytes())) {
			obj.Set("model", fastjson.MustParse(fmt.Sprintf(`"%s"`, target.DefaultModel)))
		}
	} else {
		obj.Set("model", fastjson.MustParse(fmt.Sprintf(`"%s"`, target.DefaultModel)))
	}

	var objMap map[string]interface{}
	if err := json.Unmarshal(parsedBody.MarshalTo(nil), &objMap); err != nil {
		return nil, fmt.Errorf("failed to convert JSON object: %w", err)
	}

	transformed, err := h.mapBetweenSchemas(objMap, targetEndpointConfig.Schema)
	if err != nil {
		return nil, fmt.Errorf("failed to transform request for provider %s endpoint %s: %w", target.Provider, target.Path, err)
	}

	if stream := obj.Get("stream"); stream != nil && stream.Type() == fastjson.TypeTrue {
		transformed["stream"] = true
	}

	buffer := bytebufferpool.Get()
	defer bytebufferpool.Put(buffer)
	jsonData, err := json.Marshal(transformed)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal transformed body: %w", err)
	}
	buffer.B = append(buffer.B[:0], jsonData...)
	return buffer.B, nil
}

func (h *forwardedHandler) mapBetweenSchemas(data map[string]interface{}, targetSchema *config.ProviderSchema) (map[string]interface{}, error) {
	if targetSchema == nil {
		return nil, fmt.Errorf("missing target schema configuration")
	}
	result := make(map[string]interface{}, len(targetSchema.RequestFormat))
	for targetKey, targetField := range targetSchema.RequestFormat {
		if value, err := h.extractValueByPath(data, targetField.Path); err == nil {
			result[targetKey] = value
		} else if targetField.Default != nil {
			result[targetKey] = targetField.Default
		} else if targetField.Required {
			return nil, fmt.Errorf("missing required field %s: %w", targetKey, err)
		}
	}
	return result, nil
}

func (h *forwardedHandler) extractValueByPath(data map[string]interface{}, path string) (interface{}, error) {
	if path == "" {
		return nil, fmt.Errorf("empty path")
	}

	segments := strings.FieldsFunc(path, func(r rune) bool {
		return r == '.' || r == '[' || r == ']'
	})

	var current interface{} = data
	for _, segment := range segments {
		if idx, err := strconv.Atoi(segment); err == nil {
			if arr, ok := current.([]interface{}); ok && idx >= 0 && idx < len(arr) {
				current = arr[idx]
				continue
			}
			return nil, fmt.Errorf("array index out of bounds or not an array: %s", segment)
		}

		if segment == "last" {
			if arr, ok := current.([]interface{}); ok && len(arr) > 0 {
				current = arr[len(arr)-1]
				continue
			}
			return nil, fmt.Errorf("expected array for 'last' access")
		}

		if currentMap, ok := current.(map[string]interface{}); ok {
			if val, exists := currentMap[segment]; exists {
				current = val
				continue
			}
			return nil, fmt.Errorf("key not found: %s", segment)
		}

		return nil, fmt.Errorf("unexpected type at segment: %s", segment)
	}

	return current, nil
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
				Protocol: rsp.Target.Provider,
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
			Protocol: rsp.Target.Provider,
			Provider: rsp.Target.Provider,
			Headers:  rsp.Target.Headers,
		}
	}
	fmt.Println("emit stream response event")
	collector.Emit(evt)
}
