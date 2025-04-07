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
	"github.com/NeuralTrust/TrustGate/pkg/database"
	domainService "github.com/NeuralTrust/TrustGate/pkg/domain/service"
	domainUpstream "github.com/NeuralTrust/TrustGate/pkg/domain/upstream"
	"github.com/NeuralTrust/TrustGate/pkg/loadbalancer"
	"github.com/NeuralTrust/TrustGate/pkg/metrics"
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
	repo                *database.Repository
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
}

func NewForwardedHandler(
	logger *logrus.Logger,
	repo *database.Repository,
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
		repo:                repo,
		cache:               c,
		gatewayCache:        c.GetTTLMap(cache.GatewayTTLName),
		upstreamFinder:      upstreamFinder,
		serviceFinder:       serviceFinder,
		providers:           providers,
		pluginManager:       pluginManager,
		client:              client,
		loadBalancerFactory: loadBalancerFactory,
		cfg:                 cfg,
	}
}

type RequestData struct {
	Headers map[string][]string
	Body    []byte
	Uri     string
	Host    string
	Method  string
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
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "internal server error"})
	}

	gatewayID, ok := gatewayIDAny.(string)
	if !ok {
		h.logger.Error("gateway ID not found in Fiber context")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Internal server error"})
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

	// Create the ResponseContext
	respCtx := &types.ResponseContext{
		Context:   c.Context(),
		GatewayID: gatewayID,
		Headers:   make(map[string][]string),
		Metadata:  make(map[string]interface{}),
	}

	// get gateway data set in plugin_chain middleware
	gatewayData, ok := c.Locals(common.GatewayDataContextKey).(*types.GatewayData)
	if !ok {
		h.logger.Error("failed to get gateway data in handler")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Internal server error"})
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
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "no matching rule found"})
	}

	// Configure plugins for this request
	if err := h.configureRulePlugins(gatewayID, matchingRule); err != nil {
		h.logger.WithError(err).Error("Failed to configure plugins")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to configure plugins"})
	}

	if _, err := h.pluginManager.ExecuteStage(
		c.Context(),
		types.PreRequest,
		gatewayID,
		reqCtx,
		respCtx,
	); err != nil {
		var pluginErr *types.PluginError
		if errors.As(err, &pluginErr) {
			for k, values := range respCtx.Headers {
				for _, v := range values {
					c.Set(k, v)
				}
			}
			return c.Status(pluginErr.StatusCode).JSON(fiber.Map{
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
			return c.Status(respCtx.StatusCode).Send(respCtx.Body)
		}
		if !h.cfg.Plugins.IgnoreErrors {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Plugin execution failed"})
		}
	}

	if respCtx.StopProcessing {
		for k, values := range respCtx.Headers {
			for _, v := range values {
				c.Set(k, v)
			}
		}
		return c.Status(respCtx.StatusCode).Send(respCtx.Body)
	}
	// Forward the request
	response, err := h.forwardRequest(reqCtx, matchingRule)
	if err != nil {
		h.logger.WithError(err).Error("Failed to forward request")
		return c.Status(fiber.StatusBadGateway).JSON(fiber.Map{
			"error":   "failed to forward request",
			"message": err.Error(),
		})
	}

	// Record upstream latency if available
	if metrics.Config.EnableUpstreamLatency {
		upstreamLatency := float64(time.Since(startTime).Milliseconds())
		metrics.GatewayUpstreamLatency.WithLabelValues(
			gatewayID,
			matchingRule.ServiceID,
			matchingRule.ID,
		).Observe(upstreamLatency)
	}

	// Copy response to response context
	respCtx.StatusCode = response.StatusCode
	respCtx.Body = response.Body
	for k, v := range response.Headers {
		respCtx.Headers[k] = v
	}

	if response.StatusCode >= http.StatusBadRequest {
		// Parse the error response
		var errorResponse map[string]interface{}
		if err := json.Unmarshal(response.Body, &errorResponse); err != nil {
			return c.Status(response.StatusCode).JSON(fiber.Map{"error": "upstream service error"})
		}

		// Copy all headers from response context to client response
		for k, values := range respCtx.Headers {
			for _, v := range values {
				c.Set(k, v)
			}
		}

		// Return the original error response
		return c.Status(response.StatusCode).JSON(errorResponse)
	}

	// Execute pre-response plugins
	if _, err := h.pluginManager.ExecuteStage(c.Context(), types.PreResponse, gatewayID, reqCtx, respCtx); err != nil {
		var pluginErr *types.PluginError
		if errors.As(err, &pluginErr) {
			// Copy headers from response context
			for k, values := range respCtx.Headers {
				for _, v := range values {
					c.Set(k, v)
				}
			}
			return c.Status(pluginErr.StatusCode).JSON(fiber.Map{
				"error":       pluginErr.Message,
				"retry_after": respCtx.Metadata["retry_after"],
			})
		}

		if !h.cfg.Plugins.IgnoreErrors {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Plugin execution failed"})
		}
	}

	// Execute post-response plugins
	if _, err := h.pluginManager.ExecuteStage(
		c.Context(),
		types.PostResponse,
		gatewayID,
		reqCtx,
		respCtx,
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

			return c.Status(pluginErr.StatusCode).JSON(fiber.Map{
				"error":       pluginErr.Message,
				"retry_after": respCtx.Metadata["retry_after"],
			})
		}
		if !h.cfg.Plugins.IgnoreErrors {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Plugin execution failed"})
		}

	}

	// Copy all headers from response context to client response
	for k, values := range respCtx.Headers {
		for _, v := range values {
			c.Set(k, v)
		}
	}

	duration := time.Since(startTime).Milliseconds()

	if metrics.Config.EnableLatency {
		metrics.GatewayRequestLatency.WithLabelValues(
			gatewayID,
			c.Path(),
		).Observe(float64(duration))
	}

	if metrics.Config.EnablePerRoute {
		metrics.GatewayDetailedLatency.WithLabelValues(
			gatewayID,
			matchingRule.ServiceID,
			matchingRule.ID,
		).Observe(float64(duration))
	}

	// Write the response body
	return c.Status(respCtx.StatusCode).Send(respCtx.Body)

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
) (*types.ResponseContext, error) {
	serviceEntity, err := h.serviceFinder.Find(req.Context, rule.GatewayID, rule.ServiceID)
	if err != nil {
		return nil, fmt.Errorf("service not found: %w", err)
	}
	switch serviceEntity.Type {
	case domainService.TypeUpstream:
		return h.handleUpstreamRequest(req, rule, serviceEntity)
	case domainService.TypeEndpoint:
		return h.handleEndpointRequest(req, rule, serviceEntity)
	default:
		return nil, fmt.Errorf("unsupported service type: %s", serviceEntity.Type)
	}
}
func (h *forwardedHandler) handleUpstreamRequest(
	req *types.RequestContext,
	rule *types.ForwardingRule,
	serviceEntity *domainService.Service,
) (*types.ResponseContext, error) {
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
		target, err := lb.NextTarget(req.Context)
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

		response, err := h.doForwardRequest(req, rule, target)
		reqErr = err
		if err == nil {
			lb.ReportSuccess(target)
			return response, nil
		}
		lb.ReportFailure(target, err)
	}

	return nil, fmt.Errorf("%v", reqErr)
}

func (h *forwardedHandler) handleEndpointRequest(
	req *types.RequestContext,
	rule *types.ForwardingRule,
	serviceEntity *domainService.Service,
) (*types.ResponseContext, error) {
	target := &types.UpstreamTarget{
		Host:        serviceEntity.Host,
		Port:        serviceEntity.Port,
		Protocol:    serviceEntity.Protocol,
		Path:        serviceEntity.Path,
		Headers:     serviceEntity.Headers,
		Credentials: serviceEntity.Credentials,
	}
	return h.doForwardRequest(req, rule, target)
}

// Add helper method to create or get load balancer
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
	req *types.RequestContext,
	rule *types.ForwardingRule,
	target *types.UpstreamTarget,
) (*types.ResponseContext, error) {

	var sb strings.Builder
	if target.Provider != "" {
		providerConfig, ok := h.providers[target.Provider]
		if !ok {
			return nil, fmt.Errorf("unsupported provider: %s", target.Provider)
		}
		endpointConfig, ok := providerConfig.Endpoints[target.Path]
		if !ok {
			return nil, fmt.Errorf("unsupported endpoint path: %s", target.Path)
		}
		sb.WriteString(providerConfig.BaseURL)
		sb.WriteString(endpointConfig.Path)
	} else {
		sb.WriteString(target.Protocol)
		sb.WriteString("://")
		sb.WriteString(target.Host)
		sb.WriteString(":")
		sb.WriteString(strconv.Itoa(target.Port))
		sb.WriteString(target.Path)
	}
	targetURL := sb.String()

	if rule.StripPath {
		targetURL = strings.TrimSuffix(targetURL, "/") + strings.TrimPrefix(req.Path, rule.Path)
	}

	fastHttpReq := fasthttp.AcquireRequest()
	defer fasthttp.ReleaseRequest(fastHttpReq)

	fastHttpResp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseResponse(fastHttpResp)

	fastHttpReq.SetRequestURI(targetURL)
	fastHttpReq.Header.SetMethod(req.Method)

	if len(req.Body) > 0 {
		var requestBody map[string]interface{}
		if err := json.Unmarshal(req.Body, &requestBody); err == nil {
			if streamValue, exists := requestBody["stream"]; exists {
				if isStream, ok := streamValue.(bool); ok && isStream {
					return h.handleStreamingRequest(req, target)
				}
			}
		}
		if target.Provider != "" {
			transformedBody, err := h.transformRequestBody(req.Body, target)
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

	err := h.client.DoTimeout(fastHttpReq, fastHttpResp, 30*time.Second)
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

	go h.logger.WithFields(logrus.Fields{
		"provider": target.Provider,
	}).Debug("Selected provider")

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
) (*types.ResponseContext, error) {
	// Transform request body if needed
	transformedBody, err := h.transformRequestBody(req.Body, target)
	if err != nil {
		return nil, fmt.Errorf("failed to transform streaming request: %w", err)
	}

	req.Body = transformedBody

	return h.handleStreamingResponse(req, target)
}

func (h *forwardedHandler) handleStreamingResponse(
	req *types.RequestContext,
	target *types.UpstreamTarget,
) (*types.ResponseContext, error) {
	providerConfig, ok := h.providers[target.Provider]
	if !ok {
		return nil, fmt.Errorf("unsupported provider: %s", target.Provider)
	}

	endpointConfig, ok := providerConfig.Endpoints[target.Path]
	if !ok {
		return nil, fmt.Errorf("unsupported endpoint path: %s", target.Path)
	}

	upstreamURL := fmt.Sprintf("%s%s", providerConfig.BaseURL, endpointConfig.Path)

	httpReq, err := http.NewRequestWithContext(req.Context, req.Method, upstreamURL, bytes.NewReader(req.Body))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Copy headers
	for k, v := range req.Headers {
		if k != "Host" {
			for _, val := range v {
				httpReq.Header.Add(k, val)
			}
		}
	}

	// Set required headers for streaming
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "text/event-stream")
	httpReq.Header.Set("Cache-Control", "no-cache")
	httpReq.Header.Set("Connection", "keep-alive")

	// Apply authentication and target headers
	if target.Credentials.HeaderValue != "" {
		httpReq.Header.Set(target.Credentials.HeaderName, target.Credentials.HeaderValue)
	}
	for k, v := range target.Headers {
		httpReq.Header.Set(k, v)
	}

	resp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to make streaming request: %w", err)
	}
	defer resp.Body.Close()

	responseHeaders := make(map[string][]string)
	for k, v := range resp.Header {
		responseHeaders[k] = v
	}
	responseHeaders["X-Selected-Provider"] = []string{target.Provider}

	if rateLimitHeaders, ok := req.Metadata["rate_limit_headers"].(map[string][]string); ok {
		for k, v := range rateLimitHeaders {
			responseHeaders[k] = v
		}
	}

	reader := bufio.NewReader(resp.Body)
	var lastUsage map[string]interface{}
	var responseBody []byte

	for {
		line, err := reader.ReadBytes('\n')
		if err != nil {
			if err == io.EOF {
				break
			}
			h.logger.WithError(err).Error("Error reading streaming response")
			break
		}

		if bytes.HasPrefix(line, []byte("data: ")) {
			if bytes.Equal(line, []byte("data: [DONE]\n")) {
				if lastUsage != nil {
					req.Metadata["token_usage"] = lastUsage
					h.logger.WithFields(logrus.Fields{
						"token_usage": lastUsage,
					}).Debug("Stored token usage from streaming response")
				}
				responseBody = append(responseBody, line...)
				continue
			}

			jsonData := line[6:]
			var response map[string]interface{}
			if err := json.Unmarshal(jsonData, &response); err == nil {
				if usage, ok := response["usage"].(map[string]interface{}); ok {
					lastUsage = usage
				}
			}
		}
		responseBody = append(responseBody, line...)
	}

	if lastUsage != nil && req.Metadata["token_usage"] == nil {
		req.Metadata["token_usage"] = lastUsage
		h.logger.WithFields(logrus.Fields{
			"token_usage": lastUsage,
		}).Debug("Stored token usage from last chunk")
	}

	return &types.ResponseContext{
		StatusCode: resp.StatusCode,
		Headers:    responseHeaders,
		Body:       responseBody,
		Streaming:  true,
		Metadata:   req.Metadata,
	}, nil
}

func (h *forwardedHandler) getQueryParams(c *fiber.Ctx) url.Values {
	queryParams := make(url.Values)
	c.Request().URI().QueryArgs().VisitAll(func(k, v []byte) {
		queryParams.Set(string(k), string(v))
	})
	return queryParams
}

func (h *forwardedHandler) transformRequestBody(body []byte, target *types.UpstreamTarget) ([]byte, error) {
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
