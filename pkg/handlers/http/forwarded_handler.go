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
	"github.com/NeuralTrust/TrustGate/pkg/database"
	"github.com/NeuralTrust/TrustGate/pkg/loadbalancer"
	"github.com/NeuralTrust/TrustGate/pkg/metrics"
	"github.com/NeuralTrust/TrustGate/pkg/middleware"
	"github.com/NeuralTrust/TrustGate/pkg/models"
	"github.com/NeuralTrust/TrustGate/pkg/plugins"
	"github.com/NeuralTrust/TrustGate/pkg/types"
	"github.com/gofiber/fiber/v2"
	"github.com/sirupsen/logrus"
	"github.com/valyala/bytebufferpool"
	"github.com/valyala/fasthttp"
	"github.com/valyala/fastjson"
)

type forwardedHandler struct {
	logger         *logrus.Logger
	repo           *database.Repository
	cache          *cache.Cache
	gatewayCache   *common.TTLMap
	upstreamFinder upstream.Finder
	serviceFinder  service.Finder
	providers      map[string]config.ProviderConfig
	pluginManager  *plugins.Manager
	loadBalancers  sync.Map
	client         *fasthttp.Client
}

func NewForwardedHandler(
	logger *logrus.Logger,
	repo *database.Repository,
	c *cache.Cache,
	upstreamFinder upstream.Finder,
	serviceFinder service.Finder,
	providers map[string]config.ProviderConfig,
	pluginManager *plugins.Manager,
) Handler {

	client := &fasthttp.Client{
		ReadTimeout:                   3 * time.Second,
		WriteTimeout:                  3 * time.Second,
		MaxConnsPerHost:               16384,
		MaxIdleConnDuration:           120 * time.Second,
		ReadBufferSize:                32768,
		WriteBufferSize:               32768,
		NoDefaultUserAgentHeader:      true,
		DisableHeaderNamesNormalizing: true,
		DisablePathNormalizing:        true,
	}

	return &forwardedHandler{
		logger:         logger,
		repo:           repo,
		cache:          c,
		gatewayCache:   c.GetTTLMap(cache.GatewayTTLName),
		upstreamFinder: upstreamFinder,
		serviceFinder:  serviceFinder,
		providers:      providers,
		pluginManager:  pluginManager,
		client:         client,
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

	// Get metadata from gin context
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

	//// Get gateway data with plugins
	gatewayData, err := h.getGatewayData(c.Context(), gatewayID)
	reqCtx.Metadata[string(common.GatewayDataContextKey)] = gatewayData

	if err != nil {
		h.logger.WithError(err).Error("Failed to get gateway data")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Internal server error"})
	}

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
		// Check if path matches
		if strings.HasPrefix(c.Path(), rule.Path) {
			// Convert the rule to models.ForwardingRule
			modelRule := types.ForwardingRule{
				ID:            rule.ID,
				GatewayID:     rule.GatewayID,
				Path:          rule.Path,
				ServiceID:     rule.ServiceID,
				Methods:       rule.Methods,
				Headers:       rule.Headers,
				StripPath:     rule.StripPath,
				PreserveHost:  rule.PreserveHost,
				RetryAttempts: rule.RetryAttempts,
				PluginChain:   rule.PluginChain,
				Active:        rule.Active,
				Public:        rule.Public,
				CreatedAt:     time.Now().Format(time.RFC3339),
				UpdatedAt:     time.Now().Format(time.RFC3339),
			}
			matchingRule = &modelRule
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
		}).Debug("No matching rule found")
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "No matching rule found"})
	}

	// Configure plugins for this request
	if err := h.configurePlugins(gatewayData.Gateway, matchingRule); err != nil {
		h.logger.WithError(err).Error("Failed to configure plugins")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to configure plugins"})
	}

	if _, err := h.pluginManager.ExecuteStage(
		c.Context(),
		types.PreRequest,
		gatewayID,
		matchingRule.ID,
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
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Plugin execution failed"})
	}

	// Forward the request
	response, err := h.forwardRequest(reqCtx, matchingRule)
	if err != nil {
		h.logger.WithError(err).Error("Failed to forward request")
		return c.Status(fiber.StatusBadGateway).JSON(fiber.Map{"error": "Failed to forward request"})
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
			return c.Status(response.StatusCode).JSON(fiber.Map{"error": "Upstream service error"})
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
	if _, err := h.pluginManager.ExecuteStage(c.Context(), types.PreResponse, gatewayID, matchingRule.ID, reqCtx, respCtx); err != nil {
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

		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Plugin execution failed"})
	}

	// Execute post-response plugins
	if _, err := h.pluginManager.ExecuteStage(
		c.Context(),
		types.PostResponse,
		gatewayID,
		matchingRule.ID,
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

		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Plugin execution failed"})
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

func (h *forwardedHandler) getGatewayDataFromCache(value interface{}) (*types.GatewayData, error) {
	data, ok := value.(*types.GatewayData)
	if !ok {
		return nil, fmt.Errorf("invalid type assertion for gateway data")
	}
	return data, nil
}

func (h *forwardedHandler) getGatewayData(ctx context.Context, gatewayID string) (*types.GatewayData, error) {
	// Try memory cache first
	if cached, ok := h.gatewayCache.Get(gatewayID); ok {
		data, err := h.getGatewayDataFromCache(cached)
		if err != nil {
			h.logger.WithError(err).Error("Failed to get gateway data from cache")
		} else {
			return data, nil
		}
	}
	// Try Redis cache
	gatewayData, err := h.getGatewayDataFromRedis(ctx, gatewayID)
	if err == nil {
		h.logger.WithFields(logrus.Fields{
			"gatewayID":  gatewayID,
			"rulesCount": len(gatewayData.Rules),
			"fromCache":  "redis",
		}).Debug("Gateway data found in Redis cache")

		// Store in memory cache
		h.gatewayCache.Set(gatewayID, gatewayData)
		return gatewayData, nil
	}
	h.logger.WithError(err).Debug("Failed to get gateway data from Redis")

	// Fallback to database
	return h.getGatewayDataFromDB(ctx, gatewayID)
}

// Helper function to check if a route is public
func (h *forwardedHandler) isPublicRoute(ctx *fiber.Ctx) bool {
	path := ctx.Path()
	if strings.HasPrefix(path, "/__/") || path == "/health" {
		return true
	}

	// Get gateway data from context
	gatewayData := ctx.Locals("gateway_data")

	if gatewayData == "" {
		return false
	}

	// Check if the route is marked as public in the gateway rules
	if data, ok := gatewayData.(*types.GatewayData); ok {
		for _, rule := range data.Rules {
			if rule.Path == path && rule.Public {
				return true
			}
		}
	}

	return false
}

func (h *forwardedHandler) configurePlugins(gateway *types.Gateway, rule *types.ForwardingRule) error {
	gatewayChains := h.convertGatewayPlugins(gateway)
	if err := h.pluginManager.SetPluginChain(types.GatewayLevel, gateway.ID, gatewayChains); err != nil {
		return fmt.Errorf("failed to configure gateway plugins: %w", err)
	}
	if rule != nil && len(rule.PluginChain) > 0 {
		if err := h.pluginManager.SetPluginChain(types.RuleLevel, rule.ID, rule.PluginChain); err != nil {
			return fmt.Errorf("failed to configure rule plugins: %w", err)
		}
	}
	return nil
}

func (h *forwardedHandler) forwardRequest(req *types.RequestContext, rule *types.ForwardingRule) (*types.ResponseContext, error) {
	serviceEntity, err := h.serviceFinder.Find(req.Context, rule.GatewayID, rule.ServiceID)
	if err != nil {
		return nil, fmt.Errorf("service not found: %w", err)
	}
	switch serviceEntity.Type {
	case models.ServiceTypeUpstream:
		return h.handleUpstreamRequest(req, rule, serviceEntity)
	case models.ServiceTypeEndpoint:
		return h.handleEndpointRequest(req, rule, serviceEntity)
	default:
		return nil, fmt.Errorf("unsupported service type: %s", serviceEntity.Type)
	}
}
func (h *forwardedHandler) handleUpstreamRequest(req *types.RequestContext, rule *types.ForwardingRule, serviceEntity *models.Service) (*types.ResponseContext, error) {
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
		if err == nil {
			lb.ReportSuccess(target)
			return response, nil
		}
		lb.ReportFailure(target, err)
	}

	return nil, fmt.Errorf("all retry attempts failed")
}

func (h *forwardedHandler) handleEndpointRequest(req *types.RequestContext, rule *types.ForwardingRule, serviceEntity *models.Service) (*types.ResponseContext, error) {
	target := &types.UpstreamTarget{
		Host:        serviceEntity.Host,
		Port:        serviceEntity.Port,
		Protocol:    serviceEntity.Protocol,
		Path:        serviceEntity.Path,
		Headers:     serviceEntity.Headers,
		Credentials: types.Credentials(serviceEntity.Credentials),
	}
	return h.doForwardRequest(req, rule, target)
}

// Add helper method to create or get load balancer
func (h *forwardedHandler) getOrCreateLoadBalancer(upstream *models.Upstream) (*loadbalancer.LoadBalancer, error) {
	if lb, ok := h.loadBalancers.Load(upstream.ID); ok {
		if lb, ok := lb.(*loadbalancer.LoadBalancer); ok {
			return lb, nil
		}
	}

	lb, err := loadbalancer.NewLoadBalancer(upstream, h.logger, h.cache)
	if err != nil {
		return nil, err
	}

	h.loadBalancers.Store(upstream.ID, lb)
	return lb, nil
}

func (h *forwardedHandler) getGatewayDataFromRedis(ctx context.Context, gatewayID string) (*types.GatewayData, error) {
	// Get gateway from Redis
	gatewayKey := fmt.Sprintf("gateway:%s", gatewayID)
	gatewayJSON, err := h.cache.Get(ctx, gatewayKey)
	if err != nil {
		return nil, fmt.Errorf("failed to get gateway from Redis: %w", err)
	}

	var gateway *models.Gateway
	if err := json.Unmarshal([]byte(gatewayJSON), &gateway); err != nil {
		return nil, fmt.Errorf("failed to unmarshal gateway from Redis: %w", err)
	}

	// Get rules from Redis
	rulesKey := fmt.Sprintf("rules:%s", gatewayID)
	rulesJSON, err := h.cache.Get(ctx, rulesKey)
	if err != nil {
		return nil, fmt.Errorf("failed to get rules from Redis: %w", err)
	}

	var rules []types.ForwardingRule
	if err := json.Unmarshal([]byte(rulesJSON), &rules); err != nil {
		return nil, fmt.Errorf("failed to unmarshal rules from Redis: %w", err)
	}

	return &types.GatewayData{
		Gateway: h.convertModelToTypesGateway(gateway),
		Rules:   rules,
	}, nil
}

// Helper functions to convert between models and types
func (h *forwardedHandler) convertModelToTypesGateway(g *models.Gateway) *types.Gateway {
	var requiredPlugins []types.PluginConfig
	for _, pluginConfig := range g.RequiredPlugins {
		requiredPlugins = append(requiredPlugins, pluginConfig)
	}
	return &types.Gateway{
		ID:              g.ID,
		Name:            g.Name,
		Subdomain:       g.Subdomain,
		Status:          g.Status,
		RequiredPlugins: requiredPlugins,
	}
}

func (h *forwardedHandler) getGatewayDataFromDB(ctx context.Context, gatewayID string) (*types.GatewayData, error) {
	// Get gateway from database
	gateway, err := h.repo.GetGateway(ctx, gatewayID)
	if err != nil {
		return nil, fmt.Errorf("failed to get gateway from database: %w", err)
	}

	// Get rules from database
	rules, err := h.repo.ListRules(ctx, gatewayID)
	if err != nil {
		return nil, fmt.Errorf("failed to get rules from database: %w", err)
	}

	// Convert models to types
	gatewayData := &types.GatewayData{
		Gateway: h.convertModelToTypesGateway(gateway),
		Rules:   h.convertModelToTypesRules(rules),
	}

	// Cache the results
	if err := h.cacheGatewayData(ctx, gatewayID, gateway, rules); err != nil {
		h.logger.WithError(err).Warn("Failed to cache gateway data")
	}

	h.logger.WithFields(logrus.Fields{
		"gatewayID":       gatewayID,
		"requiredPlugins": gateway.RequiredPlugins,
		"rulesCount":      len(rules),
		"fromCache":       "database",
	}).Debug("Loaded gateway data from database")

	return gatewayData, nil
}

func (h *forwardedHandler) cacheGatewayData(
	ctx context.Context,
	gatewayID string,
	gateway *models.Gateway,
	rules []models.ForwardingRule,
) error {
	// Cache gateway
	gatewayJSON, err := json.Marshal(gateway)
	if err != nil {
		return fmt.Errorf("failed to marshal gateway: %w", err)
	}
	gatewayKey := fmt.Sprintf("gateway:%s", gatewayID)
	if err := h.cache.Set(ctx, gatewayKey, string(gatewayJSON), 0); err != nil {
		return fmt.Errorf("failed to cache gateway: %w", err)
	}

	// Convert and cache rules as types
	typesRules := h.convertModelToTypesRules(rules)
	rulesJSON, err := json.Marshal(typesRules)
	if err != nil {
		return fmt.Errorf("failed to marshal rules: %w", err)
	}
	rulesKey := fmt.Sprintf("rules:%s", gatewayID)
	if err := h.cache.Set(ctx, rulesKey, string(rulesJSON), 0); err != nil {
		return fmt.Errorf("failed to cache rules: %w", err)
	}

	// Cache in memory
	gatewayData := &types.GatewayData{
		Gateway: h.convertModelToTypesGateway(gateway),
		Rules:   typesRules,
	}

	h.gatewayCache.Set(gatewayID, gatewayData)

	return nil
}

func (h *forwardedHandler) convertModelToTypesRules(rules []models.ForwardingRule) []types.ForwardingRule {
	var result []types.ForwardingRule
	for _, r := range rules {
		var pluginChain []types.PluginConfig

		jsonBytes, err := h.getJSONBytes(r.PluginChain)
		if err != nil {
			return []types.ForwardingRule{}
		}

		if err := json.Unmarshal(jsonBytes, &pluginChain); err != nil {
			pluginChain = []types.PluginConfig{} // fallback to empty slice on error
		}

		result = append(result, types.ForwardingRule{
			ID:            r.ID,
			GatewayID:     r.GatewayID,
			Path:          r.Path,
			ServiceID:     r.ServiceID,
			Methods:       r.Methods,
			Headers:       r.Headers,
			StripPath:     r.StripPath,
			PreserveHost:  r.PreserveHost,
			RetryAttempts: r.RetryAttempts,
			PluginChain:   pluginChain,
			Active:        r.Active,
			Public:        r.Public,
			CreatedAt:     r.CreatedAt.Format(time.RFC3339),
			UpdatedAt:     r.UpdatedAt.Format(time.RFC3339),
		})
	}
	return result
}

func (h *forwardedHandler) getJSONBytes(value interface{}) ([]byte, error) {
	switch v := value.(type) {
	case []byte:
		return v, nil
	case string:
		return []byte(v), nil
	case json.RawMessage:
		return v, nil
	default:
		b, err := json.Marshal(value)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal value to JSON bytes: %w", err)
		}
		return b, nil
	}
}

var responseBodyPool = sync.Pool{
	New: func() interface{} {
		return new([]byte)
	},
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
		return nil, fmt.Errorf("failed to forward request: %w", err)
	}

	respBodyPtr := responseBodyPool.Get().(*[]byte)
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

func (h *forwardedHandler) convertGatewayPlugins(gateway *types.Gateway) []types.PluginConfig {
	chains := make([]types.PluginConfig, 0, len(gateway.RequiredPlugins))
	for _, cfg := range gateway.RequiredPlugins {
		if !cfg.Enabled {
			continue
		}

		plugin := h.pluginManager.GetPlugin(cfg.Name)
		if plugin == nil {
			h.logger.WithField("plugin", cfg.Name).Error("Plugin not found")
			continue
		}

		pluginConfig := cfg
		pluginConfig.Level = types.GatewayLevel

		if len(plugin.Stages()) > 0 || cfg.Stage != "" {
			chains = append(chains, pluginConfig)
		} else {
			h.logger.WithField("plugin", cfg.Name).Error("Stage not configured for plugin")
		}
	}
	return chains
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
