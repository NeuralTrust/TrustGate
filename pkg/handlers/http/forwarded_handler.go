package http

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/NeuralTrust/TrustGate/pkg/app/upstream"
	"github.com/NeuralTrust/TrustGate/pkg/cache"
	"github.com/NeuralTrust/TrustGate/pkg/common"
	"github.com/NeuralTrust/TrustGate/pkg/database"
	"github.com/NeuralTrust/TrustGate/pkg/loadbalancer"
	"github.com/NeuralTrust/TrustGate/pkg/metrics"
	"github.com/NeuralTrust/TrustGate/pkg/middleware"
	"github.com/NeuralTrust/TrustGate/pkg/models"
	"github.com/NeuralTrust/TrustGate/pkg/types"
	"github.com/gin-gonic/gin"
	"github.com/gofiber/fiber/v2"
	"github.com/sirupsen/logrus"
	"github.com/valyala/fasthttp"
	"io"
	"net/http"
	"strings"
	"time"
)

const (
	GatewayCacheTTL = 1 * time.Hour
	RulesCacheTTL   = 5 * time.Minute
	PluginCacheTTL  = 30 * time.Minute
)

type ForwardedHandler struct {
	logger         *logrus.Logger
	repo           *database.Repository
	cache          *cache.Cache
	gatewayCache   *common.TTLMap
	upstreamFinder upstream.Finder
	skipAuthCheck  bool
}

func NewForwardedHandler(
	logger *logrus.Logger,
	repo *database.Repository,
	cache *cache.Cache,
	upstreamFinder upstream.Finder,
	skipAuthCheck bool,
) *ForwardedHandler {

	gatewayCache := cache.CreateTTLMap("gateway", GatewayCacheTTL)

	return &ForwardedHandler{
		logger:         logger,
		repo:           repo,
		cache:          cache,
		gatewayCache:   gatewayCache,
		skipAuthCheck:  skipAuthCheck,
		upstreamFinder: upstreamFinder,
	}
}

func (h *ForwardedHandler) Handle(ctx *fiber.Ctx) error {

	// headers := ctx.GetRespHeaders()
	// reqHost := ctx.Hostname()
	// reqMethod := ctx.Method()
	// requestUri := ctx.OriginalURL()

	// Handle auth check - skipAuthCheck now means "using EE auth"
	if !h.skipAuthCheck {
		// CE auth handling
		isPublic := h.isPublicRoute(ctx)
		if !isPublic {
			authHandler := authMiddleware.ValidateAPIKey()
			authHandler(c)
			if c.IsAborted() {
				return
			}
		}
	}
	// Note: When skipAuthCheck is true, we don't do CE auth,
	// allowing EE to handle auth in its middleware chain

	// Only proceed with HandleForward if not aborted
	if !c.IsAborted() {
		s.HandleForward(c)
	}

	return nil

}

func (h *ForwardedHandler) HandleForward(c *gin.Context) {
	// Check if request was already aborted
	if c.IsAborted() {
		h.logger.Debug("Skipping HandleForward for aborted request")
		return
	}

	// Skip handling for system routes
	path := c.Request.URL.Path
	if path == AdminHealthPath || path == HealthPath || path == PingPath {
		c.Next()
		return
	}

	start := time.Now()

	// Add logger to context
	ctx := context.WithValue(c.Request.Context(), common.LoggerKey, s.logger)

	method := c.Request.Method

	// Get gateway ID from context
	gatewayIDAny, exists := c.Get(middleware.GatewayContextKey)
	if !exists {
		h.logger.Error("Gateway ID not found in gin context")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}
	gatewayID, ok := gatewayIDAny.(string)
	if !ok {
		h.logger.Error("Gateway ID not found in gin context")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	// Get metadata from gin context
	var metadata map[string]interface{}
	if md, exists := c.Get("metadata"); exists {
		if m, ok := md.(map[string]interface{}); ok {
			metadata = m
		}
	}

	if metadata == nil {
		metadata = make(map[string]interface{})
		if apiKey, exists := c.Get("api_key"); exists && apiKey != nil {
			metadata["api_key"] = apiKey
		}
	}

	fastCtx, err := getContextValue[*fasthttp.RequestCtx](c.Request.Context(), common.FastHTTPKey)
	if err != nil {
		h.logger.WithError(err).Error("Failed to get FastHTTP context")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}
	// Create the RequestContext
	reqCtx := &types.RequestContext{
		Context:     ctx,
		FasthttpCtx: fastCtx,
		GatewayID:   gatewayID,
		Headers:     make(map[string][]string),
		Method:      method,
		Path:        path,
		Query:       c.Request.URL.Query(),
		Metadata:    metadata,
	}
	// Read the request body
	bodyData, err := io.ReadAll(c.Request.Body)
	if err != nil {
		h.logger.WithError(err).Error("Failed to read request body")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to read request body"})
		return
	}

	// Set the body in the request context
	reqCtx.Body = bodyData

	// Restore the request body for later use
	c.Request.Body = io.NopCloser(bytes.NewBuffer(bodyData))

	// Copy request headers
	for key, values := range c.Request.Header {
		reqCtx.Headers[key] = values
	}

	// Create the ResponseContext
	respCtx := &types.ResponseContext{
		Context:   ctx,
		GatewayID: gatewayID,
		Headers:   make(map[string][]string),
		Metadata:  make(map[string]interface{}),
	}

	// Get gateway data with plugins
	gatewayData, err := h.getGatewayData(ctx, gatewayID)
	reqCtx.Metadata["gateway_data"] = gatewayData

	if err != nil {
		h.logger.WithError(err).Error("Failed to get gateway data")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}
	// Find matching rule
	var matchingRule *types.ForwardingRule
	for _, rule := range gatewayData.Rules {
		h.logger.WithFields(logrus.Fields{
			"rule": rule,
		}).Debug("Rule")
		if !rule.Active {
			continue
		}

		// Check if method is allowed
		methodAllowed := false
		for _, m := range rule.Methods {
			if m == method {
				methodAllowed = true
				break
			}
		}

		if !methodAllowed {
			continue
		}

		// Check if path matches
		if strings.HasPrefix(path, rule.Path) {
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
			"path":   path,
			"method": method,
		}).Debug("No matching rule found")
		c.JSON(http.StatusNotFound, gin.H{"error": "No matching rule found"})
		return
	}

	// Configure plugins for this request
	if err := h.ConfigurePlugins(gatewayData.Gateway, matchingRule); err != nil {
		h.logger.WithError(err).Error("Failed to configure plugins")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to configure plugins"})
		return
	}

	// Execute pre-request plugins
	if _, err := h.pluginManager.ExecuteStage(ctx, types.PreRequest, gatewayID, matchingRule.ID, reqCtx, respCtx); err != nil {
		if pluginErr, ok := err.(*types.PluginError); ok {
			// Copy headers from response context
			for k, values := range respCtx.Headers {
				for _, v := range values {
					c.Header(k, v)
				}
			}
			c.JSON(pluginErr.StatusCode, gin.H{
				"error":       pluginErr.Message,
				"retry_after": respCtx.Metadata["retry_after"],
			})
			return
		}
		if respCtx.StopProcessing {
			h.logger.Debug("Stopping request processing due to plugin response (e.g., cache hit)")
			// Copy headers from the plugin response
			for k, values := range respCtx.Headers {
				for _, v := range values {
					c.Header(k, v)
				}
			}
			// Return the response from the plugin
			c.Data(respCtx.StatusCode, "application/json", respCtx.Body)
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Plugin execution failed"})
		return
	}
	// Forward the request
	startTime := time.Now()
	response, err := h.ForwardRequest(reqCtx, matchingRule)
	if err != nil {
		h.logger.WithError(err).Error("Failed to forward request")
		c.JSON(http.StatusBadGateway, gin.H{"error": "Failed to forward request"})
		return
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

	// If it's an error response (4xx or 5xx), return the original error response
	if response.StatusCode >= 400 {
		// Parse the error response
		var errorResponse map[string]interface{}
		if err := json.Unmarshal(response.Body, &errorResponse); err != nil {
			// If we can't parse the error, return a generic error
			c.JSON(response.StatusCode, gin.H{"error": "Upstream service error"})
			return
		}

		// Copy all headers from response context to client response
		for k, values := range respCtx.Headers {
			for _, v := range values {
				c.Header(k, v)
			}
		}

		// Return the original error response
		c.JSON(response.StatusCode, errorResponse)
		return
	}

	// Execute pre-response plugins
	if _, err := s.pluginManager.ExecuteStage(ctx, types.PreResponse, gatewayID, matchingRule.ID, reqCtx, respCtx); err != nil {
		if pluginErr, ok := err.(*types.PluginError); ok {
			// Copy headers from response context
			for k, values := range respCtx.Headers {
				for _, v := range values {
					c.Header(k, v)
				}
			}
			c.JSON(pluginErr.StatusCode, gin.H{
				"error":       pluginErr.Message,
				"retry_after": respCtx.Metadata["retry_after"],
			})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Plugin execution failed"})
		return
	}

	// Execute post-response plugins
	if _, err := h.pluginManager.ExecuteStage(ctx, types.PostResponse, gatewayID, matchingRule.ID, reqCtx, respCtx); err != nil {
		if pluginErr, ok := err.(*types.PluginError); ok {
			// Copy headers from response context
			h.logger.WithFields(logrus.Fields{
				"headers": respCtx.Headers,
			}).Debug("Plugin response headers")

			for k, values := range respCtx.Headers {
				for _, v := range values {
					c.Header(k, v)
				}
			}
			c.JSON(pluginErr.StatusCode, gin.H{
				"error":       pluginErr.Message,
				"retry_after": respCtx.Metadata["retry_after"],
			})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Plugin execution failed"})
		return
	}

	// Copy all headers from response context to client response
	for k, values := range respCtx.Headers {
		for _, v := range values {
			c.Header(k, v)
		}
	}
	duration := time.Since(start).Milliseconds()

	if metrics.Config.EnableLatency {
		metrics.GatewayRequestLatency.WithLabelValues(
			gatewayID,
			c.Request.URL.Path,
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
	c.Data(respCtx.StatusCode, "application/json", respCtx.Body)
}

func (h *ForwardedHandler) getGatewayData(ctx context.Context, gatewayID string) (*types.GatewayData, error) {
	// Try memory cache first
	if cached, ok := h.gatewayCache.Get(gatewayID); ok {
		h.logger.WithField("fromCache", "memory").Debug("Gateway data found in memory cache")
		data, err := getGatewayDataFromCache(cached)
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
func (h *ForwardedHandler) isPublicRoute(ctx *fiber.Ctx) bool {
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

func (h *ForwardedHandler) configurePlugins(gateway *types.Gateway, rule *types.ForwardingRule) error {
	// Configure gateway-level plugins
	gatewayChains := s.convertGatewayPlugins(gateway)
	h.logger.WithFields(logrus.Fields{
		"gatewayChains": gatewayChains,
	}).Debug("Gateway chains")

	if err := h.pluginManager.SetPluginChain(types.GatewayLevel, gateway.ID, gatewayChains); err != nil {
		return fmt.Errorf("failed to configure gateway plugins: %w", err)
	}

	if rule != nil && len(rule.PluginChain) > 0 {
		h.logger.WithFields(logrus.Fields{
			"ruleID":  rule.ID,
			"plugins": rule.PluginChain,
		}).Debug("Rule plugins")

		if err := s.pluginManager.SetPluginChain(types.RuleLevel, rule.ID, rule.PluginChain); err != nil {
			return fmt.Errorf("failed to configure rule plugins: %w", err)
		}
	}

	return nil
}

func (h *ForwardedHandler) ForwardRequest(req *types.RequestContext, rule *types.ForwardingRule) (*types.ResponseContext, error) {
	service, err := h.repo.GetService(req.Context, rule.ServiceID)
	if err != nil {
		return nil, fmt.Errorf("service not found: %w", err)
	}

	switch service.Type {
	case models.ServiceTypeUpstream:
		upstreamModel, err := h.upstreamFinder.Find(req.Context, service.GatewayID, service.UpstreamID)
		if err != nil {
			return nil, fmt.Errorf("upstream not found: %w", err)
		}

		// Create or get load balancer
		lb, err := h.getOrCreateLoadBalancer(upstreamModel)
		if err != nil {
			return nil, fmt.Errorf("failed to get load balancer: %w", err)
		}

		// Try with retries and fallback
		maxRetries := rule.RetryAttempts
		if maxRetries == 0 {
			maxRetries = 2 // default retries
		}

		var lastErr error
		for attempt := 0; attempt <= maxRetries; attempt++ {
			target, err := lb.NextTarget(req.Context)
			if err != nil {
				lastErr = err
				continue
			}

			h.logger.WithFields(logrus.Fields{
				"attempt":   attempt + 1,
				"provider":  target.Provider,
				"target_id": target.ID,
			}).Debug("Attempting request")

			response, err := h.doForwardRequest(req, rule, target)

			if err == nil {
				lb.ReportSuccess(target)
				return response, nil
			}

			lastErr = err
			lb.ReportFailure(target, err)

			if attempt == maxRetries {
				h.logger.WithFields(logrus.Fields{
					"total_attempts": maxRetries + 1,
					"last_error":     lastErr.Error(),
				}).Error("All retry attempts failed")
				return nil, fmt.Errorf("all retry attempts failed, last error: %v", lastErr)
			}
		}
		return nil, lastErr

	case models.ServiceTypeEndpoint:
		target := &types.UpstreamTarget{
			Host:        service.Host,
			Port:        service.Port,
			Protocol:    service.Protocol,
			Path:        service.Path,
			Headers:     service.Headers,
			Credentials: types.Credentials(service.Credentials),
		}
		return h.doForwardRequest(req, rule, target)

	default:
		return nil, fmt.Errorf("unsupported service type: %s", service.Type)
	}
}

// Add helper method to create or get load balancer
func (h *ForwardedHandler) getOrCreateLoadBalancer(upstream *models.Upstream) (*loadbalancer.LoadBalancer, error) {
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

func (h *ForwardedHandler) getGatewayDataFromRedis(ctx context.Context, gatewayID string) (*types.GatewayData, error) {
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
func (h *ForwardedHandler) convertModelToTypesGateway(g *models.Gateway) *types.Gateway {
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

func (h *ForwardedHandler) getGatewayDataFromDB(ctx context.Context, gatewayID string) (*types.GatewayData, error) {
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

func (h *ForwardedHandler) cacheGatewayData(
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

func (h *ForwardedHandler) convertModelToTypesRules(rules []models.ForwardingRule) []types.ForwardingRule {
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

func (h *ForwardedHandler) getJSONBytes(value interface{}) ([]byte, error) {
	switch v := value.(type) {
	case []byte:
		return v, nil
	case string:
		return []byte(v), nil
	case json.RawMessage:
		return v, nil
	default:
		// Try to marshal the value to JSON if it's not already in byte form
		b, err := json.Marshal(value)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal value to JSON bytes: %w", err)
		}
		return b, nil
	}
}

func (h *ForwardedHandler) doForwardRequest(
	req *types.RequestContext,
	rule *types.ForwardingRule,
	target *types.UpstreamTarget,
) (*types.ResponseContext, error) {
	client := &fasthttp.Client{
		ReadTimeout:  time.Second * 30,
		WriteTimeout: time.Second * 30,
	}

	httpReq := fasthttp.AcquireRequest()
	httpResp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseRequest(httpReq)
	defer fasthttp.ReleaseResponse(httpResp)

	// Build target URL based on target type
	var targetURL string
	if target.Provider != "" {
		providerConfig, ok := h.providers[target.Provider]
		if !ok {
			return nil, fmt.Errorf("unsupported provider: %s", target.Provider)
		}

		endpointConfig, ok := providerConfig.Endpoints[target.Path]
		if !ok {
			return nil, fmt.Errorf("unsupported endpoint path: %s", target.Path)
		}
		targetURL = fmt.Sprintf("%s%s", providerConfig.BaseURL, endpointConfig.Path)
	} else {
		targetURL = fmt.Sprintf("%s://%s:%d%s",
			target.Protocol,
			target.Host,
			target.Port,
			target.Path,
		)
	}

	if rule.StripPath {
		targetURL = strings.TrimSuffix(targetURL, "/") + strings.TrimPrefix(req.Path, rule.Path)
	}
	httpReq.SetRequestURI(targetURL)
	httpReq.Header.SetMethod(req.Method)

	// Handle request body and check for streaming
	if len(req.Body) > 0 {
		var requestData map[string]interface{}
		if err := json.Unmarshal(req.Body, &requestData); err == nil {
			if stream, ok := requestData["stream"].(bool); ok && stream {
				return h.handleStreamingRequest(req, target, requestData)
			}
		}

		// Non-streaming request - transform body if needed
		if target.Provider != "" {
			transformedBody, err := h.transformRequestBody(req.Body, target)
			if err != nil {
				return nil, fmt.Errorf("failed to transform request body: %w", err)
			}
			httpReq.SetBody(transformedBody)
		} else {
			httpReq.SetBody(req.Body)
		}
	}

	// Copy headers and apply authentication
	for k, v := range req.Headers {
		for _, val := range v {
			httpReq.Header.Add(k, val)
		}
	}
	if len(target.Headers) > 0 {
		for k, v := range target.Headers {
			httpReq.Header.Set(k, v)
		}
	}
	h.applyAuthentication(httpReq, &target.Credentials, req.Body)

	// Make the request
	if err := client.Do(httpReq, httpResp); err != nil {
		return nil, fmt.Errorf("failed to forward request: %w", err)
	}

	// Set provider in response header
	h.logger.WithFields(logrus.Fields{
		"provider": target.Provider,
	}).Debug("Selected provider")
	httpResp.Header.Set("X-Selected-Provider", target.Provider)

	// Handle response status
	statusCode := httpResp.StatusCode()
	if statusCode <= 0 || statusCode >= 600 {
		return nil, fmt.Errorf("invalid status code received: %d", statusCode)
	}
	if statusCode < 200 || statusCode >= 300 {
		respBody := httpResp.Body()
		return nil, fmt.Errorf("upstream returned status code %d: %s", statusCode, string(respBody))
	}

	return h.createResponse(httpResp), nil
}
