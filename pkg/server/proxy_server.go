package server

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
	"github.com/valyala/fasthttp"

	"github.com/NeuralTrust/TrustGate/pkg/middleware"
	"github.com/NeuralTrust/TrustGate/pkg/types"

	"github.com/NeuralTrust/TrustGate/pkg/cache"
	"github.com/NeuralTrust/TrustGate/pkg/common"
	"github.com/NeuralTrust/TrustGate/pkg/config"
	"github.com/NeuralTrust/TrustGate/pkg/database"
	"github.com/NeuralTrust/TrustGate/pkg/loadbalancer"
	"github.com/NeuralTrust/TrustGate/pkg/metrics"
	"github.com/NeuralTrust/TrustGate/pkg/models"
	"github.com/NeuralTrust/TrustGate/pkg/pluginiface"
	"github.com/NeuralTrust/TrustGate/pkg/plugins"

	"golang.org/x/exp/slices"
)

type ProxyServer struct {
	*BaseServer
	repo              *database.Repository
	pluginManager     *plugins.Manager
	gatewayCache      *common.TTLMap
	rulesCache        *common.TTLMap
	pluginCache       *common.TTLMap
	skipAuthCheck     bool
	httpClient        *http.Client
	loadBalancers     sync.Map // map[string]*loadbalancer.LoadBalancer
	providers         map[string]config.ProviderConfig
	lbFactory         loadbalancer.Factory
	gatewayMiddleware *middleware.GatewayMiddleware
	metricsMiddleware *middleware.MetricsMiddleware
}

// Cache TTLs
const (
	GatewayCacheTTL = 1 * time.Hour
	RulesCacheTTL   = 5 * time.Minute
	PluginCacheTTL  = 30 * time.Minute
)

// Add helper function for safe type assertions
func getContextValue[T any](ctx context.Context, key interface{}) (T, error) {
	value := ctx.Value(key)
	if value == nil {
		var zero T
		return zero, fmt.Errorf("value not found in context for key: %v", key)
	}
	result, ok := value.(T)
	if !ok {
		var zero T
		return zero, fmt.Errorf("invalid type assertion for key: %v", key)
	}
	return result, nil
}

// Add helper function for safe type assertions if not already present
func getGatewayDataFromCache(value interface{}) (*types.GatewayData, error) {
	data, ok := value.(*types.GatewayData)
	if !ok {
		return nil, fmt.Errorf("invalid type assertion for gateway data")
	}
	return data, nil
}

// Add at the top of the file with other constants
const (
	HealthPath      = "/health"
	AdminHealthPath = "/__/health"
	PingPath        = "/__/ping"
)

func NewProxyServer(config *config.Config, cache *cache.Cache, repo *database.Repository, logger *logrus.Logger, skipAuthCheck bool, extraPlugins ...pluginiface.Plugin) *ProxyServer {
	// Initialize metrics with config from yaml
	metricsConfig := metrics.MetricsConfig{
		EnableLatency:         config.Metrics.EnableLatency,
		EnableUpstreamLatency: config.Metrics.EnableUpstream,
		EnableConnections:     config.Metrics.EnableConnections,
		EnablePerRoute:        config.Metrics.EnablePerRoute,
	}
	metrics.Initialize(metricsConfig)

	// Initialize plugins
	plugins.InitializePlugins(cache, logger)
	manager := plugins.GetManager()

	// Create TTL maps
	gatewayCache := cache.CreateTTLMap("gateway", GatewayCacheTTL)
	rulesCache := cache.CreateTTLMap("rules", RulesCacheTTL)
	pluginCache := cache.CreateTTLMap("plugin", PluginCacheTTL)

	// Create middleware instance
	gatewayMiddleware := middleware.NewGatewayMiddleware(logger, cache, repo, config.Server.BaseDomain)
	metricsMiddleware := middleware.NewMetricsMiddleware(logger)

	s := &ProxyServer{
		BaseServer:        NewBaseServer(config, cache, repo, logger),
		repo:              repo,
		pluginManager:     manager,
		gatewayCache:      gatewayCache,
		rulesCache:        rulesCache,
		pluginCache:       pluginCache,
		skipAuthCheck:     skipAuthCheck,
		httpClient:        &http.Client{},
		providers:         config.Providers.Providers,
		lbFactory:         loadbalancer.NewBaseFactory(),
		gatewayMiddleware: gatewayMiddleware,
		metricsMiddleware: metricsMiddleware,
	}

	// Register extra plugins with error handling
	for _, plugin := range extraPlugins {
		if err := manager.RegisterPlugin(plugin); err != nil {
			logger.WithFields(logrus.Fields{
				"plugin": plugin.Name(),
				"error":  err,
			}).Error("Failed to register plugin")
		}
	}

	// Subscribe to gateway events
	go s.subscribeToEvents()

	// Setup metrics endpoint using BaseServer's implementation
	s.BaseServer.setupMetricsEndpoint()

	return s
}

func (s *ProxyServer) GetRouter() *gin.Engine {
	return s.router
}

func (s *ProxyServer) Run() error {
	// Set Gin to release mode
	gin.SetMode(gin.ReleaseMode)

	// Create a new router
	router := gin.New()

	// Create auth middleware
	authMiddleware := middleware.NewAuthMiddleware(s.logger, s.repo)

	// Create a combined middleware handler
	mainHandler := func(c *gin.Context) {
		// Skip middleware for system routes
		path := c.Request.URL.Path
		if path == AdminHealthPath || path == HealthPath || path == PingPath {
			s.logger.Debug("Skipping middleware for system route: ", path)
			return // Let the specific route handler take care of it
		}

		// Create and initialize fasthttp context
		fctx := &fasthttp.RequestCtx{}
		fctx.Request.SetRequestURI(c.Request.URL.String())
		fctx.Request.Header.SetMethod(c.Request.Method)
		fctx.Request.SetHost(c.Request.Host)

		// Copy headers
		for k, v := range c.Request.Header {
			for _, val := range v {
				fctx.Request.Header.Add(k, val)
			}
		}

		// Set up context
		ctx := context.WithValue(c.Request.Context(), common.LoggerKey, s.logger)
		ctx = context.WithValue(ctx, common.FastHTTPKey, fctx)
		ctx = context.WithValue(ctx, common.ResponseWriterKey, c.Writer)
		c.Request = c.Request.WithContext(ctx)

		// Apply gateway middleware first to set up gateway context
		s.gatewayMiddleware.IdentifyGateway()(c)
		if c.IsAborted() {
			s.logger.Debug("Request aborted by gateway middleware")
			return
		}

		// Apply metrics middleware
		s.metricsMiddleware.MetricsMiddleware()(c)
		if c.IsAborted() {
			s.logger.Debug("Request aborted by metrics middleware")
			return
		}

		// Handle auth check - skipAuthCheck now means "using EE auth"
		if !s.skipAuthCheck {
			// CE auth handling
			isPublic := isPublicRoute(c, s.cache)
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
	}

	// Register system routes
	router.GET(AdminHealthPath, func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status": "ok",
			"time":   time.Now().Format(time.RFC3339),
		})
	})

	router.GET(HealthPath, func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status": "ok",
			"time":   time.Now().Format(time.RFC3339),
		})
	})

	router.GET(PingPath, func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"message": "pong",
		})
	})

	// Register the main handler for all non-system routes
	router.NoRoute(mainHandler)

	return router.Run(fmt.Sprintf(":%d", s.config.Server.ProxyPort))
}

func (s *ProxyServer) HandleForward(c *gin.Context) {
	// Check if request was already aborted
	if c.IsAborted() {
		s.logger.Debug("Skipping HandleForward for aborted request")
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
		s.logger.Error("Gateway ID not found in gin context")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}
	gatewayID, ok := gatewayIDAny.(string)
	if !ok {
		s.logger.Error("Gateway ID not found in gin context")
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
		s.logger.WithError(err).Error("Failed to get FastHTTP context")
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
		s.logger.WithError(err).Error("Failed to read request body")
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
	gatewayData, err := s.GetGatewayData(ctx, gatewayID)
	reqCtx.Metadata["gateway_data"] = gatewayData

	if err != nil {
		s.logger.WithError(err).Error("Failed to get gateway data")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}
	// Find matching rule
	var matchingRule *types.ForwardingRule
	for _, rule := range gatewayData.Rules {
		s.logger.WithFields(logrus.Fields{
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
		s.logger.WithFields(logrus.Fields{
			"path":   path,
			"method": method,
		}).Debug("No matching rule found")
		c.JSON(http.StatusNotFound, gin.H{"error": "No matching rule found"})
		return
	}

	// Configure plugins for this request
	if err := s.ConfigurePlugins(gatewayData.Gateway, matchingRule); err != nil {
		s.logger.WithError(err).Error("Failed to configure plugins")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to configure plugins"})
		return
	}

	// Execute pre-request plugins
	if _, err := s.pluginManager.ExecuteStage(ctx, types.PreRequest, gatewayID, matchingRule.ID, reqCtx, respCtx); err != nil {
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
			s.logger.Debug("Stopping request processing due to plugin response (e.g., cache hit)")
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
	response, err := s.ForwardRequest(reqCtx, matchingRule)
	if err != nil {
		s.logger.WithError(err).Error("Failed to forward request")
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
	if _, err := s.pluginManager.ExecuteStage(ctx, types.PostResponse, gatewayID, matchingRule.ID, reqCtx, respCtx); err != nil {
		if pluginErr, ok := err.(*types.PluginError); ok {
			// Copy headers from response context
			s.logger.WithFields(logrus.Fields{
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

// Helper function to check if a route is public
func isPublicRoute(c *gin.Context, cache *cache.Cache) bool {
	path := c.Request.URL.Path
	if strings.HasPrefix(path, "/__/") || path == "/health" {
		return true
	}

	// Get gateway data from context
	gatewayData, exists := c.Get("gateway_data")
	if !exists {
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

func (s *ProxyServer) ConfigurePlugins(gateway *types.Gateway, rule *types.ForwardingRule) error {
	// Configure gateway-level plugins
	gatewayChains := s.convertGatewayPlugins(gateway)
	s.logger.WithFields(logrus.Fields{
		"gatewayChains": gatewayChains,
	}).Debug("Gateway chains")

	if err := s.pluginManager.SetPluginChain(types.GatewayLevel, gateway.ID, gatewayChains); err != nil {
		return fmt.Errorf("failed to configure gateway plugins: %w", err)
	}

	if rule != nil && len(rule.PluginChain) > 0 {
		s.logger.WithFields(logrus.Fields{
			"ruleID":  rule.ID,
			"plugins": rule.PluginChain,
		}).Debug("Rule plugins")

		if err := s.pluginManager.SetPluginChain(types.RuleLevel, rule.ID, rule.PluginChain); err != nil {
			return fmt.Errorf("failed to configure rule plugins: %w", err)
		}
	}

	return nil
}

func (s *ProxyServer) GetGatewayData(ctx context.Context, gatewayID string) (*types.GatewayData, error) {
	logger, err := getContextValue[*logrus.Logger](ctx, common.LoggerKey)
	if err != nil {
		return nil, fmt.Errorf("failed to get logger: %w", err)
	}

	// Try memory cache first
	if cached, ok := s.gatewayCache.Get(gatewayID); ok {
		logger.WithField("fromCache", "memory").Debug("Gateway data found in memory cache")
		data, err := getGatewayDataFromCache(cached)
		if err != nil {
			logger.WithError(err).Error("Failed to get gateway data from cache")
			// Continue to try Redis cache
		} else {
			return data, nil
		}
	}

	// Try Redis cache
	gatewayData, err := s.getGatewayDataFromRedis(ctx, gatewayID)
	if err == nil {
		logger.WithFields(logrus.Fields{
			"gatewayID":  gatewayID,
			"rulesCount": len(gatewayData.Rules),
			"fromCache":  "redis",
		}).Debug("Gateway data found in Redis cache")

		// Store in memory cache
		s.gatewayCache.Set(gatewayID, gatewayData)
		return gatewayData, nil
	}
	logger.WithError(err).Debug("Failed to get gateway data from Redis")

	// Fallback to database
	return s.getGatewayDataFromDB(ctx, gatewayID)
}

func (s *ProxyServer) getGatewayDataFromRedis(ctx context.Context, gatewayID string) (*types.GatewayData, error) {
	// Get gateway from Redis
	gatewayKey := fmt.Sprintf("gateway:%s", gatewayID)
	gatewayJSON, err := s.cache.Get(ctx, gatewayKey)
	if err != nil {
		return nil, fmt.Errorf("failed to get gateway from Redis: %w", err)
	}

	var gateway *models.Gateway
	if err := json.Unmarshal([]byte(gatewayJSON), &gateway); err != nil {
		return nil, fmt.Errorf("failed to unmarshal gateway from Redis: %w", err)
	}

	// Get rules from Redis
	rulesKey := fmt.Sprintf("rules:%s", gatewayID)
	rulesJSON, err := s.cache.Get(ctx, rulesKey)
	if err != nil {
		return nil, fmt.Errorf("failed to get rules from Redis: %w", err)
	}

	var rules []types.ForwardingRule
	if err := json.Unmarshal([]byte(rulesJSON), &rules); err != nil {
		return nil, fmt.Errorf("failed to unmarshal rules from Redis: %w", err)
	}

	return &types.GatewayData{
		Gateway: convertModelToTypesGateway(gateway),
		Rules:   rules,
	}, nil
}

func (s *ProxyServer) getGatewayDataFromDB(ctx context.Context, gatewayID string) (*types.GatewayData, error) {
	logger, err := getContextValue[*logrus.Logger](ctx, common.LoggerKey)
	if err != nil {
		return nil, fmt.Errorf("failed to get logger: %w", err)
	}

	// Get gateway from database
	gateway, err := s.repo.GetGateway(ctx, gatewayID)
	if err != nil {
		return nil, fmt.Errorf("failed to get gateway from database: %w", err)
	}

	// Get rules from database
	rules, err := s.repo.ListRules(ctx, gatewayID)
	if err != nil {
		return nil, fmt.Errorf("failed to get rules from database: %w", err)
	}

	// Convert models to types
	gatewayData := &types.GatewayData{
		Gateway: convertModelToTypesGateway(gateway),
		Rules:   convertModelToTypesRules(rules),
	}

	// Cache the results
	if err := s.cacheGatewayData(ctx, gatewayID, gateway, rules); err != nil {
		logger.WithError(err).Warn("Failed to cache gateway data")
	}

	logger.WithFields(logrus.Fields{
		"gatewayID":       gatewayID,
		"requiredPlugins": gateway.RequiredPlugins,
		"rulesCount":      len(rules),
		"fromCache":       "database",
	}).Debug("Loaded gateway data from database")

	return gatewayData, nil
}

func (s *ProxyServer) cacheGatewayData(ctx context.Context, gatewayID string, gateway *models.Gateway, rules []models.ForwardingRule) error {
	// Cache gateway
	gatewayJSON, err := json.Marshal(gateway)
	if err != nil {
		return fmt.Errorf("failed to marshal gateway: %w", err)
	}
	gatewayKey := fmt.Sprintf("gateway:%s", gatewayID)
	if err := s.cache.Set(ctx, gatewayKey, string(gatewayJSON), 0); err != nil {
		return fmt.Errorf("failed to cache gateway: %w", err)
	}

	// Convert and cache rules as types
	typesRules := convertModelToTypesRules(rules)
	rulesJSON, err := json.Marshal(typesRules)
	if err != nil {
		return fmt.Errorf("failed to marshal rules: %w", err)
	}
	rulesKey := fmt.Sprintf("rules:%s", gatewayID)
	if err := s.cache.Set(ctx, rulesKey, string(rulesJSON), 0); err != nil {
		return fmt.Errorf("failed to cache rules: %w", err)
	}

	// Cache in memory
	gatewayData := &types.GatewayData{
		Gateway: convertModelToTypesGateway(gateway),
		Rules:   typesRules,
	}
	s.gatewayCache.Set(gatewayID, gatewayData)

	return nil
}

// Helper functions to convert between models and types
func convertModelToTypesGateway(g *models.Gateway) *types.Gateway {
	requiredPlugins := []types.PluginConfig{}

	// Convert required plugins
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

func getJSONBytes(value interface{}) ([]byte, error) {
	switch v := value.(type) {
	case []byte:
		return v, nil
	case string:
		return []byte(v), nil
	case json.RawMessage:
		return []byte(v), nil
	default:
		// Try to marshal the value to JSON if it's not already in byte form
		bytes, err := json.Marshal(value)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal value to JSON bytes: %w", err)
		}
		return bytes, nil
	}
}

func convertModelToTypesRules(rules []models.ForwardingRule) []types.ForwardingRule {
	var result []types.ForwardingRule
	for _, r := range rules {
		var pluginChain []types.PluginConfig

		jsonBytes, err := getJSONBytes(r.PluginChain)
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
			Headers:       map[string]string(r.Headers),
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

func (s *ProxyServer) ForwardRequest(req *types.RequestContext, rule *types.ForwardingRule) (*types.ResponseContext, error) {
	service, err := s.repo.GetService(req.Context, rule.ServiceID)
	if err != nil {
		return nil, fmt.Errorf("service not found: %w", err)
	}

	switch service.Type {
	case models.ServiceTypeUpstream:
		upstreamModel, err := s.repo.GetUpstream(req.Context, service.UpstreamID)
		if err != nil {
			return nil, fmt.Errorf("upstream not found: %w", err)
		}

		// Create or get load balancer
		lb, err := s.getOrCreateLoadBalancer(upstreamModel)
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

			s.logger.WithFields(logrus.Fields{
				"attempt":   attempt + 1,
				"provider":  target.Provider,
				"target_id": target.ID,
			}).Debug("Attempting request")

			response, err := s.doForwardRequest(req, rule, target, service.Type, lb)
			s.logger.WithFields(logrus.Fields{
				"response": response,
			}).Debug("Forwarded request")
			if err == nil {
				lb.ReportSuccess(target)
				return response, nil
			}

			lastErr = err
			lb.ReportFailure(target, err)

			if attempt == maxRetries {
				s.logger.WithFields(logrus.Fields{
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
		return s.doForwardRequest(req, rule, target, service.Type, nil)

	default:
		return nil, fmt.Errorf("unsupported service type: %s", service.Type)
	}
}

// Add helper method to create or get load balancer
func (s *ProxyServer) getOrCreateLoadBalancer(upstream *models.Upstream) (*loadbalancer.LoadBalancer, error) {
	if lb, ok := s.loadBalancers.Load(upstream.ID); ok {
		if lb, ok := lb.(*loadbalancer.LoadBalancer); ok {
			return lb, nil
		}
	}

	lb, err := loadbalancer.NewLoadBalancer(upstream, s.logger, s.cache)
	if err != nil {
		return nil, err
	}

	s.loadBalancers.Store(upstream.ID, lb)
	return lb, nil
}

func (s *ProxyServer) doForwardRequest(req *types.RequestContext, rule *types.ForwardingRule, target *types.UpstreamTarget, serviceType string, lb *loadbalancer.LoadBalancer) (*types.ResponseContext, error) {
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
		providerConfig, ok := s.providers[target.Provider]
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
				return s.handleStreamingRequest(req, target, requestData)
			}
		}

		// Non-streaming request - transform body if needed
		if target.Provider != "" {
			transformedBody, err := s.transformRequestBody(req.Body, target)
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
	s.applyAuthentication(httpReq, &target.Credentials, req.Body)

	// Make the request
	if err := client.Do(httpReq, httpResp); err != nil {
		return nil, fmt.Errorf("failed to forward request: %w", err)
	}

	// Set provider in response header
	s.logger.WithFields(logrus.Fields{
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

	return s.createResponse(httpResp), nil
}

// handleStreamingRequest handles streaming requests to providers
func (s *ProxyServer) handleStreamingRequest(req *types.RequestContext, target *types.UpstreamTarget, requestData map[string]interface{}) (*types.ResponseContext, error) {
	// Transform request body if needed
	transformedBody, err := s.transformRequestBody(req.Body, target)
	if err != nil {
		return nil, fmt.Errorf("failed to transform streaming request: %w", err)
	}

	// Update the request body with transformed data
	req.Body = transformedBody

	// Handle the streaming based on the provider
	return s.handleStreamingResponse(req, target)
}

func (s *ProxyServer) handleStreamingResponse(req *types.RequestContext, target *types.UpstreamTarget) (*types.ResponseContext, error) {
	providerConfig, ok := s.providers[target.Provider]
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

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return &types.ResponseContext{
			StatusCode: resp.StatusCode,
			Headers:    make(map[string][]string),
			Body:       body,
		}, nil
	}

	if w, ok := req.Context.Value(common.ResponseWriterKey).(http.ResponseWriter); ok {
		// Copy response headers
		for k, v := range resp.Header {
			for _, val := range v {
				w.Header().Add(k, val)
			}
		}

		// Add rate limit headers if they exist in metadata
		if rateLimitHeaders, ok := req.Metadata["rate_limit_headers"].(map[string][]string); ok {
			for k, v := range rateLimitHeaders {
				for _, val := range v {
					w.Header().Set(k, val)
				}
			}
		}
		w.Header().Add("X-Selected-Provider", target.Provider)
		w.WriteHeader(resp.StatusCode)

		reader := bufio.NewReader(resp.Body)
		var lastUsage map[string]interface{}

		for {
			line, err := reader.ReadBytes('\n')
			if err != nil {
				if err == io.EOF {
					break
				}
				s.logger.WithError(err).Error("Error reading streaming response")
				break
			}

			// Check if this is a data line
			if bytes.HasPrefix(line, []byte("data: ")) {
				// Check if this is the [DONE] message
				if bytes.Equal(line, []byte("data: [DONE]\n")) {
					// If we have usage from the last chunk, store it
					if lastUsage != nil {
						req.Metadata["token_usage"] = lastUsage
						s.logger.WithFields(logrus.Fields{
							"token_usage": lastUsage,
						}).Debug("Stored token usage from streaming response")
					}
					// Write the [DONE] message
					if _, err := w.Write(line); err != nil {
						s.logger.WithError(err).Error("Failed to write [DONE] message")
						break
					}
					continue
				}

				// For non-[DONE] messages, try to extract usage info
				jsonData := line[6:] // Skip "data: " prefix
				var response map[string]interface{}
				if err := json.Unmarshal(jsonData, &response); err == nil {
					if usage, ok := response["usage"].(map[string]interface{}); ok {
						lastUsage = usage
					}
				}
			}

			// Write the line to the client
			if _, err := w.Write(line); err != nil {
				s.logger.WithError(err).Error("Failed to write SSE message")
				break
			}
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
		}

		// If we have usage info but didn't get a [DONE] message, store it anyway
		if lastUsage != nil && req.Metadata["token_usage"] == nil {
			req.Metadata["token_usage"] = lastUsage
			s.logger.WithFields(logrus.Fields{
				"token_usage": lastUsage,
			}).Debug("Stored token usage from last chunk")
		}
	}

	return &types.ResponseContext{
		StatusCode: resp.StatusCode,
		Headers:    resp.Header,
		Streaming:  true,
		Metadata:   req.Metadata, // Include the metadata with token usage
	}, nil
}

// Add getter for plugin manager
func (s *ProxyServer) PluginManager() *plugins.Manager {
	return s.pluginManager
}

func (s *ProxyServer) convertGatewayPlugins(gateway *types.Gateway) []types.PluginConfig {
	var chains []types.PluginConfig
	for _, config := range gateway.RequiredPlugins {
		if config.Enabled {
			// Get the plugin to check its stages
			plugin := s.pluginManager.GetPlugin(config.Name)
			if plugin == nil {
				s.logger.WithField("plugin", config.Name).Error("Plugin not found")
				continue
			}

			// Check if this is a fixed-stage plugin
			supportedStages := plugin.Stages()
			if len(supportedStages) > 0 {
				// For fixed-stage plugins, just add the config without a stage
				// The stage will be set when executing based on the plugin's supported stages
				pluginConfig := config
				pluginConfig.Level = types.GatewayLevel
				chains = append(chains, pluginConfig)
			} else {
				// For user-configured plugins, the stage must be set in the config
				if config.Stage == "" {
					s.logger.WithField("plugin", config.Name).Error("Stage not configured for plugin")
					continue
				}
				pluginConfig := config
				pluginConfig.Level = types.GatewayLevel
				chains = append(chains, pluginConfig)
			}
		}
	}
	return chains
}

// InvalidateGatewayCache removes the gateway data from both memory and Redis cache
func (s *ProxyServer) InvalidateGatewayCache(ctx context.Context, gatewayID string) error {
	s.logger.WithFields(logrus.Fields{
		"gatewayID": gatewayID,
	}).Debug("Invalidating gateway cache")

	// Remove from memory cache
	s.gatewayCache.Delete(gatewayID)

	// Remove from Redis cache
	rulesKey := fmt.Sprintf("rules:%s", gatewayID)
	if err := s.cache.Delete(ctx, rulesKey); err != nil {
		s.logger.WithError(err).Warn("Failed to delete rules from Redis cache")
	}

	return nil
}

func (s *ProxyServer) subscribeToEvents() {
	// Get Redis client from cache
	rdb := s.cache.Client()
	pubsub := rdb.Subscribe(context.Background(), "gateway_events")
	defer pubsub.Close()

	// Listen for messages
	ch := pubsub.Channel()
	for msg := range ch {
		var event map[string]string
		if err := json.Unmarshal([]byte(msg.Payload), &event); err != nil {
			s.logger.WithError(err).Error("Failed to unmarshal event")
			continue
		}

		if event["type"] == "cache_invalidation" {
			gatewayID := event["gatewayID"]
			if err := s.InvalidateGatewayCache(context.Background(), gatewayID); err != nil {
				s.logger.WithError(err).Error("Failed to invalidate gateway cache")
			}
		}
	}
}

func (s *ProxyServer) transformRequestBody(body []byte, target *types.UpstreamTarget) ([]byte, error) {
	// Handle empty body case
	if len(body) == 0 {
		return body, nil
	}

	// Parse original request
	var requestData map[string]interface{}
	if err := json.Unmarshal(body, &requestData); err != nil {
		return nil, fmt.Errorf("failed to unmarshal request body: %w", err)
	}

	targetEndpointConfig, ok := s.providers[target.Provider].Endpoints[target.Path]
	if !ok || targetEndpointConfig.Schema == nil {
		return nil, fmt.Errorf("missing schema for target provider %s endpoint %s", target.Provider, target.Path)
	}

	// Handle model validation and streaming
	if modelName, ok := requestData["model"].(string); ok {
		if !slices.Contains(target.Models, modelName) {
			requestData["model"] = target.DefaultModel
		}
	} else {
		requestData["model"] = target.DefaultModel
	}

	// Transform data to target format
	transformed, err := s.mapBetweenSchemas(requestData, targetEndpointConfig.Schema)
	if err != nil {
		return nil, fmt.Errorf("failed to transform request for provider %s endpoint %s: %w",
			target.Provider, target.Path, err)
	}

	// Preserve streaming parameter if present in original request
	if stream, ok := requestData["stream"].(bool); ok {
		transformed["stream"] = stream
	}
	return json.Marshal(transformed)
}

func (s *ProxyServer) mapBetweenSchemas(data map[string]interface{}, targetSchema *config.ProviderSchema) (map[string]interface{}, error) {
	// When no source schema is provided, we just validate against target schema
	if targetSchema == nil {
		return nil, fmt.Errorf("missing target schema configuration")
	}

	result := make(map[string]interface{})

	for targetKey, targetField := range targetSchema.RequestFormat {
		value, err := s.extractValueByPath(data, targetField.Path)
		if err != nil {
			if targetField.Default != nil {
				result[targetKey] = targetField.Default
				continue
			}
			if targetField.Required {
				return nil, fmt.Errorf("missing required field %s: %w", targetKey, err)
			}
			continue
		}
		result[targetKey] = value
	}

	return result, nil
}

func (s *ProxyServer) extractValueByPath(data map[string]interface{}, path string) (interface{}, error) {
	if path == "" {
		return nil, fmt.Errorf("empty path")
	}

	// Direct field access for simple paths
	if !strings.Contains(path, ".") && !strings.Contains(path, "[") {
		if val, exists := data[path]; exists {
			return val, nil
		}
		return nil, fmt.Errorf("key not found: %s", path)
	}

	// Split path into segments (e.g., "messages[0].content" -> ["messages", "[0]", "content"])
	segments := strings.FieldsFunc(path, func(r rune) bool {
		return r == '.' || r == '[' || r == ']'
	})

	var current interface{} = data
	for i, segment := range segments {
		if idx, err := strconv.Atoi(segment); err == nil {
			if arr, ok := current.([]interface{}); ok {
				if idx < 0 || idx >= len(arr) {
					return nil, fmt.Errorf("array index out of bounds: %d", idx)
				}
				if i == len(segments)-1 {
					return arr[idx], nil
				}
				// If not last segment, next value must be a map
				if nextMap, ok := arr[idx].(map[string]interface{}); ok {
					current = nextMap
					continue
				}
				return nil, fmt.Errorf("expected object at index %d", idx)
			}
			return nil, fmt.Errorf("expected array for index access")
		}

		// Handle special paths
		switch segment {
		case "last":
			if arr, ok := current.([]interface{}); ok {
				if len(arr) == 0 {
					return nil, fmt.Errorf("array is empty")
				}
				if i == len(segments)-1 {
					return arr[len(arr)-1], nil
				}
				// If not last segment, next value must be a map
				if nextMap, ok := arr[len(arr)-1].(map[string]interface{}); ok {
					current = nextMap
					continue
				}
				return nil, fmt.Errorf("expected object at last index")
			}
			return nil, fmt.Errorf("expected array for 'last' access")

		default:
			// Regular object property access
			if currentMap, ok := current.(map[string]interface{}); ok {
				if val, exists := currentMap[segment]; exists {
					if i == len(segments)-1 {
						return val, nil
					}
					current = val // Set current to the value for next iteration
					continue
				}
				return nil, fmt.Errorf("key not found: %s", segment)
			}
			return nil, fmt.Errorf("expected object at path %s", segment)
		}
	}

	return nil, fmt.Errorf("invalid path")
}

// Helper function to create ResponseContext from fasthttp.Response
func (s *ProxyServer) createResponse(resp *fasthttp.Response) *types.ResponseContext {
	response := &types.ResponseContext{
		StatusCode: resp.StatusCode(),
		Headers:    make(map[string][]string),
		Body:       resp.Body(),
	}

	// Copy all response headers
	resp.Header.VisitAll(func(key, value []byte) {
		k := string(key)
		v := string(value)
		if response.Headers[k] == nil {
			response.Headers[k] = make([]string, 0)
		}
		response.Headers[k] = append(response.Headers[k], v)
	})

	return response
}

func (s *ProxyServer) applyAuthentication(req *fasthttp.Request, creds *types.Credentials, body []byte) {
	if creds == nil {
		s.logger.Debug("No credentials found")
		return
	}
	s.logger.WithFields(logrus.Fields{
		"creds": creds,
	}).Debug("Applying authentication")
	// Header-based auth
	if creds.HeaderName != "" && creds.HeaderValue != "" {
		s.logger.WithFields(logrus.Fields{
			"header_name": creds.HeaderName,
			// Don't log the actual value for security
			"has_value": creds.HeaderValue != "",
		}).Debug("Setting auth header")

		// Set the auth header
		req.Header.Set(creds.HeaderName, creds.HeaderValue)
	}

	// Parameter-based auth
	if creds.ParamName != "" && creds.ParamValue != "" {
		if creds.ParamLocation == "query" {
			uri := req.URI()
			args := uri.QueryArgs()
			args.Set(creds.ParamName, creds.ParamValue)
		} else if creds.ParamLocation == "body" && len(body) > 0 {
			// Parse JSON body
			var jsonBody map[string]interface{}
			if err := json.Unmarshal(body, &jsonBody); err != nil {
				s.logger.WithError(err).Error("Failed to parse request body")
				return
			}

			// Add auth parameter
			jsonBody[creds.ParamName] = creds.ParamValue

			// Rewrite body
			newBody, err := json.Marshal(jsonBody)
			if err != nil {
				s.logger.WithError(err).Error("Failed to marshal request body")
				return
			}

			req.SetBody(newBody)
		}
	}
}

// Add these methods to expose middleware
func (s *ProxyServer) GetGatewayMiddleware() gin.HandlerFunc {
	return s.gatewayMiddleware.IdentifyGateway()
}

func (s *ProxyServer) GetMetricsMiddleware() gin.HandlerFunc {
	return s.metricsMiddleware.MetricsMiddleware()
}
