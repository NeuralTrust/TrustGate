package server

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/NeuralTrust/TrustGate/pkg/app/upstream"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/lib/pq"
	"github.com/sirupsen/logrus"

	"github.com/NeuralTrust/TrustGate/pkg/cache"
	"github.com/NeuralTrust/TrustGate/pkg/common"
	"github.com/NeuralTrust/TrustGate/pkg/config"
	"github.com/NeuralTrust/TrustGate/pkg/database"
	"github.com/NeuralTrust/TrustGate/pkg/models"
	"github.com/NeuralTrust/TrustGate/pkg/pluginiface"
	"github.com/NeuralTrust/TrustGate/pkg/plugins"
	"github.com/NeuralTrust/TrustGate/pkg/types"
)

type (
	AdminServerDI struct {
		Config         *config.Config
		Cache          *cache.Cache
		Repo           *database.Repository
		Logger         *logrus.Logger
		ExtraPlugins   []pluginiface.Plugin
		UpstreamFinder upstream.Finder
	}
	AdminServer struct {
		*BaseServer
		upstreamFinder upstream.Finder
	}
)

func NewAdminServer(di AdminServerDI) *AdminServer {
	// Initialize plugins
	plugins.InitializePlugins(di.Cache, di.Logger)

	// Register extra plugins
	for _, plugin := range di.ExtraPlugins {
		if err := plugins.GetManager().RegisterPlugin(plugin); err != nil {
			di.Logger.WithError(err).Error("Failed to register plugin")
		}
	}

	return &AdminServer{
		BaseServer:     NewBaseServer(di.Config, di.Cache, di.Repo, di.Logger),
		upstreamFinder: di.UpstreamFinder,
	}
}

func (s *AdminServer) AddRoutes(router *gin.RouterGroup) {
	// Base routes that are common to both CE and EE editions
	s.addBaseRoutes(router)

	// Note: EE version can call this method and then add its own additional routes
}

// addBaseRoutes adds the core/common routes used in both CE and EE editions
func (s *AdminServer) addBaseRoutes(router *gin.RouterGroup) {
	v1 := router.Group("/api/v1")
	{
		gateways := v1.Group("/gateways")
		{
			gateways.POST("", s.CreateGateway)
			gateways.GET("", s.listGateways)
			gateways.GET("/:gateway_id", s.getGatewayHandler)
			gateways.PUT("/:gateway_id", s.updateGateway)
			gateways.DELETE("/:gateway_id", s.handleDeleteGateway)

			// Upstream management (scoped to gateway)
			upstreams := gateways.Group("/:gateway_id/upstreams")
			{
				upstreams.POST("", s.createUpstream)
				upstreams.GET("", s.listUpstreams)
				upstreams.GET("/:upstream_id", s.getUpstream)
				upstreams.PUT("/:upstream_id", s.updateUpstream)
				upstreams.DELETE("/:upstream_id", s.deleteUpstream)
			}

			// Service management (scoped to gateway)
			services := gateways.Group("/:gateway_id/services")
			{
				services.POST("", s.createService)
				services.GET("", s.listServices)
				services.GET("/:service_id", s.getService)
				services.PUT("/:service_id", s.updateService)
				services.DELETE("/:service_id", s.deleteService)
			}

			// Rules management (already scoped to gateway)
			rules := gateways.Group("/:gateway_id/rules")
			{
				rules.GET("", s.listRules)
				rules.POST("", s.createRule)
				rules.PUT("/:rule_id", s.updateRule)
				rules.DELETE("/:rule_id", s.deleteRule)
			}

			// API key management
			keys := gateways.Group("/:gateway_id/keys")
			{
				keys.POST("", s.createAPIKey)
				keys.GET("", s.listAPIKeys)
				keys.GET("/:key_id", s.getAPIKeyHandler)
				keys.DELETE("/:key_id", s.deleteAPIKey)
			}
		}
	}
}

func (s *AdminServer) setupRoutes() {
	// Create the base router group and add routes to it
	baseRouter := s.router.Group("")
	s.AddRoutes(baseRouter)
}

func (s *AdminServer) Run() error {
	// Set up routes
	s.setupRoutes()

	// Start the server
	addr := fmt.Sprintf(":%d", s.config.Server.AdminPort)
	defer s.logger.WithField("addr", addr).Info("Starting admin server")
	return s.runServer(addr)
}

// Gateway Management
func (s *AdminServer) CreateGateway(c *gin.Context) {
	var gateway models.Gateway
	if err := c.ShouldBindJSON(&gateway); err != nil {
		s.logger.WithError(err).Error("Failed to bind request")
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Set timestamps
	now := time.Now()
	gateway.CreatedAt = now
	gateway.UpdatedAt = now

	// Create gateway
	if err := s.repo.CreateGateway(c.Request.Context(), &gateway); err != nil {
		s.logger.WithError(err).Error("Failed to create gateway")
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if err := s.updateGatewayCache(c.Request.Context(), &gateway); err != nil {
		s.logger.WithError(err).Error("Failed to update gateway cache")
	}

	c.JSON(http.StatusCreated, gateway)
}

func generateAPIKey() string {
	// Generate 32 random bytes
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return uuid.NewString() // Fallback to UUID if crypto/rand fails
	}
	return base64.URLEncoding.EncodeToString(bytes)
}

func (s *AdminServer) listGateways(c *gin.Context) {
	offset := 0
	limit := 10

	if offsetStr := c.Query("offset"); offsetStr != "" {
		if val, err := strconv.Atoi(offsetStr); err == nil {
			offset = val
		}
	}
	if limitStr := c.Query("limit"); limitStr != "" {
		if val, err := strconv.Atoi(limitStr); err == nil && val > 0 && val <= 100 {
			limit = val
		}
	}

	dbGateways, err := s.repo.ListGateways(c, offset, limit)
	if err != nil {
		s.logger.WithError(err).Error("Failed to list gateways")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list gateways"})
		return
	}

	var gateways []types.Gateway
	for _, dbGateway := range dbGateways {
		gateway, err := s.convertDBGatewayToAPI(&dbGateway)
		if err != nil {
			s.logger.WithError(err).Error("Failed to convert gateway")
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to process gateway configuration"})
			return
		}
		gateways = append(gateways, *gateway)

		// Update cache in background
		go func(g models.Gateway) {
			ctx := context.Background()
			if err := s.updateGatewayCache(ctx, &g); err != nil {
				s.logger.WithError(err).Error("Failed to update gateway cache")
			}
		}(dbGateway)
	}

	c.JSON(http.StatusOK, gin.H{
		"gateways": gateways,
		"count":    len(gateways),
		"offset":   offset,
		"limit":    limit,
	})
}

func (s *AdminServer) getGatewayHandler(c *gin.Context) {
	gatewayID := c.Param("gateway_id")

	// Add request details logging
	s.logger.WithFields(logrus.Fields{
		"gateway_id": gatewayID,
		"method":     c.Request.Method,
		"path":       c.Request.URL.Path,
		"user_agent": c.Request.UserAgent(),
		"referer":    c.Request.Referer(),
	}).Info("Gateway retrieval request received")

	// Add validation for gateway ID
	if gatewayID == "" || gatewayID == "null" {
		s.logger.WithFields(logrus.Fields{
			"gateway_id": gatewayID,
			"method":     c.Request.Method,
			"path":       c.Request.URL.Path,
			"user_agent": c.Request.UserAgent(),
			"referer":    c.Request.Referer(),
		}).Error("Invalid gateway ID")
		c.JSON(http.StatusBadRequest, gin.H{"error": "Get gateway handler: Invalid gateway ID"})
		return
	}

	// Validate UUID format
	if _, err := uuid.Parse(gatewayID); err != nil {
		s.logger.WithError(err).WithField("gateway_id", gatewayID).Error("Invalid UUID format")
		c.JSON(http.StatusBadRequest, gin.H{"error": "Get gateway handler: Invalid gateway ID format"})
		return
	}

	s.logger.WithField("gateway_id", gatewayID).Info("Getting gateway")
	// Try to get from cache first
	gateway, err := s.getGatewayFromCache(c, gatewayID)
	if err != nil {
		// If not in cache, get from database
		dbGateway, err := s.repo.GetGateway(c, gatewayID)
		if err != nil {
			s.logger.WithError(err).Error("Failed to get gateway")
			c.JSON(http.StatusNotFound, gin.H{"error": "Gateway not found"})
			return
		}

		// Convert to API type
		gateway, err = s.convertDBGatewayToAPI(dbGateway)
		if err != nil {
			s.logger.WithError(err).Error("Failed to convert gateway")
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to process gateway configuration"})
			return
		}

		// Store in cache
		if err := s.updateGatewayCache(c.Request.Context(), dbGateway); err != nil {
			s.logger.WithError(err).Error("Failed to cache gateway")
		}
	}

	c.JSON(http.StatusOK, gateway)
}

func (s *AdminServer) getGatewayFromCache(c *gin.Context, id string) (*types.Gateway, error) {
	if err := validateGatewayID(id); err != nil {
		return nil, err
	}

	key := fmt.Sprintf("gateway:%s", id)
	gatewayJSON, err := s.cache.Get(c, key)
	if err != nil {
		return nil, err
	}

	var gateway types.Gateway
	if err := json.Unmarshal([]byte(gatewayJSON), &gateway); err != nil {
		return nil, err
	}

	return &gateway, nil
}

func (s *AdminServer) updateGateway(c *gin.Context) {
	gatewayID := c.Param("gateway_id")

	if err := validateGatewayID(gatewayID); err != nil {
		s.logger.WithError(err).WithField("gateway_id", gatewayID).Error("Invalid gateway ID")
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	dbGateway, err := s.repo.GetGateway(c, gatewayID)
	if err != nil {
		s.logger.WithError(err).Error("Failed to get gateway")
		c.JSON(http.StatusNotFound, gin.H{"error": "Gateway not found"})
		return
	}

	var req types.UpdateGatewayRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		s.logger.WithError(err).Error("Failed to bind request")
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if req.Name != nil {
		dbGateway.Name = *req.Name
	}
	if req.Status != nil {
		dbGateway.Status = *req.Status
	}

	if req.RequiredPlugins != nil {
		// Initialize plugins map
		if dbGateway.RequiredPlugins == nil {
			dbGateway.RequiredPlugins = []types.PluginConfig{}
		}

		// Convert and validate plugins
		manager := plugins.GetManager()
		for _, cfg := range req.RequiredPlugins {
			if err := manager.ValidatePlugin(cfg.Name, cfg); err != nil {
				s.logger.WithError(err).WithField("plugin", cfg.Name).Error("Invalid plugin configuration")
				c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("Invalid plugin configuration: %v", err)})
				return
			}
		}
	}

	dbGateway.UpdatedAt = time.Now()

	if err := s.repo.UpdateGateway(c, dbGateway); err != nil {
		s.logger.WithError(err).Error("Failed to update gateway")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update gateway"})
		return
	}

	// Convert to response type
	apiGateway, err := s.convertDBGatewayToAPI(dbGateway)
	if err != nil {
		s.logger.WithError(err).Error("Failed to convert gateway")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to process gateway"})
		return
	}

	response := types.Gateway{
		ID:              dbGateway.ID,
		Name:            dbGateway.Name,
		Subdomain:       dbGateway.Subdomain,
		Status:          dbGateway.Status,
		CreatedAt:       dbGateway.CreatedAt.Format(time.RFC3339),
		UpdatedAt:       dbGateway.UpdatedAt.Format(time.RFC3339),
		RequiredPlugins: apiGateway.RequiredPlugins,
	}

	if err := s.updateGatewayCache(c.Request.Context(), dbGateway); err != nil {
		s.logger.WithError(err).Error("Failed to update gateway cache")
	}

	// Invalidate caches
	if err := s.invalidateCaches(c.Request.Context(), dbGateway.ID); err != nil {
		s.logger.WithError(err).Error("Failed to invalidate caches")
	}

	c.JSON(http.StatusOK, response)
}

func (s *AdminServer) handleDeleteGateway(c *gin.Context) {
	id := c.Param("id")
	if id == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "id is required"})
		return
	}

	if err := s.repo.DeleteGateway(id); err != nil {
		s.logger.WithError(err).Error("Failed to delete gateway")
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.Status(http.StatusNoContent)
}

// API Key Management
func (s *AdminServer) createAPIKey(c *gin.Context) {
	gatewayID := c.Param("gateway_id")
	var req types.CreateAPIKeyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		s.logger.WithError(err).Error("Failed to bind request")
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Generate new API key
	apiKey := &models.APIKey{
		ID:        uuid.NewString(),
		Name:      req.Name,
		GatewayID: gatewayID,
		Key:       generateAPIKey(),
	}

	if req.ExpiresAt != nil {
		apiKey.ExpiresAt = *req.ExpiresAt
	}

	if err := s.repo.CreateAPIKey(c, apiKey); err != nil {
		s.logger.WithError(err).Error("Failed to create API key")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create API key"})
		return
	}

	// Save to cache
	if err := s.cache.SaveAPIKey(c, apiKey); err != nil {
		s.logger.WithError(err).Error("Failed to cache API key")
		// Continue anyway as key is in DB
	}

	c.JSON(http.StatusCreated, apiKey)
}

func (s *AdminServer) listAPIKeys(c *gin.Context) {
	gatewayID := c.Param("gateway_id")

	// Verify gateway exists
	if _, err := s.repo.GetGateway(c, gatewayID); err != nil {
		s.logger.WithError(err).Error("Failed to get gateway")
		c.JSON(http.StatusNotFound, gin.H{"error": "Gateway not found"})
		return
	}

	// Get API keys from database
	apiKeys, err := s.repo.ListAPIKeys(c, gatewayID)
	if err != nil {
		s.logger.WithError(err).Error("Failed to list API keys")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list API keys"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"api_keys": apiKeys,
		"count":    len(apiKeys),
	})
}

func (s *AdminServer) getAPIKeyHandler(c *gin.Context) {
	gatewayID := c.Param("gateway_id")
	keyID := c.Param("key_id")

	key := fmt.Sprintf("apikey:%s:%s", gatewayID, keyID)
	apiKeyJSON, err := s.cache.Get(c, key)
	if err != nil {
		if err.Error() == "redis: nil" {
			c.JSON(http.StatusNotFound, gin.H{"error": "API key not found"})
			return
		}
		s.logger.WithError(err).Error("Failed to get API key")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get API key"})
		return
	}

	var apiKey models.APIKey
	if err := json.Unmarshal([]byte(apiKeyJSON), &apiKey); err != nil {
		s.logger.WithError(err).Error("Failed to unmarshal API key")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get API key"})
		return
	}

	// Don't expose the actual key
	apiKey.Key = ""
	c.JSON(http.StatusOK, apiKey)
}

func (s *AdminServer) updateGatewayCache(ctx context.Context, gateway *models.Gateway) error {
	if err := validateGatewayID(gateway.ID); err != nil {
		return fmt.Errorf("invalid gateway ID: %w", err)
	}

	// Convert to API type for caching
	apiGateway, err := s.convertDBGatewayToAPI(gateway)
	if err != nil {
		return fmt.Errorf("failed to convert gateway: %w", err)
	}

	// Cache the gateway
	gatewayJSON, err := json.Marshal(apiGateway)
	if err != nil {
		return fmt.Errorf("failed to marshal gateway: %w", err)
	}

	key := fmt.Sprintf("gateway:%s", gateway.ID)
	if err := s.cache.Set(ctx, key, string(gatewayJSON), 0); err != nil {
		return fmt.Errorf("failed to cache gateway: %w", err)
	}

	return nil
}

func (s *AdminServer) convertDBGatewayToAPI(dbGateway *models.Gateway) (*types.Gateway, error) {
	if dbGateway.RequiredPlugins == nil {
		dbGateway.RequiredPlugins = []types.PluginConfig{}
	}

	return &types.Gateway{
		ID:              dbGateway.ID,
		Name:            dbGateway.Name,
		Subdomain:       dbGateway.Subdomain,
		Status:          dbGateway.Status,
		RequiredPlugins: dbGateway.RequiredPlugins,
		CreatedAt:       dbGateway.CreatedAt.Format(time.RFC3339),
		UpdatedAt:       dbGateway.UpdatedAt.Format(time.RFC3339),
	}, nil
}

// Helper function to validate gateway ID format
func validateGatewayID(id string) error {
	if id == "" {
		return fmt.Errorf("gateway ID cannot be empty")
	}

	// Check if it's a valid UUID
	if _, err := uuid.Parse(id); err != nil {
		return fmt.Errorf("gateway ID must be a valid UUID: %v", err)
	}

	return nil
}

func (s *AdminServer) getRuleResponse(rule *models.ForwardingRule) (types.ForwardingRule, error) {
	var pluginChain []types.PluginConfig
	if rule.PluginChain != nil {
		chainJSON, err := json.Marshal(rule.PluginChain)
		if err != nil {
			return types.ForwardingRule{}, fmt.Errorf("failed to marshal plugin chain: %w", err)
		}
		if err := json.Unmarshal(chainJSON, &pluginChain); err != nil {
			return types.ForwardingRule{}, fmt.Errorf("failed to unmarshal plugin chain: %w", err)
		}
	}

	// Convert headers from pq.StringArray to map[string]string
	headers := make(map[string]string)
	for _, h := range rule.Headers {
		parts := strings.SplitN(h, ":", 2)
		if len(parts) == 2 {
			headers[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}

	return types.ForwardingRule{
		ID:            rule.ID,
		GatewayID:     rule.GatewayID,
		Path:          rule.Path,
		ServiceID:     rule.ServiceID,
		Methods:       []string(rule.Methods),
		Headers:       headers,
		StripPath:     rule.StripPath,
		PreserveHost:  rule.PreserveHost,
		RetryAttempts: rule.RetryAttempts,
		PluginChain:   pluginChain,
		Active:        rule.Active,
		Public:        rule.Public,
		CreatedAt:     rule.CreatedAt.Format(time.RFC3339),
		UpdatedAt:     rule.UpdatedAt.Format(time.RFC3339),
	}, nil
}

// Rule management methods
func (s *AdminServer) createRule(c *gin.Context) {
	gatewayID := c.Param("gateway_id")

	var req types.CreateRuleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		s.logger.WithError(err).Error("Failed to bind request")
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Validate the rule request
	if err := s.validateRule(&req); err != nil {
		s.logger.WithError(err).Error("Failed to validate rule")
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Convert headers to map[string]string format
	headers := make(map[string]string)
	for k, v := range req.Headers {
		headers[k] = v
	}

	// Set default values for optional fields
	stripPath := false
	if req.StripPath != nil {
		stripPath = *req.StripPath
	}

	preserveHost := false
	if req.PreserveHost != nil {
		preserveHost = *req.PreserveHost
	}

	retryAttempts := 0
	if req.RetryAttempts != nil {
		retryAttempts = *req.RetryAttempts
	}

	// Create the database model
	dbRule := &models.ForwardingRule{
		ID:            uuid.NewString(),
		GatewayID:     gatewayID,
		Path:          req.Path,
		ServiceID:     req.ServiceID,
		Methods:       req.Methods,
		Headers:       models.HeadersJSON(req.Headers),
		StripPath:     stripPath,
		PreserveHost:  preserveHost,
		RetryAttempts: retryAttempts,
		PluginChain:   req.PluginChain,
		Active:        true,
		Public:        false,
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}

	// Store in database
	if err := s.repo.CreateRule(c, dbRule); err != nil {
		s.logger.WithError(err).Error("Failed to create rule")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create rule"})
		return
	}

	// Use existing helper to convert to API response
	response, err := s.getRuleResponse(dbRule)
	if err != nil {
		s.logger.WithError(err).Error("Failed to get rule response")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to process rule"})
		return
	}

	c.JSON(http.StatusCreated, response)
}

func (s *AdminServer) listRules(c *gin.Context) {
	gatewayID := c.Param("gateway_id")

	// Get rules from database
	dbRules, err := s.repo.ListRules(c, gatewayID)
	if err != nil {
		s.logger.WithError(err).Error("Failed to get rules from database")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list rules"})
		return
	}

	// Convert to API response format
	rules := make([]types.ForwardingRule, len(dbRules))
	for i, rule := range dbRules {
		rules[i] = types.ForwardingRule{
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
			CreatedAt:     rule.CreatedAt.Format(time.RFC3339),
			UpdatedAt:     rule.UpdatedAt.Format(time.RFC3339),
		}
	}

	// Cache the rules for future requests
	rulesJSON, err := json.Marshal(rules)
	if err == nil {
		rulesKey := fmt.Sprintf("rules:%s", gatewayID)
		if err := s.cache.Set(c, rulesKey, string(rulesJSON), 0); err != nil {
			s.logger.WithError(err).Warn("Failed to cache rules")
		}
	}

	c.JSON(http.StatusOK, rules)
}

func (s *AdminServer) updateRule(c *gin.Context) {
	gatewayID := c.Param("gateway_id")
	ruleID := c.Param("rule_id")

	var req types.UpdateRuleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		s.logger.WithError(err).Error("Failed to bind request")
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Convert UpdateRuleRequest to CreateRuleRequest for validation
	validateReq := types.CreateRuleRequest{
		Path:          req.Path,
		ServiceID:     req.ServiceID,
		Methods:       req.Methods,
		Headers:       req.Headers,
		StripPath:     req.StripPath,
		PreserveHost:  req.PreserveHost,
		RetryAttempts: req.RetryAttempts,
		PluginChain:   req.PluginChain,
	}

	// Validate the rule request
	if err := s.validateRule(&validateReq); err != nil {
		s.logger.WithError(err).Error("Rule validation failed")
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Get existing rules
	rulesKey := fmt.Sprintf("rules:%s", gatewayID)
	rulesJSON, err := s.cache.Get(c, rulesKey)
	if err != nil {
		s.logger.WithError(err).Error("Failed to get rules")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update rule"})
		return
	}

	var rules []types.ForwardingRule
	if err := json.Unmarshal([]byte(rulesJSON), &rules); err != nil {
		s.logger.WithError(err).Error("Failed to unmarshal rules")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update rule"})
		return
	}

	// Find and update rule
	found := false
	for i, rule := range rules {
		if rule.ID == ruleID {
			if req.Path != "" {
				rules[i].Path = req.Path
			}
			if len(req.Methods) > 0 {
				rules[i].Methods = pq.StringArray(req.Methods)
			}
			if req.Headers != nil {
				rules[i].Headers = convertMapToDBHeaders(req.Headers)
			}
			if req.StripPath != nil {
				rules[i].StripPath = *req.StripPath
			}
			if req.Active != nil {
				rules[i].Active = *req.Active
			}
			if req.PreserveHost != nil {
				rules[i].PreserveHost = *req.PreserveHost
			}
			if req.RetryAttempts != nil {
				rules[i].RetryAttempts = *req.RetryAttempts
			}
			if req.PluginChain != nil {
				chainJSON, err := json.Marshal(req.PluginChain)
				if err != nil {
					s.logger.WithError(err).Error("Failed to marshal plugin chain")
					c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to process plugin chain"})
					return
				}
				var pluginChain []types.PluginConfig
				if err := json.Unmarshal(chainJSON, &pluginChain); err != nil {
					s.logger.WithError(err).Error("Failed to unmarshal plugin chain")
					c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to process plugin chain"})
					return
				}
				pluginChainMap, err := json.Marshal(pluginChain)
				if err != nil {
					s.logger.WithError(err).Error("Failed to marshal plugin chain")
					c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to process plugin chain"})
					return
				}
				var jsonMap map[string]interface{}
				if err := json.Unmarshal(pluginChainMap, &jsonMap); err != nil {
					s.logger.WithError(err).Error("Failed to unmarshal plugin chain")
					c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to process plugin chain"})
					return
				}
				rules[i].PluginChain = pluginChain
			}
			found = true
			break
		}
	}

	if !found {
		c.JSON(http.StatusNotFound, gin.H{"error": "Rule not found"})
		return
	}

	// Save updated rules
	updatedJSON, err := json.Marshal(rules)
	if err != nil {
		s.logger.WithError(err).Error("Failed to marshal rules")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update rule"})
		return
	}

	if err := s.cache.Set(c, rulesKey, string(updatedJSON), 0); err != nil {
		s.logger.WithError(err).Error("Failed to save rules")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update rule"})
		return
	}

	// After successfully updating the rule
	if err := s.publishCacheInvalidation(c.Request.Context(), gatewayID); err != nil {
		s.logger.WithError(err).Error("Failed to publish cache invalidation")
	}

	c.JSON(http.StatusOK, gin.H{"message": "Rule updated successfully"})
}

func (s *AdminServer) deleteRule(c *gin.Context) {
	gatewayID := c.Param("gateway_id")
	ruleID := c.Param("rule_id")

	// Get existing rules
	rulesKey := fmt.Sprintf("rules:%s", gatewayID)
	rulesJSON, err := s.cache.Get(c, rulesKey)
	if err != nil {
		s.logger.WithError(err).Error("Failed to get rules")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete rule"})
		return
	}

	var rules []types.ForwardingRule
	if err := json.Unmarshal([]byte(rulesJSON), &rules); err != nil {
		s.logger.WithError(err).Error("Failed to unmarshal rules")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete rule"})
		return
	}

	// Find and remove rule
	found := false
	var updatedRules []types.ForwardingRule
	for _, rule := range rules {
		if rule.ID == ruleID {
			found = true
			continue
		}
		updatedRules = append(updatedRules, rule)
	}

	if !found {
		c.JSON(http.StatusNotFound, gin.H{"error": "Rule not found"})
		return
	}

	// Save updated rules
	updatedJSON, err := json.Marshal(updatedRules)
	if err != nil {
		s.logger.WithError(err).Error("Failed to marshal rules")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete rule"})
		return
	}

	if err := s.cache.Set(c, rulesKey, string(updatedJSON), 0); err != nil {
		s.logger.WithError(err).Error("Failed to save rules")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete rule"})
		return
	}

	// After successfully deleting the rule
	if err := s.publishCacheInvalidation(c.Request.Context(), gatewayID); err != nil {
		s.logger.WithError(err).Error("Failed to publish cache invalidation")
	}

	c.JSON(http.StatusOK, gin.H{"message": "Rule deleted successfully"})
}

// API key management methods
func (s *AdminServer) deleteAPIKey(c *gin.Context) {
	gatewayID := c.Param("gateway_id")
	keyID := c.Param("key_id")

	// Delete API key from cache
	key := fmt.Sprintf("apikey:%s:%s", gatewayID, keyID)
	if err := s.cache.Delete(c, key); err != nil {
		s.logger.WithError(err).Error("Failed to delete API key")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete API key"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "API key deleted successfully"})
}

func convertMapToDBHeaders(headers map[string]string) map[string]string {
	result := make(map[string]string)
	for k, v := range headers {
		result[k] = v
	}
	return result
}

func (s *AdminServer) invalidateCaches(ctx context.Context, gatewayID string) error {
	// Get cache keys
	keys := common.GetCacheKeys(gatewayID)

	// Delete cache entries and handle errors
	if err := s.cache.Delete(ctx, keys.Gateway); err != nil {
		return fmt.Errorf("failed to delete gateway cache: %w", err)
	}

	if err := s.cache.Delete(ctx, keys.Rules); err != nil {
		return fmt.Errorf("failed to delete rules cache: %w", err)
	}

	if err := s.cache.Delete(ctx, keys.Plugin); err != nil {
		return fmt.Errorf("failed to delete plugin cache: %w", err)
	}

	// Publish cache invalidation event
	if err := s.publishCacheInvalidation(ctx, gatewayID); err != nil {
		return fmt.Errorf("failed to publish cache invalidation: %w", err)
	}

	return nil
}

func (s *AdminServer) publishCacheInvalidation(ctx context.Context, gatewayID string) error {
	msg := map[string]string{
		"type":      "cache_invalidation",
		"gatewayID": gatewayID,
	}

	msgJSON, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("failed to marshal message: %w", err)
	}

	// Get Redis client from cache
	rdb := s.cache.Client()
	return rdb.Publish(ctx, "gateway_events", string(msgJSON)).Err()
}

func (s *AdminServer) validateRule(rule *types.CreateRuleRequest) error {
	// Validate required fields
	if rule.Path == "" {
		return fmt.Errorf("path is required")
	}

	if len(rule.Methods) == 0 {
		return fmt.Errorf("at least one method is required")
	}

	if rule.ServiceID == "" {
		return fmt.Errorf("service_id is required")
	}

	// Validate methods
	validMethods := map[string]bool{
		"GET":     true,
		"POST":    true,
		"PUT":     true,
		"DELETE":  true,
		"PATCH":   true,
		"HEAD":    true,
		"OPTIONS": true,
	}
	for _, method := range rule.Methods {
		if !validMethods[strings.ToUpper(method)] {
			return fmt.Errorf("invalid HTTP method: %s", method)
		}
	}

	// Validate plugin chain if present
	if len(rule.PluginChain) > 0 {
		for i, plugin := range rule.PluginChain {
			if err := s.validatePlugin(plugin); err != nil {
				return fmt.Errorf("plugin %d: %v", i, err)
			}
		}
	}

	return nil
}

func (s *AdminServer) validatePlugin(plugin types.PluginConfig) error {
	// Validate required fields
	if plugin.Name == "" {
		return fmt.Errorf("plugin name is required")
	}

	if plugin.Stage == "" {
		return fmt.Errorf("plugin stage is required")
	}

	// Validate settings
	if plugin.Settings == nil {
		return fmt.Errorf("plugin settings are required")
	}

	// Validate stage
	validStages := map[types.Stage]bool{
		types.PreRequest:   true,
		types.PostRequest:  true,
		types.PreResponse:  true,
		types.PostResponse: true,
	}
	if !validStages[plugin.Stage] {
		return fmt.Errorf("invalid plugin stage: %s", plugin.Stage)
	}

	// Validate priority (0-999)
	if plugin.Priority < 0 || plugin.Priority > 999 {
		return fmt.Errorf("plugin priority must be between 0 and 999")
	}

	// Get plugin validator
	manager := plugins.GetManager()
	if err := manager.ValidatePlugin(plugin.Name, plugin); err != nil {
		return fmt.Errorf("unknown plugin: %s", plugin.Name)
	}
	return nil
}

// Upstream handlers with caching
func (s *AdminServer) createUpstream(c *gin.Context) {
	gatewayID := c.Param("gateway_id")

	var entity models.Upstream
	if err := c.ShouldBindJSON(&entity); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	entity.GatewayID = gatewayID

	if err := s.repo.CreateUpstream(c.Request.Context(), &entity); err != nil {
		s.logger.WithError(err).Error("Failed to create upstream")
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Cache the upstream
	if err := s.cache.SaveUpstream(c.Request.Context(), gatewayID, &entity); err != nil {
		s.logger.WithError(err).Error("Failed to cache upstream")
	}

	c.JSON(http.StatusCreated, entity)
}

func (s *AdminServer) listUpstreams(c *gin.Context) {
	gatewayID := c.Param("gateway_id")
	offset := 0
	limit := 10

	if offsetStr := c.Query("offset"); offsetStr != "" {
		if val, err := strconv.Atoi(offsetStr); err == nil {
			offset = val
		}
	}
	if limitStr := c.Query("limit"); limitStr != "" {
		if val, err := strconv.Atoi(limitStr); err == nil && val > 0 && val <= 100 {
			limit = val
		}
	}

	// Try to get from cache first
	upstreamsKey := fmt.Sprintf(cache.UpstreamsKeyPattern, gatewayID)
	if upstreamsJSON, err := s.cache.Get(c.Request.Context(), upstreamsKey); err == nil {
		var upstreams []models.Upstream
		if err := json.Unmarshal([]byte(upstreamsJSON), &upstreams); err == nil {
			c.JSON(http.StatusOK, upstreams)
			return
		}
	}

	// If not in cache, get from database
	upstreams, err := s.repo.ListUpstreams(c.Request.Context(), gatewayID, offset, limit)
	if err != nil {
		s.logger.WithError(err).Error("Failed to list upstreams")
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Cache the results
	if upstreamsJSON, err := json.Marshal(upstreams); err == nil {
		if err := s.cache.Set(c.Request.Context(), upstreamsKey, string(upstreamsJSON), 0); err != nil {
			s.logger.WithError(err).Error("Failed to cache upstreams list")
		}
	}

	c.JSON(http.StatusOK, upstreams)
}

func (s *AdminServer) getUpstream(c *gin.Context) {
	gatewayID := c.Param("gateway_id")
	upstreamID := c.Param("upstream_id")

	// Try to get from cache first
	upstreamKey := fmt.Sprintf(cache.UpstreamKeyPattern, gatewayID, upstreamID)
	if upstreamJSON, err := s.cache.Get(c.Request.Context(), upstreamKey); err == nil {
		var entity models.Upstream
		if err := json.Unmarshal([]byte(upstreamJSON), &entity); err == nil {
			c.JSON(http.StatusOK, entity)
			return
		}
	}

	// If not in cache, get from database
	entity, err := s.upstreamFinder.Find(c.Request.Context(), gatewayID, upstreamID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Upstream not found"})
		return
	}

	// Cache the upstream
	if err := s.cache.SaveUpstream(c.Request.Context(), gatewayID, entity); err != nil {
		s.logger.WithError(err).Error("Failed to cache upstream")
	}

	c.JSON(http.StatusOK, entity)
}

func (s *AdminServer) updateUpstream(c *gin.Context) {
	gatewayID := c.Param("gateway_id")
	upstreamID := c.Param("upstream_id")

	var entity models.Upstream
	if err := c.ShouldBindJSON(&entity); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Ensure IDs match
	entity.ID = upstreamID
	entity.GatewayID = gatewayID

	if err := s.repo.UpdateUpstream(c.Request.Context(), &entity); err != nil {
		s.logger.WithError(err).Error("Failed to update upstream")
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Cache the updated upstream
	if err := s.cache.SaveUpstream(c.Request.Context(), gatewayID, &entity); err != nil {
		s.logger.WithError(err).Error("Failed to cache upstream")
	}

	c.JSON(http.StatusOK, entity)
}

func (s *AdminServer) deleteUpstream(c *gin.Context) {
	gatewayID := c.Param("gateway_id")
	upstreamID := c.Param("upstream_id")

	if err := s.repo.DeleteUpstream(c.Request.Context(), upstreamID); err != nil {
		if strings.Contains(err.Error(), "being used by") {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		s.logger.WithError(err).Error("Failed to delete upstream")
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Invalidate cache
	upstreamKey := fmt.Sprintf(cache.UpstreamKeyPattern, gatewayID, upstreamID)
	upstreamsKey := fmt.Sprintf(cache.UpstreamsKeyPattern, gatewayID)
	if err := s.cache.Delete(c.Request.Context(), upstreamKey); err != nil {
		s.logger.WithError(err).Error("Failed to invalidate upstream cache")
	}
	if err := s.cache.Delete(c.Request.Context(), upstreamsKey); err != nil {
		s.logger.WithError(err).Error("Failed to invalidate upstreams list cache")
	}

	c.Status(http.StatusNoContent)
}

// Service handlers with caching
func (s *AdminServer) createService(c *gin.Context) {
	gatewayID := c.Param("gateway_id")

	var service models.Service
	if err := c.ShouldBindJSON(&service); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	service.GatewayID = gatewayID

	if err := s.repo.CreateService(c.Request.Context(), &service); err != nil {
		s.logger.WithError(err).Error("Failed to create service")
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Cache the service
	if err := s.cache.SaveService(c.Request.Context(), gatewayID, &service); err != nil {
		s.logger.WithError(err).Error("Failed to cache service")
	}

	c.JSON(http.StatusCreated, service)
}

func (s *AdminServer) listServices(c *gin.Context) {
	gatewayID := c.Param("gateway_id")
	offset := 0
	limit := 10

	if offsetStr := c.Query("offset"); offsetStr != "" {
		if val, err := strconv.Atoi(offsetStr); err == nil {
			offset = val
		}
	}
	if limitStr := c.Query("limit"); limitStr != "" {
		if val, err := strconv.Atoi(limitStr); err == nil && val > 0 && val <= 100 {
			limit = val
		}
	}

	services, err := s.repo.ListServices(c.Request.Context(), gatewayID, offset, limit)
	if err != nil {
		s.logger.WithError(err).Error("Failed to list services")
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, services)
}

func (s *AdminServer) getService(c *gin.Context) {
	gatewayID := c.Param("gateway_id")
	serviceID := c.Param("service_id")

	// Try to get from cache first
	serviceKey := fmt.Sprintf(cache.ServiceKeyPattern, gatewayID, serviceID)
	if serviceJSON, err := s.cache.Get(c.Request.Context(), serviceKey); err == nil {
		var service models.Service
		if err := json.Unmarshal([]byte(serviceJSON), &service); err == nil {
			c.JSON(http.StatusOK, service)
			return
		}
	}

	// If not in cache, get from database
	service, err := s.repo.GetService(c.Request.Context(), serviceID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Service not found"})
		return
	}

	// Cache the service
	if err := s.cache.SaveService(c.Request.Context(), gatewayID, service); err != nil {
		s.logger.WithError(err).Error("Failed to cache service")
	}

	c.JSON(http.StatusOK, service)
}

func (s *AdminServer) updateService(c *gin.Context) {
	gatewayID := c.Param("gateway_id")
	serviceID := c.Param("service_id")

	var service models.Service
	if err := c.ShouldBindJSON(&service); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Ensure IDs match
	service.ID = serviceID
	service.GatewayID = gatewayID

	if err := s.repo.UpdateService(c.Request.Context(), &service); err != nil {
		s.logger.WithError(err).Error("Failed to update service")
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Cache the updated service
	if err := s.cache.SaveService(c.Request.Context(), gatewayID, &service); err != nil {
		s.logger.WithError(err).Error("Failed to cache service")
	}

	c.JSON(http.StatusOK, service)
}

func (s *AdminServer) deleteService(c *gin.Context) {
	gatewayID := c.Param("gateway_id")
	serviceID := c.Param("service_id")

	if err := s.repo.DeleteService(c.Request.Context(), serviceID); err != nil {
		if strings.Contains(err.Error(), "being used by") {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		s.logger.WithError(err).Error("Failed to delete service")
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Invalidate cache
	serviceKey := fmt.Sprintf(cache.ServiceKeyPattern, gatewayID, serviceID)
	servicesKey := fmt.Sprintf(cache.ServicesKeyPattern, gatewayID)
	if err := s.cache.Delete(c.Request.Context(), serviceKey); err != nil {
		s.logger.WithError(err).Error("Failed to invalidate service cache")
	}
	if err := s.cache.Delete(c.Request.Context(), servicesKey); err != nil {
		s.logger.WithError(err).Error("Failed to invalidate services list cache")
	}

	c.Status(http.StatusNoContent)
}
