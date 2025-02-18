package server

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/NeuralTrust/TrustGate/pkg/app/upstream"
	handlers "github.com/NeuralTrust/TrustGate/pkg/handlers/http"
	"github.com/NeuralTrust/TrustGate/pkg/middleware"
	"github.com/NeuralTrust/TrustGate/pkg/types"
	"github.com/gofiber/fiber/v2"
	"github.com/sirupsen/logrus"
	"github.com/valyala/fasthttp"
	"github.com/valyala/fasthttp/fasthttpadaptor"
	"io"
	"net/http"
	_ "net/http/pprof"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/cache"
	"github.com/NeuralTrust/TrustGate/pkg/common"
	"github.com/NeuralTrust/TrustGate/pkg/config"
	"github.com/NeuralTrust/TrustGate/pkg/database"
	"github.com/NeuralTrust/TrustGate/pkg/loadbalancer"
	"github.com/NeuralTrust/TrustGate/pkg/metrics"
	"github.com/NeuralTrust/TrustGate/pkg/pluginiface"
	"github.com/NeuralTrust/TrustGate/pkg/plugins"

	"golang.org/x/exp/slices"
)

type (
	ProxyServerDI struct {
		Config         *config.Config
		Cache          *cache.Cache
		Repo           *database.Repository
		Logger         *logrus.Logger
		Manager        *plugins.Manager
		SkipAuthCheck  bool
		ExtraPlugins   []pluginiface.Plugin
		UpstreamFinder upstream.Finder
	}
	ProxyServer struct {
		*BaseServer
		repo           *database.Repository
		pluginManager  *plugins.Manager
		gatewayCache   *common.TTLMap
		rulesCache     *common.TTLMap
		pluginCache    *common.TTLMap
		skipAuthCheck  bool
		httpClient     *http.Client
		loadBalancers  sync.Map // map[string]*loadbalancer.LoadBalancer
		providers      map[string]config.ProviderConfig
		lbFactory      loadbalancer.Factory
		upstreamFinder upstream.Finder
	}
)

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

func NewProxyServer(di ProxyServerDI) *ProxyServer {
	// Initialize metrics with config from yaml
	metricsConfig := metrics.MetricsConfig{
		EnableLatency:         di.Config.Metrics.EnableLatency,
		EnableUpstreamLatency: di.Config.Metrics.EnableUpstream,
		EnableConnections:     di.Config.Metrics.EnableConnections,
		EnablePerRoute:        di.Config.Metrics.EnablePerRoute,
	}
	metrics.Initialize(metricsConfig)

	// Create TTL maps
	gatewayCache := di.Cache.CreateTTLMap("gateway", GatewayCacheTTL)
	rulesCache := di.Cache.CreateTTLMap("rules", RulesCacheTTL)
	pluginCache := di.Cache.CreateTTLMap("plugin", PluginCacheTTL)

	// Register extra plugins with error handling
	for _, plugin := range di.ExtraPlugins {
		if err := di.Manager.RegisterPlugin(plugin); err != nil {
			di.Logger.WithFields(logrus.Fields{
				"plugin": plugin.Name(),
				"error":  err,
			}).Error("Failed to register plugin")
		}
	}

	s := &ProxyServer{
		BaseServer:     NewBaseServer(di.Config, di.Cache, di.Repo, di.Logger),
		repo:           di.Repo,
		pluginManager:  di.Manager,
		gatewayCache:   gatewayCache,
		rulesCache:     rulesCache,
		pluginCache:    pluginCache,
		skipAuthCheck:  di.SkipAuthCheck,
		httpClient:     &http.Client{},
		providers:      di.Config.Providers.Providers,
		lbFactory:      loadbalancer.NewBaseFactory(),
		upstreamFinder: di.UpstreamFinder,
	}

	s.BaseServer.setupMetricsEndpoint()
	// Subscribe to gateway events
	go s.subscribeToEvents()

	return s
}

func (s *ProxyServer) Run() error {

	// Create auth middleware
	authMiddleware := middleware.NewAuthMiddleware(s.logger, s.repo)
	gatewayMiddleware := middleware.NewGatewayMiddleware(s.logger, s.cache, s.repo, s.config.Server.BaseDomain)
	metricsMiddleware := middleware.NewMetricsMiddleware(s.logger)

	forwardedHandler := handlers.NewForwardedHandler(s.logger, s.repo, s.cache, s.upstreamFinder, s.skipAuthCheck)

	// Register system routes
	s.router.Get(AdminHealthPath, func(ctx *fiber.Ctx) error {
		return ctx.Status(http.StatusOK).JSON(fiber.Map{
			"status": "ok",
			"time":   time.Now().Format(time.RFC3339),
		})
	})

	s.router.Get(HealthPath, func(ctx *fiber.Ctx) error {
		return ctx.Status(http.StatusOK).JSON(fiber.Map{
			"status": "ok",
			"time":   time.Now().Format(time.RFC3339),
		})
	})

	s.router.Get(PingPath, func(ctx *fiber.Ctx) error {
		return ctx.Status(http.StatusOK).JSON(fiber.Map{
			"message": "pong",
		})
	})

	s.router.Get("/debug/pprof/*", func(c *fiber.Ctx) error {
		pprofHandler := fasthttpadaptor.NewFastHTTPHandler(http.DefaultServeMux)
		pprofHandler(c.Context())
		return nil
	})

	// Register the main handler for all non-system routes
	s.router.Use(
		authMiddleware.ValidateAPIKey(),
		gatewayMiddleware.IdentifyGateway(),
		metricsMiddleware.MetricsMiddleware(),
		forwardedHandler,
	)

	return s.router.Listen(fmt.Sprintf(":%d", s.config.Server.ProxyPort))
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
