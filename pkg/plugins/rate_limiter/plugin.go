package rate_limiter

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/google/uuid"
	"github.com/mitchellh/mapstructure"

	"ai-gateway-ce/pkg/pluginiface"
	"ai-gateway-ce/pkg/types"
)

type RateLimiterPlugin struct {
	redis  *redis.Client
	limits map[string]LimitConfig
}

type LimitConfig struct {
	Limit  int    `json:"limit"`
	Window string `json:"window"`
}

type Config struct {
	Limits  map[string]LimitConfig `mapstructure:"limits"`
	Actions struct {
		Type       string `mapstructure:"type"`
		RetryAfter string `mapstructure:"retry_after"`
	} `mapstructure:"actions"`
}

func NewRateLimiterPlugin(redisClient *redis.Client) pluginiface.Plugin {
	return &RateLimiterPlugin{
		redis:  redisClient,
		limits: make(map[string]LimitConfig),
	}
}

func (r *RateLimiterPlugin) Name() string {
	return "rate_limiter"
}

func (r *RateLimiterPlugin) Stages() []types.Stage {
	return []types.Stage{types.PreRequest}
}

type RateLimiterValidator struct{}

func (v *RateLimiterValidator) ValidateConfig(config types.PluginConfig) error {
	if config.Stage != types.PreRequest {
		return fmt.Errorf("rate limiter plugin must be in pre_request stage")
	}

	// Validate settings
	settings := config.Settings
	limits, ok := settings["limits"].(map[string]interface{})
	if !ok {
		return fmt.Errorf("rate limiter requires 'limits' configuration")
	}

	// Validate each limit configuration
	for limitType, config := range limits {
		limitConfig, ok := config.(map[string]interface{})
		if !ok {
			return fmt.Errorf("invalid limit configuration for %s", limitType)
		}

		// Validate limit value
		limit, ok := limitConfig["limit"].(float64)
		if !ok || limit <= 0 {
			return fmt.Errorf("rate limiter requires positive 'limit' value for %s", limitType)
		}

		// Validate window
		window, ok := limitConfig["window"].(string)
		if !ok || window == "" {
			return fmt.Errorf("rate limiter requires 'window' configuration for %s", limitType)
		}

		// Validate window format
		if _, err := time.ParseDuration(window); err != nil {
			return fmt.Errorf("invalid window format for %s: %v", limitType, err)
		}
	}

	actions, ok := settings["actions"].(map[string]interface{})
	if !ok {
		return fmt.Errorf("rate limiter requires 'actions' configuration")
	}

	actionType, ok := actions["type"].(string)
	if !ok {
		return fmt.Errorf("rate limiter requires 'type' configuration")
	}

	if actionType != "reject" && actionType != "block" {
		return fmt.Errorf("rate limiter requires 'type' to be 'reject' or 'block'")
	}

	return nil
}

func (r *RateLimiterPlugin) Execute(ctx context.Context, cfg types.PluginConfig, req *types.RequestContext, resp *types.ResponseContext) (*types.PluginResponse, error) {
	var config Config
	if err := mapstructure.Decode(cfg.Settings, &config); err != nil {
		return nil, fmt.Errorf("invalid rate limiter config: %w", err)
	}

	// Initialize headers map if nil
	if resp.Headers == nil {
		resp.Headers = make(map[string][]string)
	}

	type limitStatus struct {
		exceeded     bool
		limitType    string
		retryAfter   string
		currentCount int64
	}

	var finalStatus limitStatus

	// Check limits in specific order: per_ip -> per_user -> global
	limitOrder := []string{"per_ip", "per_user", "global"}

	for _, limitType := range limitOrder {
		if limitCfg, ok := config.Limits[limitType]; ok {
			// Skip per_user check if user is anonymous
			if limitType == "per_user" {
				userKey := r.extractKey(req, limitType)
				if userKey == "anonymous" {
					continue
				}
			}

			window, err := time.ParseDuration(limitCfg.Window)
			if err != nil {
				return nil, fmt.Errorf("invalid window duration for %s: %w", limitType, err)
			}

			key := fmt.Sprintf("ratelimit:%s:%s:%s:%s",
				cfg.Level,
				cfg.ID,
				limitType,
				r.extractKey(req, limitType),
			)

			now := time.Now()
			windowStart := now.Add(-window).Unix()

			// Check current count
			currentCount, err := r.redis.ZCount(ctx, key,
				strconv.FormatInt(windowStart, 10),
				strconv.FormatInt(now.Unix(), 10)).Result()
			if err != nil {
				return nil, fmt.Errorf("failed to get count for %s: %w", limitType, err)
			}

			// Set rate limit headers
			resetTime := now.Add(window)
			headerPrefix := fmt.Sprintf("X-RateLimit-%s", limitType)
			resp.Headers[headerPrefix+"-Limit"] = []string{strconv.Itoa(limitCfg.Limit)}
			resp.Headers[headerPrefix+"-Remaining"] = []string{strconv.FormatInt(int64(limitCfg.Limit)-currentCount, 10)}
			resp.Headers[headerPrefix+"-Reset"] = []string{strconv.FormatInt(resetTime.Unix(), 10)}

			// Check if limit would be exceeded
			if currentCount >= int64(limitCfg.Limit) {
				finalStatus = limitStatus{
					exceeded:     true,
					limitType:    limitType,
					retryAfter:   config.Actions.RetryAfter,
					currentCount: currentCount,
				}
				break
			}

			// Only increment counter if not exceeded
			requestID := fmt.Sprintf("%d:%s", now.Unix(), uuid.New().String())
			pipe := r.redis.Pipeline()

			pipe.ZRemRangeByScore(ctx, key, "0", strconv.FormatInt(windowStart, 10))
			pipe.ZAdd(ctx, key, &redis.Z{
				Score:  float64(now.Unix()),
				Member: requestID,
			})
			pipe.Expire(ctx, key, window)

			if _, err := pipe.Exec(ctx); err != nil {
				return nil, fmt.Errorf("failed to execute rate limit pipeline: %w", err)
			}
		}
	}

	// Return error if any limit was exceeded
	if finalStatus.exceeded {
		if finalStatus.retryAfter == "" {
			finalStatus.retryAfter = "60"
		}

		resp.Headers["Retry-After"] = []string{finalStatus.retryAfter}
		resp.Metadata["rate_limit_exceeded"] = true
		resp.Metadata["rate_limit_type"] = finalStatus.limitType
		resp.Metadata["retry_after"] = finalStatus.retryAfter

		return nil, &types.PluginError{
			StatusCode: http.StatusTooManyRequests,
			Message:    fmt.Sprintf("%s rate limit exceeded", finalStatus.limitType),
			Err:        fmt.Errorf("retry after %s seconds", finalStatus.retryAfter),
		}
	}

	return nil, nil
}

func (r *RateLimiterPlugin) extractKey(req *types.RequestContext, limitType string) string {
	switch limitType {
	case "global":
		return "global"
	case "per_ip":
		// Try different common IP headers in order of preference
		ipHeaders := []string{
			"X-Real-IP",
			"X-Real-Ip", // Mixed case version
			"X-Forwarded-For",
			"X-Original-Forwarded-For",
			"True-Client-IP",
			"CF-Connecting-IP",
		}

		for _, header := range ipHeaders {
			if ips := req.Headers[header]; len(ips) > 0 {
				return ips[0]
			}
		}
		return "unknown"

	case "per_user":
		// Try different common user ID headers
		userHeaders := []string{
			"X-User-ID",
			"X-User-Id", // Mixed case version
			"X-UserID",
			"User-ID",
		}

		for _, header := range userHeaders {
			if ids := req.Headers[header]; len(ids) > 0 {
				return ids[0]
			}
		}
		return "anonymous"

	case "per_ua":
		if ua := req.Headers["User-Agent"]; len(ua) > 0 {
			return ua[0]
		}
		return "unknown"

	default:
		return limitType
	}
}
