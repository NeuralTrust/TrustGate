package token_rate_limiter

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"sync"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/sirupsen/logrus"

	"github.com/NeuralTrust/TrustGate/pkg/common"
	"github.com/NeuralTrust/TrustGate/pkg/pluginiface"
	"github.com/NeuralTrust/TrustGate/pkg/types"
)

const (
	PluginName = "token_rate_limiter"
)

// Config represents the configuration for the token rate limiter plugin
type Config struct {
	TokensPerRequest  int `json:"tokens_per_request"`  // Default number of tokens consumed per request
	TokensPerMinute   int `json:"tokens_per_minute"`   // Token replenishment rate per minute
	BucketSize        int `json:"bucket_size"`         // Maximum number of tokens that can be accumulated
	RequestsPerMinute int `json:"requests_per_minute"` // Maximum requests per minute
}

// ResponseTokens represents the token usage from the response
type ResponseTokens struct {
	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`
	TotalTokens      int `json:"total_tokens"`
}

// TokenRateLimiterPlugin implements the token bucket rate limiting algorithm
type TokenRateLimiterPlugin struct {
	logger *logrus.Logger
	redis  *redis.Client
	mu     sync.Mutex
}

// NewTokenRateLimiterPlugin creates a new instance of the token rate limiter plugin
func NewTokenRateLimiterPlugin(logger *logrus.Logger, redisClient *redis.Client) pluginiface.Plugin {
	return &TokenRateLimiterPlugin{
		logger: logger,
		redis:  redisClient,
	}
}

// Name returns the name of the plugin
func (p *TokenRateLimiterPlugin) Name() string {
	return PluginName
}

func (p *TokenRateLimiterPlugin) ValidateConfig(config types.PluginConfig) error {
	return fmt.Errorf("method not implemented")
}

// Stages returns the fixed stages where this plugin must run
func (p *TokenRateLimiterPlugin) Stages() []types.Stage {
	return []types.Stage{
		types.PreRequest,
		types.PostResponse,
	}
}

// AllowedStages returns all stages where this plugin is allowed to run
func (p *TokenRateLimiterPlugin) AllowedStages() []types.Stage {
	return []types.Stage{
		types.PreRequest,
		types.PostResponse,
	}
}

// Execute implements the token bucket rate limiting algorithm
func (p *TokenRateLimiterPlugin) Execute(ctx context.Context, cfg types.PluginConfig, req *types.RequestContext, resp *types.ResponseContext) (*types.PluginResponse, error) {
	// Create a context with timeout and stage information
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	ctx = context.WithValue(ctx, common.StageKey, req.Stage)
	defer cancel()

	// Try to acquire the lock with context
	done := make(chan struct{})
	go func() {
		p.mu.Lock()
		close(done)
	}()

	select {
	case <-ctx.Done():
		return nil, fmt.Errorf("failed to acquire lock: %w", ctx.Err())
	case <-done:
		defer p.mu.Unlock()
	}

	// Parse plugin configuration
	var config Config
	configBytes, err := json.Marshal(cfg.Settings)
	if err != nil {
		p.logger.WithError(err).Error("Failed to marshal plugin settings")
		return nil, fmt.Errorf("failed to marshal plugin settings: %w", err)
	}

	if err := json.Unmarshal(configBytes, &config); err != nil {
		p.logger.WithError(err).Error("Failed to parse token rate limiter config")
		return nil, fmt.Errorf("failed to parse token rate limiter config: %w", err)
	}

	// Get API key from context
	apiKey, ok := req.Metadata["api_key"].(string)
	if !ok {
		return nil, fmt.Errorf("api_key not found or invalid type")
	}

	// Calculate token bucket key
	bucketKey := fmt.Sprintf("token_bucket:%s:%s", cfg.ID, apiKey)

	// Get current bucket state
	bucket, err := p.getBucketState(ctx, bucketKey, config)
	if err != nil {
		p.logger.WithError(err).Error("Failed to get bucket state")
		return nil, err
	}

	// Handle different stages
	switch req.Stage {
	case types.PreRequest:
		// Check if this is a streaming request
		var requestBody map[string]interface{}
		if err := json.Unmarshal(req.Body, &requestBody); err != nil {
			return nil, fmt.Errorf("failed to parse request body: %w", err)
		}

		tokensToReserve := config.TokensPerRequest
		isStreaming, ok := requestBody["stream"].(bool)
		if !ok {
			isStreaming = false // default value
		}

		// Check both tokens and requests limits
		if bucket.Tokens < tokensToReserve {
			p.logger.WithFields(logrus.Fields{
				"required_tokens":  tokensToReserve,
				"available_tokens": bucket.Tokens,
			}).Warn("Rate limit exceeded - not enough tokens")

			// Calculate time until next refill
			timeUntilRefill := time.Until(bucket.LastRefill.Add(time.Minute))
			if timeUntilRefill < 0 {
				timeUntilRefill = 0
			}

			// Set rate limit headers in response context
			resp.Headers = map[string][]string{
				"X-Ratelimit-Limit-Requests":     {strconv.Itoa(config.RequestsPerMinute)},
				"X-Ratelimit-Limit-Tokens":       {strconv.Itoa(config.BucketSize)},
				"X-Ratelimit-Remaining-Requests": {strconv.Itoa(bucket.RequestsRemaining)},
				"X-Ratelimit-Remaining-Tokens":   {strconv.Itoa(bucket.Tokens)},
				"X-Ratelimit-Reset-Requests":     {fmt.Sprintf("%ds", int(timeUntilRefill.Seconds()))},
				"X-Ratelimit-Reset-Tokens":       {fmt.Sprintf("%ds", int(timeUntilRefill.Seconds()))},
			}

			return nil, &types.PluginError{
				StatusCode: 429,
				Message:    fmt.Sprintf("Rate limit exceeded. Not enough tokens available. Required: %d, Current: %d", tokensToReserve, bucket.Tokens),
			}
		}

		if bucket.RequestsRemaining <= 0 {
			// Calculate time until next refill
			timeUntilRefill := time.Until(bucket.LastRefill.Add(time.Minute))
			if timeUntilRefill < 0 {
				timeUntilRefill = 0
			}

			// Set rate limit headers in response context
			resp.Headers = map[string][]string{
				"X-Ratelimit-Limit-Requests":     {strconv.Itoa(config.RequestsPerMinute)},
				"X-Ratelimit-Limit-Tokens":       {strconv.Itoa(config.BucketSize)},
				"X-Ratelimit-Remaining-Requests": {strconv.Itoa(bucket.RequestsRemaining)},
				"X-Ratelimit-Remaining-Tokens":   {strconv.Itoa(bucket.Tokens)},
				"X-Ratelimit-Reset-Requests":     {fmt.Sprintf("%ds", int(timeUntilRefill.Seconds()))},
				"X-Ratelimit-Reset-Tokens":       {fmt.Sprintf("%ds", int(timeUntilRefill.Seconds()))},
			}

			return nil, &types.PluginError{
				StatusCode: 429,
				Message:    "Rate limit exceeded. No requests remaining.",
			}
		}

		// For streaming requests, we need to reserve tokens and update the bucket immediately
		if isStreaming {
			bucket.Tokens -= tokensToReserve
			bucket.RequestsRemaining--

			if err := p.saveBucketState(ctx, bucketKey, bucket); err != nil {
				p.logger.WithError(err).Error("Failed to save bucket state for streaming request")
				return nil, err
			}
		}

		// Calculate time until next refill
		timeUntilRefill := time.Until(bucket.LastRefill.Add(time.Minute))
		if timeUntilRefill < 0 {
			timeUntilRefill = 0
		}

		// Store rate limit headers in metadata for streaming responses
		if isStreaming {
			req.Metadata["rate_limit_headers"] = map[string][]string{
				"X-Ratelimit-Limit-Requests":     {strconv.Itoa(config.RequestsPerMinute)},
				"X-Ratelimit-Limit-Tokens":       {strconv.Itoa(config.BucketSize)},
				"X-Ratelimit-Remaining-Requests": {strconv.Itoa(bucket.RequestsRemaining)},
				"X-Ratelimit-Remaining-Tokens":   {strconv.Itoa(bucket.Tokens)},
				"X-Ratelimit-Reset-Requests":     {fmt.Sprintf("%ds", int(timeUntilRefill.Seconds()))},
				"X-Ratelimit-Reset-Tokens":       {fmt.Sprintf("%ds", int(timeUntilRefill.Seconds()))},
			}
		}

		return &types.PluginResponse{
			Headers: map[string][]string{
				"X-Ratelimit-Limit-Requests":     {strconv.Itoa(config.RequestsPerMinute)},
				"X-Ratelimit-Limit-Tokens":       {strconv.Itoa(config.BucketSize)},
				"X-Ratelimit-Remaining-Requests": {strconv.Itoa(bucket.RequestsRemaining)},
				"X-Ratelimit-Remaining-Tokens":   {strconv.Itoa(bucket.Tokens)},
				"X-Ratelimit-Reset-Requests":     {fmt.Sprintf("%ds", int(timeUntilRefill.Seconds()))},
				"X-Ratelimit-Reset-Tokens":       {fmt.Sprintf("%ds", int(timeUntilRefill.Seconds()))},
			},
		}, nil

	case types.PostResponse:
		// For streaming requests, get token usage from metadata
		var requestBody map[string]interface{}
		if err := json.Unmarshal(req.Body, &requestBody); err != nil {
			return nil, fmt.Errorf("failed to parse request body: %w", err)
		}
		isStreaming, ok := requestBody["stream"].(bool)
		if !ok {
			isStreaming = false // default value
		}
		if isStreaming {
			if tokenUsage, ok := req.Metadata["token_usage"].(map[string]interface{}); ok {
				tokensToConsume := config.TokensPerRequest // default fallback

				if tt, ok := tokenUsage["total_tokens"].(float64); ok {
					tokensToConsume = int(tt)
				}

				// Update the bucket with actual token usage
				bucket.Tokens -= tokensToConsume
				bucket.RequestsRemaining--

				// Save updated bucket state
				if err := p.saveBucketState(ctx, bucketKey, bucket); err != nil {
					p.logger.WithError(err).Error("Failed to save bucket state after streaming")
					return nil, err
				}

				timeUntilRefill := time.Until(bucket.LastRefill.Add(time.Minute))
				if timeUntilRefill < 0 {
					timeUntilRefill = 0
				}

				p.logger.WithFields(logrus.Fields{
					"streaming":          true,
					"tokens_consumed":    tokensToConsume,
					"tokens_remaining":   bucket.Tokens,
					"requests_remaining": bucket.RequestsRemaining,
				}).Debug("Token rate limiter post-response update for streaming")

				return &types.PluginResponse{
					Headers: map[string][]string{
						"X-Ratelimit-Limit-Requests":     {strconv.Itoa(config.RequestsPerMinute)},
						"X-Ratelimit-Limit-Tokens":       {strconv.Itoa(config.BucketSize)},
						"X-Ratelimit-Remaining-Requests": {strconv.Itoa(bucket.RequestsRemaining)},
						"X-Ratelimit-Remaining-Tokens":   {strconv.Itoa(bucket.Tokens)},
						"X-Ratelimit-Reset-Requests":     {fmt.Sprintf("%ds", int(timeUntilRefill.Seconds()))},
						"X-Ratelimit-Reset-Tokens":       {fmt.Sprintf("%ds", int(timeUntilRefill.Seconds()))},
						"X-Tokens-Consumed":              {strconv.Itoa(tokensToConsume)},
					},
				}, nil
			}
		}

		var tokensToConsume int
		var responseBody map[string]interface{}
		if err := json.Unmarshal(resp.Body, &responseBody); err != nil {
			tokensToConsume = config.TokensPerRequest
		} else if usage, ok := responseBody["usage"].(map[string]interface{}); ok {
			var responseTokens ResponseTokens
			usageBytes, err := json.Marshal(usage)
			if err == nil && json.Unmarshal(usageBytes, &responseTokens) == nil {
				tokensToConsume = responseTokens.TotalTokens
			} else {
				tokensToConsume = config.TokensPerRequest
			}
		} else {
			tokensToConsume = config.TokensPerRequest
		}

		// Consume both tokens and requests
		bucket.Tokens -= tokensToConsume
		bucket.RequestsRemaining--

		// Save updated bucket state with stage information
		if err := p.saveBucketState(ctx, bucketKey, bucket); err != nil {
			p.logger.WithError(err).Error("Failed to save bucket state")
			return nil, err
		}

		// Calculate time until next refill
		timeUntilRefill := time.Until(bucket.LastRefill.Add(time.Minute))
		if timeUntilRefill < 0 {
			timeUntilRefill = 0
		}

		p.logger.WithFields(logrus.Fields{
			"bucket_key":         bucketKey,
			"tokens":             bucket.Tokens,
			"requests_remaining": bucket.RequestsRemaining,
			"last_refill":        bucket.LastRefill,
		}).Debug("Updated bucket state")

		return &types.PluginResponse{
			StatusCode: resp.StatusCode,
			Headers: map[string][]string{
				"X-Ratelimit-Limit-Requests":     {strconv.Itoa(config.RequestsPerMinute)},
				"X-Ratelimit-Limit-Tokens":       {strconv.Itoa(config.BucketSize)},
				"X-Ratelimit-Remaining-Requests": {strconv.Itoa(bucket.RequestsRemaining)},
				"X-Ratelimit-Remaining-Tokens":   {strconv.Itoa(bucket.Tokens)},
				"X-Ratelimit-Reset-Requests":     {fmt.Sprintf("%ds", int(timeUntilRefill.Seconds()))},
				"X-Ratelimit-Reset-Tokens":       {fmt.Sprintf("%ds", int(timeUntilRefill.Seconds()))},
				"X-Tokens-Consumed":              {strconv.Itoa(tokensToConsume)},
			},
		}, nil
	}

	return nil, fmt.Errorf("unsupported stage: %s", req.Stage)
}

// TokenBucket represents the state of a token bucket
type TokenBucket struct {
	Tokens            int       `json:"tokens"`
	RequestsRemaining int       `json:"requests_remaining"`
	LastRefill        time.Time `json:"last_refill"`
}

// getBucketState retrieves and updates the token bucket state
func (p *TokenRateLimiterPlugin) getBucketState(ctx context.Context, key string, config Config) (*TokenBucket, error) {
	var bucket TokenBucket

	// Try to get existing bucket
	result, err := p.redis.Get(ctx, key).Result()
	if err != nil && err != redis.Nil {
		p.logger.WithError(err).Error("Failed to get bucket from cache")
		return nil, fmt.Errorf("failed to get bucket from cache: %w", err)
	}

	// If bucket exists, unmarshal it
	if err != redis.Nil {
		if err := json.Unmarshal([]byte(result), &bucket); err != nil {
			p.logger.WithError(err).Error("Failed to unmarshal existing bucket")
			return nil, fmt.Errorf("failed to unmarshal bucket: %w", err)
		}
	} else {
		// Initialize new bucket with our configured limits
		bucket = TokenBucket{
			Tokens:            config.BucketSize,        // Use our bucket size
			RequestsRemaining: config.RequestsPerMinute, // Use our requests per minute
			LastRefill:        time.Now(),
		}
	}

	// Calculate time since last refill
	now := time.Now()
	duration := now.Sub(bucket.LastRefill)
	minutes := int(duration.Minutes())

	// Refill tokens and requests if needed
	if minutes > 0 {
		tokensToAdd := minutes * config.TokensPerMinute
		bucket.Tokens = min(bucket.Tokens+tokensToAdd, config.BucketSize)
		bucket.RequestsRemaining = config.RequestsPerMinute // Reset to our configured limit
		bucket.LastRefill = now
	}

	// Ensure we never exceed our configured limits
	bucket.Tokens = min(bucket.Tokens, config.BucketSize)
	bucket.RequestsRemaining = min(bucket.RequestsRemaining, config.RequestsPerMinute)

	return &bucket, nil
}

// saveBucketState saves the token bucket state to Redis
func (p *TokenRateLimiterPlugin) saveBucketState(ctx context.Context, key string, bucket *TokenBucket) error {
	// Marshal bucket state
	data, err := json.Marshal(bucket)
	if err != nil {
		p.logger.WithError(err).Error("Failed to marshal bucket")
		return fmt.Errorf("failed to marshal bucket: %w", err)
	}

	// Save to Redis with 24-hour TTL
	if err := p.redis.Set(ctx, key, string(data), 24*time.Hour).Err(); err != nil {
		p.logger.WithError(err).Error("Failed to save bucket to cache")
		return fmt.Errorf("failed to save bucket to cache: %w", err)
	}

	return nil
}

// min returns the minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
