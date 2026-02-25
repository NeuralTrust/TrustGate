package token_rate_limiter

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/infra/metrics"
	"github.com/NeuralTrust/TrustGate/pkg/infra/pluginiface"
	pluginTypes "github.com/NeuralTrust/TrustGate/pkg/infra/plugins/types"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
	"github.com/NeuralTrust/TrustGate/pkg/types"
	"github.com/go-redis/redis/v8"
	"github.com/mitchellh/mapstructure"
	"github.com/sirupsen/logrus"
)

const (
	PluginName     = "token_rate_limiter"
	defaultWindow  = 60
	bucketKeyPrefix = "trl"
)

type Config struct {
	TokensPerRequest int `mapstructure:"tokens_per_request"`
	TokensPerMinute  int `mapstructure:"tokens_per_minute"`
	BucketSize       int `mapstructure:"bucket_size"`
	WindowSeconds    int `mapstructure:"window_seconds"`
}

type TokenRateLimiterPlugin struct {
	logger *logrus.Logger
	redis  *redis.Client
}

func NewTokenRateLimiterPlugin(logger *logrus.Logger, redisClient *redis.Client) pluginiface.Plugin {
	return &TokenRateLimiterPlugin{
		logger: logger,
		redis:  redisClient,
	}
}

func (p *TokenRateLimiterPlugin) Name() string { return PluginName }

func (p *TokenRateLimiterPlugin) RequiredPlugins() []string { return nil }

func (p *TokenRateLimiterPlugin) Stages() []pluginTypes.Stage {
	return []pluginTypes.Stage{pluginTypes.PreRequest, pluginTypes.PreResponse}
}

func (p *TokenRateLimiterPlugin) AllowedStages() []pluginTypes.Stage {
	return []pluginTypes.Stage{pluginTypes.PreRequest, pluginTypes.PreResponse}
}

func (p *TokenRateLimiterPlugin) ValidateConfig(pc pluginTypes.PluginConfig) error {
	if pc.Settings == nil {
		return fmt.Errorf("token_rate_limiter requires settings")
	}

	var cfg Config
	if err := mapstructure.Decode(pc.Settings, &cfg); err != nil {
		return fmt.Errorf("invalid settings: %w", err)
	}

	if cfg.TokensPerRequest <= 0 {
		return fmt.Errorf("tokens_per_request must be > 0")
	}
	if cfg.BucketSize <= 0 {
		return fmt.Errorf("bucket_size must be > 0")
	}
	if cfg.BucketSize < cfg.TokensPerRequest {
		return fmt.Errorf("bucket_size must be >= tokens_per_request")
	}
	if cfg.TokensPerMinute < 0 {
		return fmt.Errorf("tokens_per_minute must be >= 0")
	}
	if cfg.WindowSeconds < 0 {
		return fmt.Errorf("window_seconds must be >= 0")
	}
	return nil
}

func (p *TokenRateLimiterPlugin) Execute(
	ctx context.Context,
	cfg pluginTypes.PluginConfig,
	req *types.RequestContext,
	resp *types.ResponseContext,
	evtCtx *metrics.EventContext,
) (*pluginTypes.PluginResponse, error) {
	if req.Provider == "" {
		return &pluginTypes.PluginResponse{StatusCode: http.StatusOK}, nil
	}

	var config Config
	if err := mapstructure.Decode(cfg.Settings, &config); err != nil {
		return nil, fmt.Errorf("failed to decode config: %w", err)
	}
	if config.WindowSeconds <= 0 {
		config.WindowSeconds = defaultWindow
	}

	identifier := extractIdentifier(req)

	bucketKey := fmt.Sprintf("%s:%s:%s", bucketKeyPrefix, cfg.ID, identifier)

	switch req.Stage {
	case pluginTypes.PreRequest:
		return p.handlePreRequest(ctx, config, bucketKey, req.Provider, evtCtx)
	case pluginTypes.PreResponse:
		return p.handlePreResponse(ctx, config, bucketKey, req, resp, evtCtx)
	default:
		return nil, fmt.Errorf("unsupported stage: %s", req.Stage)
	}
}

func (p *TokenRateLimiterPlugin) handlePreRequest(
	ctx context.Context,
	config Config,
	bucketKey string,
	provider string,
	evtCtx *metrics.EventContext,
) (*pluginTypes.PluginResponse, error) {
	nowMs := time.Now().UnixMilli()
	windowMs := int64(config.WindowSeconds) * 1000

	result, err := consumeScript.Run(ctx, p.redis, []string{bucketKey},
		config.BucketSize,
		config.TokensPerMinute,
		windowMs,
		config.TokensPerRequest,
		nowMs,
	).Int64Slice()
	if err != nil {
		p.logger.WithError(err).Error("consume script failed")
		return nil, fmt.Errorf("rate limiter consume failed: %w", err)
	}

	allowed := result[0] == 1
	remaining := int(result[1])

	headers := rateLimitHeaders(config.BucketSize, remaining, config.WindowSeconds)

	if !allowed {
		evtCtx.SetError(errors.New("token rate limit exceeded"))
		evtCtx.SetExtras(TokenRateLimiterData{
			Stage:           string(pluginTypes.PreRequest),
			BucketKey:       bucketKey,
			Provider:        provider,
			BucketSize:      config.BucketSize,
			TokensPerMinute: config.TokensPerMinute,
			TokensReserved:  config.TokensPerRequest,
			TokensRemaining: remaining,
			TokensConsumed:  0,
			LimitExceeded:   true,
		})
		return nil, &pluginTypes.PluginError{
			StatusCode: http.StatusTooManyRequests,
			Message:    fmt.Sprintf("Rate limit exceeded. Required: %d, Available: %d", config.TokensPerRequest, remaining),
			Headers:    headers,
		}
	}

	evtCtx.SetExtras(TokenRateLimiterData{
		Stage:           string(pluginTypes.PreRequest),
		BucketKey:       bucketKey,
		Provider:        provider,
		BucketSize:      config.BucketSize,
		TokensPerMinute: config.TokensPerMinute,
		TokensReserved:  config.TokensPerRequest,
		TokensRemaining: remaining,
		TokensConsumed:  config.TokensPerRequest,
		LimitExceeded:   false,
	})
	return &pluginTypes.PluginResponse{Headers: headers}, nil
}

func (p *TokenRateLimiterPlugin) handlePreResponse(
	ctx context.Context,
	config Config,
	bucketKey string,
	req *types.RequestContext,
	resp *types.ResponseContext,
	evtCtx *metrics.EventContext,
) (*pluginTypes.PluginResponse, error) {
	if resp == nil || len(resp.Body) == 0 {
		return &pluginTypes.PluginResponse{}, nil
	}

	providerFormat := adapter.Format(req.Provider)
	canonical, err := adapter.DecodeResponseFor(resp.Body, providerFormat)
	if err != nil {
		p.logger.WithError(err).WithField("provider", req.Provider).
			Warn("could not decode provider response for token counting, skipping adjustment")
		return &pluginTypes.PluginResponse{}, nil
	}

	actualTokens := 0
	if canonical.Usage != nil {
		actualTokens = canonical.Usage.TotalTokens
	}

	if actualTokens == 0 {
		return &pluginTypes.PluginResponse{}, nil
	}

	delta := actualTokens - config.TokensPerRequest
	remaining := 0

	if delta != 0 {
		res, err := adjustScript.Run(ctx, p.redis, []string{bucketKey},
			delta,
			config.BucketSize,
		).Int64Slice()
		if err != nil {
			p.logger.WithError(err).Error("adjust script failed")
			return nil, fmt.Errorf("rate limiter adjust failed: %w", err)
		}
		remaining = int(res[0])
	}

	headers := rateLimitHeaders(config.BucketSize, remaining, config.WindowSeconds)
	headers["X-Tokens-Consumed"] = []string{strconv.Itoa(actualTokens)}

	evtCtx.SetExtras(TokenRateLimiterData{
		Stage:           string(pluginTypes.PreResponse),
		BucketKey:       bucketKey,
		Provider:        req.Provider,
		BucketSize:      config.BucketSize,
		TokensPerMinute: config.TokensPerMinute,
		TokensReserved:  config.TokensPerRequest,
		TokensActual:    actualTokens,
		Delta:           delta,
		TokensRemaining: remaining,
		TokensConsumed:  actualTokens,
		LimitExceeded:   false,
	})
	return &pluginTypes.PluginResponse{Headers: headers}, nil
}

func extractIdentifier(req *types.RequestContext) string {
	if values, ok := req.Headers["Authorization"]; ok && len(values) > 0 {
		v := values[0]
		if strings.HasPrefix(v, "Bearer ") {
			return v[7:]
		}
		return v
	}
	if req.IP != "" {
		return req.IP
	}
	return "_global"
}

func rateLimitHeaders(bucketSize, remaining, windowSeconds int) map[string][]string {
	return map[string][]string{
		"X-Ratelimit-Limit-Tokens":     {strconv.Itoa(bucketSize)},
		"X-Ratelimit-Remaining-Tokens": {strconv.Itoa(remaining)},
		"X-Ratelimit-Reset-Tokens":     {strconv.Itoa(windowSeconds) + "s"},
	}
}
