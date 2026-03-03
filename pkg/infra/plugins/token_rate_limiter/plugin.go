package token_rate_limiter

import (
	"bytes"
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
	PluginName       = "token_rate_limiter"
	counterKeyPrefix = "trl"
)

type WindowConfig struct {
	Unit string `mapstructure:"unit"`
	Max  int    `mapstructure:"max"`
}

type Config struct {
	IdentifierHeader string       `mapstructure:"identifier_header"`
	Window           WindowConfig `mapstructure:"window"`
}

func (c *Config) windowSeconds() int {
	switch strings.ToLower(c.Window.Unit) {
	case "second":
		return 1
	case "minute":
		return 60
	case "hour":
		return 3600
	case "day":
		return 86400
	default:
		return 60
	}
}

type TokenRateLimiterPlugin struct {
	logger          *logrus.Logger
	redis           *redis.Client
	adapterRegistry *adapter.Registry
}

func NewTokenRateLimiterPlugin(logger *logrus.Logger, redisClient *redis.Client, adapterRegistry *adapter.Registry) pluginiface.Plugin {
	return &TokenRateLimiterPlugin{
		logger:          logger,
		redis:           redisClient,
		adapterRegistry: adapterRegistry,
	}
}

func (p *TokenRateLimiterPlugin) Name() string { return PluginName }

func (p *TokenRateLimiterPlugin) RequiredPlugins() []string { return nil }

func (p *TokenRateLimiterPlugin) Stages() []pluginTypes.Stage {
	return []pluginTypes.Stage{pluginTypes.PreRequest, pluginTypes.PostResponse}
}

func (p *TokenRateLimiterPlugin) AllowedStages() []pluginTypes.Stage {
	return []pluginTypes.Stage{pluginTypes.PreRequest, pluginTypes.PostResponse}
}

func (p *TokenRateLimiterPlugin) ValidateConfig(pc pluginTypes.PluginConfig) error {
	if pc.Settings == nil {
		return fmt.Errorf("token_rate_limiter requires settings")
	}

	var cfg Config
	if err := mapstructure.Decode(pc.Settings, &cfg); err != nil {
		return fmt.Errorf("invalid settings: %w", err)
	}

	if cfg.Window.Max <= 0 {
		return fmt.Errorf("window.max must be > 0")
	}

	validUnits := map[string]bool{"second": true, "minute": true, "hour": true, "day": true}
	if !validUnits[strings.ToLower(cfg.Window.Unit)] {
		return fmt.Errorf("window.unit must be one of: second, minute, hour, day")
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

	identifier := extractIdentifier(req, config.IdentifierHeader)
	counterKey := fmt.Sprintf("%s:%s:%s", counterKeyPrefix, cfg.ID, identifier)

	switch req.Stage {
	case pluginTypes.PreRequest:
		return p.handlePreRequest(ctx, config, counterKey, req.Provider, evtCtx)
	case pluginTypes.PostResponse:
		return p.handlePostResponse(ctx, config, counterKey, req, resp, evtCtx)
	default:
		return nil, fmt.Errorf("unsupported stage: %s", req.Stage)
	}
}

func (p *TokenRateLimiterPlugin) handlePreRequest(
	ctx context.Context,
	config Config,
	counterKey string,
	provider string,
	evtCtx *metrics.EventContext,
) (*pluginTypes.PluginResponse, error) {
	consumed, err := p.redis.Get(ctx, counterKey).Int64()
	if err != nil && !errors.Is(err, redis.Nil) {
		p.logger.WithError(err).Error("failed to read token counter")
		return nil, fmt.Errorf("rate limiter read failed: %w", err)
	}

	windowSec := config.windowSeconds()
	remaining := config.Window.Max - int(consumed)
	if remaining < 0 {
		remaining = 0
	}

	ttl, _ := p.redis.TTL(ctx, counterKey).Result()
	resetSeconds := windowSec
	if ttl > 0 {
		resetSeconds = int(ttl / time.Second)
	}

	headers := rateLimitHeaders(config.Window.Max, remaining, resetSeconds)

	if consumed >= int64(config.Window.Max) {
		evtCtx.SetExtras(TokenRateLimiterData{
			Stage:           string(pluginTypes.PreRequest),
			CounterKey:      counterKey,
			Provider:        provider,
			WindowUnit:      config.Window.Unit,
			WindowMax:       config.Window.Max,
			TokensConsumed:  int(consumed),
			TokensRemaining: remaining,
			LimitExceeded:   true,
		})
		return nil, &pluginTypes.PluginError{
			StatusCode: http.StatusTooManyRequests,
			Message:    fmt.Sprintf("Token rate limit exceeded. Consumed: %d, Limit: %d", consumed, config.Window.Max),
			Headers:    headers,
		}
	}

	evtCtx.SetExtras(TokenRateLimiterData{
		Stage:           string(pluginTypes.PreRequest),
		CounterKey:      counterKey,
		Provider:        provider,
		WindowUnit:      config.Window.Unit,
		WindowMax:       config.Window.Max,
		TokensConsumed:  int(consumed),
		TokensRemaining: remaining,
		LimitExceeded:   false,
	})
	return &pluginTypes.PluginResponse{Headers: headers}, nil
}

func (p *TokenRateLimiterPlugin) handlePostResponse(
	ctx context.Context,
	config Config,
	counterKey string,
	req *types.RequestContext,
	resp *types.ResponseContext,
	evtCtx *metrics.EventContext,
) (*pluginTypes.PluginResponse, error) {
	if resp == nil || len(resp.Body) == 0 {
		return &pluginTypes.PluginResponse{}, nil
	}

	providerFormat := adapter.Format(req.Provider)
	actualTokens := 0

	if resp.Streaming {
		actualTokens = p.extractStreamUsage(resp.Body, providerFormat)
	} else {
		canonical, err := p.adapterRegistry.DecodeResponseFor(resp.Body, providerFormat)
		if err != nil {
			p.logger.WithError(err).WithField("provider", req.Provider).
				Warn("could not decode provider response for token counting, skipping")
			return &pluginTypes.PluginResponse{}, nil
		}
		if canonical.Usage != nil {
			actualTokens = canonical.Usage.TotalTokens
		}
	}

	if actualTokens == 0 {
		return &pluginTypes.PluginResponse{}, nil
	}

	windowSec := config.windowSeconds()

	newTotal, err := recordScript.Run(ctx, p.redis, []string{counterKey},
		actualTokens,
		windowSec,
	).Int64()
	if err != nil {
		p.logger.WithError(err).Error("record script failed")
		return nil, fmt.Errorf("rate limiter record failed: %w", err)
	}

	remaining := config.Window.Max - int(newTotal)
	if remaining < 0 {
		remaining = 0
	}

	ttl, _ := p.redis.TTL(ctx, counterKey).Result()
	resetSeconds := windowSec
	if ttl > 0 {
		resetSeconds = int(ttl / time.Second)
	}

	headers := rateLimitHeaders(config.Window.Max, remaining, resetSeconds)
	headers["X-Tokens-Consumed"] = []string{strconv.Itoa(actualTokens)}

	evtCtx.SetExtras(TokenRateLimiterData{
		Stage:           string(pluginTypes.PostResponse),
		CounterKey:      counterKey,
		Provider:        req.Provider,
		WindowUnit:      config.Window.Unit,
		WindowMax:       config.Window.Max,
		TokensConsumed:  int(newTotal),
		TokensActual:    actualTokens,
		TokensRemaining: remaining,
		LimitExceeded:   false,
	})
	return &pluginTypes.PluginResponse{Headers: headers}, nil
}

func extractIdentifier(req *types.RequestContext, headerName string) string {
	if headerName != "" {
		if values, ok := req.Headers[headerName]; ok && len(values) > 0 && values[0] != "" {
			return values[0]
		}
		canonical := strings.ToLower(headerName)
		for k, values := range req.Headers {
			if strings.ToLower(k) == canonical && len(values) > 0 && values[0] != "" {
				return values[0]
			}
		}
	}
	if req.IP != "" {
		return req.IP
	}
	return "_global"
}

func rateLimitHeaders(limit, remaining, resetSeconds int) map[string][]string {
	return map[string][]string{
		"X-Ratelimit-Limit-Tokens":     {strconv.Itoa(limit)},
		"X-Ratelimit-Remaining-Tokens": {strconv.Itoa(remaining)},
		"X-Ratelimit-Reset-Tokens":     {strconv.Itoa(resetSeconds) + "s"},
	}
}

func (p *TokenRateLimiterPlugin) extractStreamUsage(body []byte, providerFormat adapter.Format) int {
	lines := bytes.Split(body, []byte("\n"))
	for i := len(lines) - 1; i >= 0; i-- {
		line := bytes.TrimSpace(lines[i])
		if len(line) == 0 {
			continue
		}
		chunk, err := p.adapterRegistry.DecodeStreamChunkFor(line, providerFormat)
		if err != nil || chunk == nil {
			continue
		}
		if chunk.Usage != nil && chunk.Usage.TotalTokens > 0 {
			return chunk.Usage.TotalTokens
		}
	}
	return 0
}
