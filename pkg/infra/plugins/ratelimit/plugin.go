package ratelimit

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"time"

	appplugins "github.com/NeuralTrust/AgentGateway/pkg/app/plugins"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/policy"
	infracontext "github.com/NeuralTrust/AgentGateway/pkg/infra/context"
	"github.com/go-redis/redis/v8"
	"github.com/google/uuid"
)

const PluginName = "rate_limiter"

var _ appplugins.Plugin = (*Plugin)(nil)

type Plugin struct {
	redis *redis.Client
	now   func() time.Time
	newID func() string
}

type Option func(*Plugin)

func WithClock(now func() time.Time) Option {
	return func(p *Plugin) { p.now = now }
}

func WithIDGenerator(newID func() string) Option {
	return func(p *Plugin) { p.newID = newID }
}

func New(redisClient *redis.Client, opts ...Option) *Plugin {
	p := &Plugin{
		redis: redisClient,
		now:   time.Now,
		newID: func() string { return uuid.NewString() },
	}
	for _, opt := range opts {
		opt(p)
	}
	return p
}

func (p *Plugin) Name() string { return PluginName }

func (p *Plugin) MandatoryStages() []policy.Stage {
	return []policy.Stage{policy.StagePreRequest}
}

func (p *Plugin) SupportedStages() []policy.Stage {
	return []policy.Stage{policy.StagePreRequest}
}

func (p *Plugin) SupportedModes() []policy.Mode {
	return []policy.Mode{policy.ModeEnforce, policy.ModeThrottle, policy.ModeObserve}
}

func (p *Plugin) ValidateConfig(settings map[string]any) error {
	_, err := parseConfig(settings)
	return err
}

func (p *Plugin) Execute(ctx context.Context, in appplugins.ExecInput) (*appplugins.Result, error) {
	cfg, err := parseConfig(in.Config.Settings)
	if err != nil {
		return nil, fmt.Errorf("rate_limiter: %w", err)
	}

	headers := make(map[string][]string)

	var evaluated *RateLimiterData
	var exceeded *RateLimiterData
	var throttle time.Duration

	for _, limitType := range limitOrder {
		lc, ok := cfg.Limits[limitType]
		if !ok {
			continue
		}
		key := p.extractKey(ctx, in.Request, limitType)
		if limitType == keyPerUser && key == "anonymous" {
			continue
		}

		window, err := time.ParseDuration(lc.Window)
		if err != nil {
			return nil, fmt.Errorf("rate_limiter: invalid window for %q: %w", limitType, err)
		}

		now := p.now()
		redisKey := fmt.Sprintf("ratelimit:%s:%s:%s", in.Config.ID, limitType, key)
		count, err := p.currentCount(ctx, redisKey, now, window)
		if err != nil {
			return nil, err
		}

		setLimitHeaders(headers, limitType, lc.Limit, count, now.Add(window))
		evaluated = &RateLimiterData{
			ExceededType: limitType,
			CurrentCount: count,
			Limit:        lc.Limit,
			Window:       lc.Window,
		}

		if count >= int64(lc.Limit) {
			evaluated.RateLimitExceeded = true
			evaluated.RetryAfter = cfg.Actions.RetryAfter

			if appplugins.Blocks(in.Mode) && !appplugins.Throttles(in.Mode) {
				headers["Retry-After"] = []string{cfg.Actions.RetryAfter}
				appplugins.SetDecision(in.Event, in.Mode)
				if in.Event != nil {
					in.Event.SetExtras(*evaluated)
				}
				return nil, &appplugins.PluginError{
					StatusCode: http.StatusTooManyRequests,
					Message:    fmt.Sprintf("%s rate limit exceeded", limitType),
					Headers:    headers,
				}
			}

			if exceeded == nil {
				exceeded = evaluated
				throttle = throttleDelay(window, lc.Limit)
			}
		}
		if err := p.record(ctx, redisKey, now, window); err != nil {
			return nil, err
		}
	}

	if exceeded != nil && appplugins.Throttles(in.Mode) {
		if err := appplugins.Throttle(ctx, throttle); err != nil {
			return nil, err
		}
	}

	if in.Event != nil {
		in.Event.SetStatusCode(http.StatusOK)
		if exceeded != nil {
			appplugins.SetDecision(in.Event, in.Mode)
			in.Event.SetExtras(*exceeded)
		} else if evaluated != nil {
			in.Event.SetExtras(*evaluated)
		}
	}
	return &appplugins.Result{StatusCode: http.StatusOK, Headers: headers}, nil
}

func throttleDelay(window time.Duration, limit int) time.Duration {
	if limit <= 0 || window <= 0 {
		return 0
	}
	return window / time.Duration(limit)
}

// currentCount returns the number of requests recorded inside the sliding
// window ending at now.
func (p *Plugin) currentCount(ctx context.Context, key string, now time.Time, window time.Duration) (int64, error) {
	windowStart := now.Add(-window).Unix()
	count, err := p.redis.ZCount(ctx, key,
		strconv.FormatInt(windowStart, 10),
		strconv.FormatInt(now.Unix(), 10)).Result()
	if err != nil {
		return 0, fmt.Errorf("rate_limiter: count window: %w", err)
	}
	return count, nil
}

// record trims expired entries and adds the current request to the window.
func (p *Plugin) record(ctx context.Context, key string, now time.Time, window time.Duration) error {
	windowStart := now.Add(-window).Unix()
	member := fmt.Sprintf("%d:%s", now.UnixNano(), p.newID())

	pipe := p.redis.TxPipeline()
	pipe.ZRemRangeByScore(ctx, key, "0", strconv.FormatInt(windowStart, 10))
	pipe.ZAdd(ctx, key, &redis.Z{Score: float64(now.Unix()), Member: member})
	pipe.Expire(ctx, key, window)
	if _, err := pipe.Exec(ctx); err != nil {
		return fmt.Errorf("rate_limiter: record request: %w", err)
	}
	return nil
}

// extractKey resolves the rate-limit subject for a limit type.
func (p *Plugin) extractKey(ctx context.Context, req *infracontext.RequestContext, limitType string) string {
	switch limitType {
	case keyGlobal:
		return keyGlobal
	case keyPerFingerprint:
		if fp, ok := ctx.Value(infracontext.FingerprintIDContextKey).(string); ok && fp != "" {
			return fp
		}
		return "unknown"
	case keyPerIP:
		if ip := firstHeader(req, "X-Real-IP", "X-Real-Ip", "X-Forwarded-For", "X-Original-Forwarded-For", "True-Client-IP", "CF-Connecting-IP"); ip != "" {
			return ip
		}
		if req != nil && req.IP != "" {
			return req.IP
		}
		return "unknown"
	case keyPerUser:
		if user := firstHeader(req, "X-User-ID", "X-User-Id", "X-UserID", "User-ID"); user != "" {
			return user
		}
		return "anonymous"
	default:
		return limitType
	}
}

func firstHeader(req *infracontext.RequestContext, names ...string) string {
	if req == nil {
		return ""
	}
	for _, name := range names {
		if values := req.Headers[name]; len(values) > 0 && values[0] != "" {
			return values[0]
		}
	}
	return ""
}

func setLimitHeaders(headers map[string][]string, limitType string, limit int, count int64, reset time.Time) {
	prefix := "X-RateLimit-" + limitType
	remaining := int64(limit) - count
	if remaining < 0 {
		remaining = 0
	}
	headers[prefix+"-Limit"] = []string{strconv.Itoa(limit)}
	headers[prefix+"-Remaining"] = []string{strconv.FormatInt(remaining, 10)}
	headers[prefix+"-Reset"] = []string{strconv.FormatInt(reset.Unix(), 10)}
}
