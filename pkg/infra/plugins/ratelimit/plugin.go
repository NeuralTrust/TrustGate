// Copyright 2026 NeuralTrust
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package ratelimit

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"time"

	appplugins "github.com/NeuralTrust/AgentGateway/pkg/app/plugins"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/policy"
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

	dimension, subject, err := in.Scope.Subject()
	if err != nil {
		return nil, fmt.Errorf("rate_limiter: %w", err)
	}

	window, err := time.ParseDuration(cfg.Window)
	if err != nil {
		return nil, fmt.Errorf("rate_limiter: invalid window: %w", err)
	}

	now := p.now()
	redisKey := fmt.Sprintf("ratelimit:%s:%s:%s", in.Config.ID, dimension, subject)
	if group := in.Request.HeaderValue(cfg.GroupByHeader); group != "" {
		redisKey += ":hdr:" + group
	}
	count, err := p.currentCount(ctx, redisKey, now, window)
	if err != nil {
		return nil, err
	}

	headers := make(map[string][]string)
	setLimitHeaders(headers, dimension, cfg.Limit, count, now.Add(window))

	data := RateLimiterData{
		ExceededType: dimension,
		CurrentCount: count,
		Limit:        cfg.Limit,
		Window:       cfg.Window,
	}

	if count >= int64(cfg.Limit) {
		data.RateLimitExceeded = true
		data.RetryAfter = cfg.RetryAfter

		if appplugins.Blocks(in.Mode) && !appplugins.Throttles(in.Mode) {
			headers["Retry-After"] = []string{cfg.RetryAfter}
			appplugins.SetDecision(in.Event, in.Mode)
			if in.Event != nil {
				in.Event.SetExtras(data)
			}
			return nil, &appplugins.PluginError{
				StatusCode: http.StatusTooManyRequests,
				Message:    fmt.Sprintf("%s rate limit exceeded", dimension),
				Headers:    headers,
			}
		}

		if appplugins.Throttles(in.Mode) {
			if err := appplugins.Throttle(ctx, throttleDelay(window, cfg.Limit)); err != nil {
				return nil, err
			}
		}
	}

	if err := p.record(ctx, redisKey, now, window); err != nil {
		return nil, err
	}

	if in.Event != nil {
		in.Event.SetStatusCode(http.StatusOK)
		if data.RateLimitExceeded {
			appplugins.SetDecision(in.Event, in.Mode)
		}
		in.Event.SetExtras(data)
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

func setLimitHeaders(headers map[string][]string, dimension string, limit int, count int64, reset time.Time) {
	prefix := "X-RateLimit-" + dimension
	remaining := int64(limit) - count
	if remaining < 0 {
		remaining = 0
	}
	headers[prefix+"-Limit"] = []string{strconv.Itoa(limit)}
	headers[prefix+"-Remaining"] = []string{strconv.FormatInt(remaining, 10)}
	headers[prefix+"-Reset"] = []string{strconv.FormatInt(reset.Unix(), 10)}
}
