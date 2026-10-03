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
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
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

func (p *Plugin) MutatesRequestBody() bool { return false }

func (p *Plugin) MutatesResponseBody() bool { return false }

func (p *Plugin) MutatesMetadata() bool { return false }

func (p *Plugin) MandatoryStages() []policy.Stage {
	return []policy.Stage{policy.StagePreRequest}
}

func (p *Plugin) SupportedStages() []policy.Stage {
	return []policy.Stage{policy.StagePreRequest}
}

func (p *Plugin) SupportedProtocols() []appplugins.Protocol {
	return []appplugins.Protocol{appplugins.ProtocolLLM, appplugins.ProtocolMCP}
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
		return p.counterUnavailable(ctx, in, RateLimiterData{ExceededType: dimension}, nil, "read", err)
	}

	reset := now.Add(window)
	headers := make(map[string][]string)

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
			setLimitHeaders(headers, dimension, cfg.Limit, count, reset)
			headers["Retry-After"] = []string{cfg.RetryAfter}
			appplugins.SetDecision(in.Event, in.Mode)
			if in.Event != nil {
				in.Event.SetExtras(data)
			}
			message := blockedMessage(dimension, cfg)
			return nil, &appplugins.PluginError{
				StatusCode: http.StatusTooManyRequests,
				Message:    message,
				Headers:    headers,
				Body:       rateLimitRejectBody(dimension, message, cfg),
			}
		}

		if appplugins.Throttles(in.Mode) {
			if err := appplugins.Throttle(ctx, throttleDelay(window, cfg.Limit)); err != nil {
				return nil, err
			}
		}
	}

	if err := p.record(ctx, redisKey, now, window); err != nil {
		// A read that already allowed the request must not turn into a
		// refusal just because the write-back failed: the client keeps the
		// slot the read granted it, on the same fail-open rule. When the read
		// already found the window exceeded (only reachable here in
		// throttle/observe — enforce already returned its PluginError above),
		// the client-facing headers still describe that exceeded window, not
		// an empty/unknown one.
		if data.RateLimitExceeded {
			setLimitHeaders(headers, dimension, cfg.Limit, count, reset)
		}
		return p.counterUnavailable(ctx, in, data, headers, "record", err)
	}
	// The client is told what is left once this request is counted: a client
	// reading "1 remaining" must be able to spend it without being rejected.
	setLimitHeaders(headers, dimension, cfg.Limit, count+1, reset)

	if in.Event != nil {
		in.Event.SetStatusCode(http.StatusOK)
		if data.RateLimitExceeded {
			appplugins.SetDecision(in.Event, in.Mode)
		}
		in.Event.SetExtras(data)
	}
	return &appplugins.Result{StatusCode: http.StatusOK, Headers: headers}, nil
}

// counterUnavailable turns a counter-store (Redis) failure into a pass-through
// outcome via the shared appplugins.HandleCounterFailure: unlike a blocked
// request, this always fails open, whatever in.Mode is (subject to the ctx
// exception below). data is whatever the caller already knows — a read
// failure has almost nothing yet (just the dimension), while a record
// failure after an exceeded read already carries RateLimitExceeded,
// CurrentCount, Limit, Window and RetryAfter; this only adds
// FailureReason/FailureDetail on top rather than discarding it for a bare
// failure record. headers, when non-nil, are attached to the pass-through
// result unchanged (the caller has already decided what they should say).
//
// A ctx the caller itself canceled (or let deadline out) is not a
// counter-store outage — HandleCounterFailure reports that back as a non-nil
// error, and this returns it unchanged, without touching data or headers at
// all: no failed_open, no counter_unavailable, no Warn, exactly the
// pre-RUN-1675 behavior for that case.
//
// Decision precedence: when data.RateLimitExceeded is set (only reachable in
// throttle/observe — enforce already returned its PluginError before either
// call site here runs), the throttle/observe decision wins over
// HandleCounterFailure's default failed_open: the exceeded signal is what
// those modes exist to report, and failure_reason=counter_unavailable in the
// same extras still tells an operator the write-back failed on top of it. A
// plain (non-exceeded) failure keeps failed_open.
func (p *Plugin) counterUnavailable(
	ctx context.Context,
	in appplugins.ExecInput,
	data RateLimiterData,
	headers map[string][]string,
	detail string,
	err error,
) (*appplugins.Result, error) {
	result, ferr := appplugins.HandleCounterFailure(appplugins.CounterFailure{
		Ctx:    ctx,
		Plugin: PluginName,
		Stage:  in.Stage,
		Mode:   in.Mode,
		Detail: detail,
		Err:    err,
		Event:  in.Event,
	})
	if ferr != nil {
		return nil, ferr
	}
	data.FailureReason = string(appplugins.FailureCounterUnavailable)
	data.FailureDetail = detail
	if data.RateLimitExceeded {
		appplugins.SetDecision(in.Event, in.Mode)
		result = &appplugins.Result{StatusCode: http.StatusOK, Headers: headers}
	}
	if in.Event != nil {
		in.Event.SetExtras(data)
	}
	return result, nil
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
	pipe.ZAdd(ctx, key, redis.Z{Score: float64(now.Unix()), Member: member})
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

// blockedMessage is what the person behind the client reads when a request is
// refused. Clients often show it verbatim, so it names the gateway as the one
// that blocked the request and spells out the limit it hit.
func blockedMessage(dimension string, cfg *config) string {
	return fmt.Sprintf("TrustGate blocked this request: %s rate limit exceeded (%d %s per %s). Retry in %ss.",
		dimension, cfg.Limit, pluralRequests(cfg.Limit), cfg.Window, cfg.RetryAfter)
}

func pluralRequests(n int) string {
	if n == 1 {
		return "request"
	}
	return "requests"
}

func rateLimitRejectBody(dimension, message string, cfg *config) []byte {
	payload := map[string]any{
		"error":   "rate limit exceeded",
		"message": message,
		"reason":  dimension,
		"scope":   dimension,
		"limit":   cfg.Limit,
		"window":  cfg.Window,
	}
	if secs, err := strconv.Atoi(cfg.RetryAfter); err == nil && secs > 0 {
		payload["retry_after_seconds"] = secs
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return []byte(fmt.Sprintf(`{"error":"rate limit exceeded","message":%q,"reason":%q}`, message, dimension))
	}
	return raw
}
