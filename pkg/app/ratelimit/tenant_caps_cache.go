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
	"log/slog"
	"sync/atomic"
	"time"

	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/ratelimit"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/metric"
)

const (
	// DefaultTenantCapsRefresh is how often the caps of every tenant are
	// reloaded. A tier change reaches a pod within this time.
	DefaultTenantCapsRefresh = 30 * time.Second

	tenantCapsLoadTimeout = 5 * time.Second

	// DefaultPrimeTimeout bounds the load a plane waits for before it serves.
	DefaultPrimeTimeout = 2 * time.Second

	// firstLoadRetry is where the retry backoff of a cache that has never loaded
	// starts. It doubles up to the refresh interval.
	firstLoadRetry   = 2 * time.Second
	capsLoadLogEvery = 5 * time.Minute
)

// TenantCapsSource answers "what are this tenant's caps" without a round trip.
// It returns commonerrors.ErrNotFound when it has none to give.
type TenantCapsSource interface {
	FindTenantCaps(ctx context.Context, tenantID string) (*domain.TenantCaps, error)
}

// TenantCapsCache is the tenant caps of a plane that reads Postgres, kept in
// memory and reloaded on a timer.
//
// Resolving a gateway to its plan runs on every proxied request and MCP call;
// asking Postgres for the tenant's row each time would double the queries of the
// hot path. The caps change only on a restamp, so a table scan
// every refresh interval is cheap and a lookup is a map read.
//
// Until the first load succeeds, and for a tenant the last good load did not
// contain, the answer is ErrNotFound. That is not a fail-open: the caller then
// falls back to the caps stamped on the gateway, and a gateway with none is not metered.
// A failed reload (a missing relation during a rollout, Postgres being down)
// keeps the last good map.
type TenantCapsCache struct {
	lister   domain.TenantCapsLister
	interval time.Duration
	logger   *slog.Logger
	loadWarn throttle

	primeTimeout time.Duration
	retryMin     time.Duration

	// primeFailed is set when Prime tried and failed, so Run does not repeat
	// that attempt at once: it waits retryMin first.
	primeFailed atomic.Bool

	caps       atomic.Pointer[map[string]domain.TenantCaps]
	loadErrors metric.Int64Counter
}

var _ TenantCapsSource = (*TenantCapsCache)(nil)

func NewTenantCapsCache(lister domain.TenantCapsLister, interval time.Duration, logger *slog.Logger) *TenantCapsCache {
	logger = loggerOrDefault(logger)
	if interval <= 0 {
		interval = DefaultTenantCapsRefresh
	}
	c := &TenantCapsCache{
		lister: lister, interval: interval, logger: logger,
		primeTimeout: DefaultPrimeTimeout,
		retryMin:     min(firstLoadRetry, interval),
	}
	c.loadWarn.every = capsLoadLogEvery
	counter, err := otel.Meter(instrumentation).Int64Counter(
		"trustgate.ratelimit.tenant_caps.load_errors",
		metric.WithDescription("failed reloads of the tenant plan caps; the last good copy keeps being used"),
	)
	if err != nil {
		logger.Warn("failed to create tenant caps load error counter", slog.String("error", err.Error()))
	} else {
		c.loadErrors = counter
	}
	return c
}

// FindTenantCaps reads the tenant's caps from the last good load.
func (c *TenantCapsCache) FindTenantCaps(_ context.Context, tenantID string) (*domain.TenantCaps, error) {
	m := c.caps.Load()
	if m == nil {
		return nil, commonerrors.ErrNotFound
	}
	got, ok := (*m)[tenantID]
	if !ok {
		return nil, commonerrors.ErrNotFound
	}
	return &got, nil
}

// Load reloads every tenant's caps. On error the previous copy stays.
func (c *TenantCapsCache) Load(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, tenantCapsLoadTimeout)
	defer cancel()
	list, err := c.lister.ListTenantCaps(ctx)
	if err != nil {
		if c.loadErrors != nil {
			c.loadErrors.Add(ctx, 1)
		}
		if suppressed, ok := c.loadWarn.allow(time.Now()); ok {
			c.logger.Warn("rate limit: failed to load tenant caps; keeping the last copy, and the gateway stamp for tenants without one",
				slog.String("component", "ratelimit"),
				slog.Int("failures_since_last_log", suppressed+1),
				slog.Any("error", err))
		}
		return err
	}
	m := make(map[string]domain.TenantCaps, len(list))
	for _, tc := range list {
		m[tc.TenantID] = tc
	}
	c.caps.Store(&m)
	return nil
}

// Prime makes one bounded load, for a plane to call before it starts serving:
// without it the first requests are resolved from the gateway stamp, which can
// disagree with the tenant's row. A failure is not fatal: the plane serves from
// the stamp and Run keeps trying.
func (c *TenantCapsCache) Prime(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, c.primeTimeout)
	defer cancel()
	err := c.Load(ctx)
	c.primeFailed.Store(err != nil)
	return err
}

// Run keeps the copy fresh until ctx is cancelled. A cache that has never loaded
// retries with a short backoff (starting at 2 s, doubling up to the refresh
// interval) so a plane that started while Postgres was away does not run on gateway
// stamps for a whole interval after it is back. After a failed Prime the first
// retry waits retryMin instead of repeating the attempt that just failed; a
// cache that Prime already loaded waits for the first tick.
func (c *TenantCapsCache) Run(ctx context.Context) {
	backoff := c.retryMin
	waitFirst := c.primeFailed.Load()
	for c.caps.Load() == nil {
		if !waitFirst && c.Load(ctx) == nil { // logged and counted inside
			break
		}
		waitFirst = false
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		backoff = min(backoff*2, c.interval)
	}
	ticker := time.NewTicker(c.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			_ = c.Load(ctx)
		}
	}
}
