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

package main

import (
	"context"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	ratelimitapp "github.com/NeuralTrust/TrustGate/pkg/app/ratelimit"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/ratelimit"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache"
	ratelimitinfra "github.com/NeuralTrust/TrustGate/pkg/infra/ratelimit"
	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type oneGatewayResolver struct {
	resolved ratelimitapp.Resolved
}

func (r oneGatewayResolver) Resolve(context.Context, ids.GatewayID) (ratelimitapp.Resolved, error) {
	return r.resolved, nil
}

func quietLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// What the process does on SIGTERM: servers stop, then the rate-limit stop
// function runs. Whatever the pod admitted since its last tick must be in Redis
// when it returns, and the sync client must be closed after, not before.
func TestStartRateLimitStopFlushesPendingUsageBeforeClosingRedis(t *testing.T) {
	mr, err := miniredis.Run()
	require.NoError(t, err)
	t.Cleanup(mr.Close)
	rc := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	syncClient := &cache.SyncClient{Client: rc}

	meter := ratelimitapp.NewMeter(
		oneGatewayResolver{resolved: ratelimitapp.Resolved{Subject: "tenant-1", Limits: domain.Limits{BurstPerMin: 1000, QuotaPerMonth: 1000}}},
		ratelimitinfra.NewStore(rc, quietLogger()),
		ratelimitapp.Options{SyncInterval: time.Hour, DisableKick: true},
		quietLogger(),
	)
	stop := startRateLimit(rateLimitParams{Meter: meter, SyncRedis: syncClient}, quietLogger())

	for i := 0; i < 5; i++ {
		require.NoError(t, meter.Check(context.Background(), ids.New[ids.GatewayKind]()))
	}
	assert.Empty(t, mr.Keys(), "nothing reaches Redis before the stop")

	stop()

	keys := mr.Keys()
	require.NotEmpty(t, keys, "the final flush ran before the client was closed")
	assert.Error(t, rc.Ping(context.Background()).Err(), "and the sync client is closed afterwards")
}

func TestStartRateLimitWithTheLimiterDisabledStartsNothing(t *testing.T) {
	stop := startRateLimit(rateLimitParams{}, quietLogger())
	stop() // must not panic or block
}

type fixedCapsLister struct{}

func (fixedCapsLister) ListTenantCaps(context.Context) ([]domain.TenantCaps, error) {
	return []domain.TenantCaps{{TenantID: "tenant-1", Tier: "standard", BurstPerMin: 300}}, nil
}

// A plane that reads Postgres loads the tenant caps for as long as the limiter
// runs, and stops doing so with it.
func TestStartRateLimitRunsTheTenantCapsCacheWithTheMeter(t *testing.T) {
	caps := ratelimitapp.NewTenantCapsCache(fixedCapsLister{}, time.Hour, quietLogger())
	meter := ratelimitapp.NewMeter(
		oneGatewayResolver{},
		ratelimitinfra.NewStore(nil, quietLogger()),
		ratelimitapp.Options{SyncInterval: time.Hour, DisableKick: true},
		quietLogger(),
	)
	stop := startRateLimit(rateLimitParams{Meter: meter, Caps: caps}, quietLogger())

	require.Eventually(t, func() bool {
		got, err := caps.FindTenantCaps(context.Background(), "tenant-1")
		return err == nil && got.BurstPerMin == 300
	}, 2*time.Second, 5*time.Millisecond, "the cache is loaded by the lifecycle, not by a request")
	stop()
}

type slowCapsLister struct{ delay time.Duration }

func (l slowCapsLister) ListTenantCaps(context.Context) ([]domain.TenantCaps, error) {
	time.Sleep(l.delay)
	return []domain.TenantCaps{{TenantID: "tenant-1", Tier: "standard", BurstPerMin: 300}}, nil
}

// The caps are loaded before startRateLimit returns, that is before the servers
// start: no request is measured against the gateway stamp while the table is
// being read for the first time.
func TestStartRateLimitLoadsTheTenantCapsBeforeReturning(t *testing.T) {
	caps := ratelimitapp.NewTenantCapsCache(slowCapsLister{delay: 100 * time.Millisecond}, time.Hour, quietLogger())
	meter := ratelimitapp.NewMeter(
		oneGatewayResolver{},
		ratelimitinfra.NewStore(nil, quietLogger()),
		ratelimitapp.Options{SyncInterval: time.Hour, DisableKick: true},
		quietLogger(),
	)
	stop := startRateLimit(rateLimitParams{Meter: meter, Caps: caps}, quietLogger())
	defer stop()

	got, err := caps.FindTenantCaps(context.Background(), "tenant-1")
	require.NoError(t, err, "loaded synchronously, not by the background loop")
	assert.Equal(t, 300, got.BurstPerMin)
}

type redisCmdCounter struct{ ping, script atomic.Int64 }

func (c *redisCmdCounter) DialHook(next redis.DialHook) redis.DialHook { return next }

func (c *redisCmdCounter) ProcessHook(next redis.ProcessHook) redis.ProcessHook {
	return func(ctx context.Context, cmd redis.Cmder) error {
		c.count(cmd.Name())
		return next(ctx, cmd)
	}
}

func (c *redisCmdCounter) ProcessPipelineHook(next redis.ProcessPipelineHook) redis.ProcessPipelineHook {
	return func(ctx context.Context, cmds []redis.Cmder) error {
		for _, cmd := range cmds {
			c.count(cmd.Name())
		}
		return next(ctx, cmds)
	}
}

func (c *redisCmdCounter) count(name string) {
	switch strings.ToLower(name) {
	case "ping":
		c.ping.Add(1)
	case "script":
		c.script.Add(1)
	}
}

// The sync connection is authenticated and the script is loaded before
// startRateLimit returns, which is before the servers listen.
func TestStartRateLimitWarmsTheSyncClientBeforeReturning(t *testing.T) {
	mr, err := miniredis.Run()
	require.NoError(t, err)
	t.Cleanup(mr.Close)
	rc := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rc.Close() })
	counts := &redisCmdCounter{}
	rc.AddHook(counts)
	meter := ratelimitapp.NewMeter(
		oneGatewayResolver{},
		ratelimitinfra.NewStore(rc, quietLogger()),
		ratelimitapp.Options{SyncInterval: time.Hour, DisableKick: true},
		quietLogger(),
	)
	stop := startRateLimit(rateLimitParams{Meter: meter, SyncRedis: &cache.SyncClient{Client: rc}}, quietLogger())
	defer stop()

	assert.GreaterOrEqual(t, counts.ping.Load(), int64(1), "warmup pings, which is the HELLO/AUTH")
	assert.GreaterOrEqual(t, counts.script.Load(), int64(1), "warmup loads the sync script")
}

// Redis that accepts and never answers must not hold boot. The warmup gives up
// and the pod still starts; a later cold read fails open.
func TestStartRateLimitWarmupGivesUpWhenRedisHangs(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, acceptErr := ln.Accept()
			if acceptErr != nil {
				return
			}
			t.Cleanup(func() { _ = conn.Close() })
		}
	}()
	rc := redis.NewClient(&redis.Options{
		Addr:                  ln.Addr().String(),
		DialTimeout:           30 * time.Second,
		ReadTimeout:           30 * time.Second,
		WriteTimeout:          30 * time.Second,
		MaxRetries:            -1,
		ContextTimeoutEnabled: true,
	})
	t.Cleanup(func() { _ = rc.Close() })
	meter := ratelimitapp.NewMeter(
		oneGatewayResolver{},
		ratelimitinfra.NewStore(rc, quietLogger()),
		ratelimitapp.Options{SyncInterval: time.Hour, DisableKick: true},
		quietLogger(),
	)

	start := time.Now()
	stop := startRateLimit(rateLimitParams{Meter: meter, SyncRedis: &cache.SyncClient{Client: rc}}, quietLogger())
	defer stop()
	assert.Less(t, time.Since(start), ratelimitapp.DefaultSyncWarmTimeout+time.Second, "warmup is bounded and a failure does not refuse to serve")
}
