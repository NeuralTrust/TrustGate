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
	"log/slog"
	"sync"
	"time"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	"github.com/redis/go-redis/v9"
)

const (
	// leaseTTL is how long a slot survives without a heartbeat: the time a
	// crashed pod keeps a slot taken.
	leaseTTL = 2 * time.Minute
	// heartbeatEvery keeps the lease of a long stream alive; several beats fit
	// in one TTL so a missed one does not drop a live request.
	heartbeatEvery = leaseTTL / 4
	// maxLeaseLife bounds the heartbeat so a request whose release never runs
	// cannot hold a slot forever.
	maxLeaseLife = time.Hour
	// redisCallTimeout bounds every lease call's pool wait and retries; the
	// release and heartbeat outlive the request context.
	redisCallTimeout = 2 * time.Second

	parallelKeyPrefix = "ratelimit:parallel:"
)

// acquireScript purges expired leases, then adds this one unless the key is
// full. ARGV: now_ms, ttl_ms, max, member, force (1 admits over the limit, to
// keep counting in observe mode). Returns {granted, in_flight}.
var acquireScript = redis.NewScript(`
redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', ARGV[1])
local n = redis.call('ZCARD', KEYS[1])
if n >= tonumber(ARGV[3]) and ARGV[5] == '0' then
  return {0, n}
end
redis.call('ZADD', KEYS[1], tonumber(ARGV[1]) + tonumber(ARGV[2]), ARGV[4])
redis.call('PEXPIRE', KEYS[1], ARGV[2])
return {1, n + 1}
`)

// refreshScript extends a live lease only; a released or purged one stays gone.
// ARGV: now_ms, ttl_ms, member.
var refreshScript = redis.NewScript(`
if redis.call('ZSCORE', KEYS[1], ARGV[3]) then
  redis.call('ZADD', KEYS[1], tonumber(ARGV[1]) + tonumber(ARGV[2]), ARGV[3])
  redis.call('PEXPIRE', KEYS[1], ARGV[2])
  return 1
end
return 0
`)

// afterFunc schedules f once after d and returns what cancels it.
type afterFunc func(d time.Duration, f func()) (stop func())

func defaultAfterFunc(d time.Duration, f func()) func() {
	t := time.AfterFunc(d, f)
	return func() { t.Stop() }
}

func (p *Plugin) acquire(ctx context.Context, key, member string, max int, force bool) (bool, int64, error) {
	flag := "0"
	if force {
		flag = "1"
	}
	ctx, cancel := context.WithTimeout(ctx, redisCallTimeout)
	defer cancel()
	res, err := acquireScript.Run(ctx, p.redis, []string{key},
		p.now().UnixMilli(), leaseTTL.Milliseconds(), max, member, flag).Int64Slice()
	if err != nil {
		return false, 0, fmt.Errorf("rate_limiter: acquire parallel slot: %w", err)
	}
	if len(res) != 2 {
		return false, 0, fmt.Errorf("rate_limiter: acquire parallel slot: unexpected reply %v", res)
	}
	return res[0] == 1, res[1], nil
}

// lease is one held slot. release frees it exactly once, however often it is
// called, and stops the heartbeat.
type lease struct {
	p       *Plugin
	key     string
	member  string
	started time.Time

	mu     sync.Mutex
	closed bool
	stop   func()
	once   sync.Once
}

// newLease registers the release before the slot is requested: an acquire
// whose reply is lost may still have added the member. It reports false when
// the request already ended.
func (p *Plugin) newLease(done *appplugins.RequestDone, key, member string) (*lease, bool) {
	l := &lease{p: p, key: key, member: member, started: p.now()}
	return l, done.OnDone(l.release)
}

// disarm drops a lease whose slot was refused, so its release touches nothing.
func (l *lease) disarm() {
	l.once.Do(func() {
		l.mu.Lock()
		l.closed = true
		l.mu.Unlock()
	})
}

func (l *lease) schedule() {
	stop := l.p.after(heartbeatEvery, l.beat)
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		stop()
		return
	}
	l.stop = stop
}

func (l *lease) beat() {
	if l.p.now().Sub(l.started) >= maxLeaseLife {
		return
	}
	l.refresh()
	l.schedule()
}

func (l *lease) refresh() {
	ctx, cancel := context.WithTimeout(context.Background(), redisCallTimeout)
	defer cancel()
	err := refreshScript.Run(ctx, l.p.redis, []string{l.key},
		l.p.now().UnixMilli(), leaseTTL.Milliseconds(), l.member).Err()
	if err != nil {
		slog.Warn("rate_limiter: parallel lease heartbeat failed",
			slog.String("error_class", appplugins.CounterErrorClass(err)))
	}
}

func (l *lease) release() {
	l.once.Do(func() {
		l.mu.Lock()
		l.closed = true
		stop := l.stop
		l.mu.Unlock()
		if stop != nil {
			stop()
		}
		l.p.spawn(l.remove)
	})
}

func (l *lease) remove() {
	ctx, cancel := context.WithTimeout(context.Background(), redisCallTimeout)
	defer cancel()
	if err := l.p.redis.ZRem(ctx, l.key, l.member).Err(); err != nil {
		slog.Warn("rate_limiter: parallel slot release failed",
			slog.String("error_class", appplugins.CounterErrorClass(err)))
	}
}

// parallelKey names the in-flight set of a counter. tail is the limit_per and
// header suffix the request counter's key carries, so both resolve alike.
func parallelKey(configID, dimension, subject, tail string) string {
	return parallelKeyPrefix + configID + ":" + dimension + ":" + subject + tail
}
