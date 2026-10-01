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

package cache

import (
	"context"
	"fmt"
	"time"

	ratelimitdomain "github.com/NeuralTrust/TrustGate/pkg/domain/ratelimit"
	"github.com/redis/go-redis/v9"
)

// MaxSyncTimeout caps the timeout a sync client is built with, whatever is
// configured: a sync that may wait longer than this is not a bounded background
// task any more. It is the same bound the configuration is validated against.
const MaxSyncTimeout = ratelimitdomain.MaxSyncTimeout

// minDialTimeout is the floor of the dial timeout. The sync timeout bounds a
// round trip on a warm connection and is deliberately short (200 ms by default),
// but a cold connection pays for more: the TCP connect and the TLS handshake.
// The dial timeout must not be tighter than the sync timeout by construction, so
// it has a floor. go-redis applies it to every dial it makes on its own context
// (see syncMinIdleConns), not to the deadline of the sync call.
const minDialTimeout = time.Second

// SyncClient is the Redis client of the plan-counter sync loop. It is a distinct
// type from the shared client so the two cannot be mixed up in the container,
// and so a test can count the commands each one receives.
type SyncClient struct {
	*redis.Client
}

// NewSyncClient builds a client for the background plan-counter sync. It differs
// from the shared one on purpose: the caller's context deadline bounds every call
// (ContextTimeoutEnabled), every timeout is the sync timeout (at most
// MaxSyncTimeout) instead of go-redis's 3 to 5 seconds, a failed call is not
// retried because the next tick is the retry, and the pool is small because the
// loop runs one round trip at a time. Only the dial timeout is longer than the
// sync timeout (see syncDialTimeout), and one connection is kept warm in the
// background (see syncMinIdleConns). It does not ping at boot: that warm-up runs
// in a goroutine, so Redis being down neither blocks nor stops the process, since
// the limiter fails open. The failure is not silent: go-redis logs "failed to
// dial after N attempts" through its internal logger (5 attempts, 100 ms
// backoff, per dial), and then probes at most about once a second instead of
// hammering Redis.
func NewSyncClient(config Config, timeout time.Duration) (*SyncClient, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	provider, err := newCredentialsProvider(ctx, &config, defaultRedisAuthDependencies())
	if err != nil {
		return nil, fmt.Errorf("configure redis authentication: %w", err)
	}
	options := buildSyncOptions(buildRedisOptions(config, provider), timeout)
	return &SyncClient{Client: redis.NewClient(options)}, nil
}

func buildSyncOptions(options *redis.Options, timeout time.Duration) *redis.Options {
	if timeout <= 0 || timeout > MaxSyncTimeout {
		timeout = MaxSyncTimeout
	}
	options.ContextTimeoutEnabled = true
	options.DialTimeout = syncDialTimeout(timeout)
	options.ReadTimeout = timeout
	options.WriteTimeout = timeout
	options.MaxRetries = -1
	options.PoolSize = 2
	options.MinIdleConns = syncMinIdleConns
	options.PoolTimeout = timeout
	return options
}

// syncMinIdleConns is the number of connections the pool dials ahead of any
// call. go-redis dials them in a goroutine on context.Background() and bounds each
// attempt by Options.DialTimeout only (pool.addIdleConn), at construction and
// again whenever a connection is removed or found dead, so the TCP connect and
// the TLS handshake of a cold connection happen outside the request-bounded sync
// call and get the floored dial timeout instead of the sync timeout. Without it,
// the first call after boot (or after a connection died) has to wait for that
// dial inside its own deadline and fails it; the dial does finish in the
// background, but a whole tick is lost and the plan counters stay local. What
// still runs inside the call is the handshake of a connection that was already
// dialed: fetching the IAM token and HELLO/AUTH. The AWS credentials cache keeps retrieving after the
// call's context is cancelled, so a slow first retrieval is cached for the next
// tick. ConnMaxIdleTime (30 minutes by default) is left alone: a tick uses the
// connection far more often than that, and an idle one that is reaped is
// replaced in the background by the same mechanism. The pool size stays at 2, of
// which this takes one.
const syncMinIdleConns = 1

// syncDialTimeout is the dial timeout for a (already clamped) sync timeout: at
// least minDialTimeout, because a cold connection needs the TCP connect and the
// TLS handshake that a warm round trip does not, and never more than
// MaxSyncTimeout. The pool's own dials are not bound by the context of the sync
// call (a call that gives up leaves its dial running and the connection lands in
// the pool), so this value is the real budget of a dial.
func syncDialTimeout(timeout time.Duration) time.Duration {
	return min(max(timeout, minDialTimeout), MaxSyncTimeout)
}
