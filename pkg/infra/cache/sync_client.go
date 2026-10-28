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
	redis.UniversalClient
}

// NewSyncClient builds a client for the background plan-counter sync and for the
// one cold read. syncTimeout is the background round trip. coldReadTimeout is
// the longest a single command may run: read, write and pool wait use it,
// because ContextTimeoutEnabled keeps the shorter of that and the call's own
// deadline, and a cold read's deadline is longer than a sync round. A failed
// call is not retried because the next tick is the retry, and the pool is small
// because the loop runs one round trip at a time. Only the dial timeout is
// longer than the sync timeout (see syncDialTimeout), and one connection is
// kept warm in the background (see syncMinIdleConns). The constructor does not
// ping: startup warms the store on its own budget, so Redis being down neither
// blocks nor stops the process. The limiter fails open. A dial that fails is
// not silent: go-redis logs "failed to dial after N attempts" through its
// internal logger (5 attempts, 100 ms backoff, per dial), and then probes at
// most about once a second instead of hammering Redis.
//
// On a cluster the constructor starts loading the slot map in the background
// and returns without waiting: node clients, and so the connections
// syncMinIdleConns keeps warm, exist only once the slots are known.
func NewSyncClient(config Config, syncTimeout, coldReadTimeout time.Duration) (*SyncClient, error) {
	return newSyncClient(config, syncTimeout, coldReadTimeout, defaultRedisAuthDependencies())
}

func newSyncClient(config Config, syncTimeout, coldReadTimeout time.Duration, deps redisAuthDependencies) (*SyncClient, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	provider, err := newCredentialsProvider(ctx, &config, deps)
	if err != nil {
		return nil, fmt.Errorf("configure redis authentication: %w", err)
	}
	options, err := buildRedisOptions(config, provider)
	if err != nil {
		return nil, fmt.Errorf("configure redis TLS: %w", err)
	}
	client := newUniversalClient(buildSyncOptions(options, syncTimeout, coldReadTimeout), config.Cluster)
	if cluster, ok := client.(*redis.ClusterClient); ok {
		cluster.ReloadState(ctx)
	}
	return &SyncClient{UniversalClient: client}, nil
}

func buildSyncOptions(options *redis.Options, syncTimeout, coldReadTimeout time.Duration) *redis.Options {
	if syncTimeout <= 0 || syncTimeout > MaxSyncTimeout {
		syncTimeout = MaxSyncTimeout
	}
	budget := coldReadTimeout
	if budget <= 0 {
		budget = syncTimeout
	}
	if budget > MaxSyncTimeout {
		budget = MaxSyncTimeout
	}
	if budget < syncTimeout {
		budget = syncTimeout
	}
	options.ContextTimeoutEnabled = true
	options.DialTimeout = syncDialTimeout(syncTimeout)
	options.ReadTimeout = budget
	options.WriteTimeout = budget
	options.MaxRetries = -1
	options.PoolSize = 2
	options.MinIdleConns = syncMinIdleConns
	options.PoolTimeout = budget
	// Not go-redis's 30 minute default. See syncConnMaxIdleTime.
	options.ConnMaxIdleTime = syncConnMaxIdleTime
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
// tick. The pool size stays at 2, of which this takes one.
const syncMinIdleConns = 1

// syncConnMaxIdleTime is how long a pooled sync connection may sit unused.
// go-redis defaults this to 30 minutes. That is too long here: once the last
// slot is evicted the sync loop returns before it calls Redis, so nothing
// touches the socket. The default dialer already probes with a 30 second
// keepalive, which keeps a load balancer or NAT from idle-dropping the flow.
// The EOF on the next command is the server closing it. ElastiCache Serverless
// does that. A TLS session is not a syscall.Conn, so the pool's peek never
// notices, and the command is sent on the dead socket. Four minutes is under
// the 30 minute default that still hands a socket out after about 29 minutes
// idle. The cold read then discards the idle sockets and dials inside its own
// budget. A tenant that is still tracked is synced every second, so its
// connection never meets this.
const syncConnMaxIdleTime = 4 * time.Minute

// syncDialTimeout is the dial timeout for a (already clamped) sync timeout: at
// least minDialTimeout, because a cold connection needs the TCP connect and the
// TLS handshake that a warm round trip does not, and never more than
// MaxSyncTimeout. The pool's own dials are not bound by the context of the sync
// call (a call that gives up leaves its dial running and the connection lands in
// the pool), so this value is the real budget of a dial.
func syncDialTimeout(timeout time.Duration) time.Duration {
	return min(max(timeout, minDialTimeout), MaxSyncTimeout)
}
