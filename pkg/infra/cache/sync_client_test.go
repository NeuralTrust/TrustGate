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
	"net"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildSyncOptionsIsBoundedAndDoesNotRetry(t *testing.T) {
	t.Parallel()
	o := buildSyncOptions(&redis.Options{Addr: "x:1"}, 200*time.Millisecond)

	assert.True(t, o.ContextTimeoutEnabled, "the caller's deadline must bound every call")
	assert.Equal(t, -1, o.MaxRetries, "go-redis retries 3 times by default; the next tick is the retry")
	assert.Equal(t, time.Second, o.DialTimeout, "a cold connection needs TLS and an IAM token: floor of 1s")
	assert.Equal(t, 200*time.Millisecond, o.ReadTimeout)
	assert.Equal(t, 200*time.Millisecond, o.WriteTimeout)
	assert.Equal(t, 200*time.Millisecond, o.PoolTimeout)
	assert.Equal(t, 2, o.PoolSize, "the loop runs one round trip at a time")
	assert.Equal(t, 1, o.MinIdleConns, "one connection is dialed in the background, outside the sync deadline")
	assert.LessOrEqual(t, o.MinIdleConns, o.PoolSize, "go-redis ignores a warm-up larger than the pool")
	assert.Zero(t, o.ConnMaxLifetime, "the warm connection must not be recycled")
	assert.Equal(t, time.Duration(0), o.ConnMaxIdleTime, "left to go-redis's 30 minute default, far above the tick")
}

func TestBuildSyncOptionsCapsTheTimeout(t *testing.T) {
	t.Parallel()
	for _, in := range []time.Duration{0, -time.Second, time.Minute} {
		o := buildSyncOptions(&redis.Options{}, in)
		assert.Equal(t, MaxSyncTimeout, o.ReadTimeout, "timeout %s", in)
		assert.Equal(t, MaxSyncTimeout, o.DialTimeout, "timeout %s", in)
	}
}

func TestSyncDialTimeoutHasAFloorAndACap(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name string
		in   time.Duration
		want time.Duration
	}{
		{"short timeout is lifted to the floor", 200 * time.Millisecond, time.Second},
		{"at the floor", time.Second, time.Second},
		{"above the floor follows the timeout", 3 * time.Second, 3 * time.Second},
		{"capped at the maximum", MaxSyncTimeout, MaxSyncTimeout},
	} {
		t.Run(tt.name, func(t *testing.T) {
			o := buildSyncOptions(&redis.Options{}, tt.in)
			assert.Equal(t, tt.want, o.DialTimeout)
			assert.Equal(t, min(max(tt.in, 0), MaxSyncTimeout), o.ReadTimeout, "read and write stay at the sync timeout")
			assert.Equal(t, o.ReadTimeout, o.WriteTimeout)
		})
	}
}

// Redis being down must neither fail nor block the constructor: the sync client
// never pings at boot, and the first command reports the outage instead.
func TestNewSyncClientDoesNotFailOrBlockAtBoot(t *testing.T) {
	t.Parallel()
	started := time.Now()
	c, err := NewSyncClient(Config{Host: "127.0.0.1", Port: 1}, 200*time.Millisecond)
	require.NoError(t, err)
	t.Cleanup(func() { _ = c.Close() })
	assert.Less(t, time.Since(started), time.Second)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	assert.Error(t, c.Ping(ctx).Err(), "and the first command reports the outage instead")
}

// A cold dial (TLS handshake) slower than the sync timeout must not cost the sync
// a call: the pool dials in the background with the floored dial timeout, so by
// the time the first call comes the connection is there. Without MinIdleConns the
// call itself would wait for the 900 ms dial inside its 600 ms deadline and fail.
func TestSyncClientFirstCallSucceedsAfterASlowBackgroundDial(t *testing.T) {
	t.Parallel()
	const (
		syncTimeout = 200 * time.Millisecond
		// The dial is slower than the call budget below and still inside the
		// dial timeout (1 s), so only a connection dialed ahead can answer.
		slowDial   = 900 * time.Millisecond
		callBudget = 600 * time.Millisecond
	)
	server := miniredis.RunT(t)

	dialed := make(chan struct{})
	var dialedOnce sync.Once
	options := &redis.Options{
		Addr: server.Addr(),
		Dialer: func(ctx context.Context, network, addr string) (net.Conn, error) {
			select {
			case <-time.After(slowDial): // the TLS handshake of a far away Redis
			case <-ctx.Done():
				return nil, ctx.Err()
			}
			conn, err := (&net.Dialer{}).DialContext(ctx, network, addr)
			dialedOnce.Do(func() { close(dialed) })
			return conn, err
		},
	}
	c := &SyncClient{Client: redis.NewClient(buildSyncOptions(options, syncTimeout))}
	t.Cleanup(func() { _ = c.Close() })

	select { // the first tick comes after the warm-up dial
	case <-dialed:
	case <-time.After(5 * time.Second):
		t.Fatal("the background dial never finished")
	}
	// IdleConns is no use here: the pool counts the idle connection it is about
	// to dial before the dial finishes. TotalConns is len(conns), which only grows
	// when the dialed connection is added to the pool, so the call finds it.
	require.Eventually(t, func() bool { return c.PoolStats().TotalConns >= 1 },
		2*time.Second, time.Millisecond, "the dialed connection lands in the pool")

	ctx, cancel := context.WithTimeout(context.Background(), callBudget)
	defer cancel()
	require.NoError(t, c.Ping(ctx).Err(), "the connection was dialed outside the call")
}
