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

package configsync

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/go-redis/redis/v8"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestNotifier(t *testing.T, stream string, maxLen int64) *RedisStreamNotifier {
	t.Helper()
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	notifier := NewRedisStreamNotifier(client, stream, maxLen)
	notifier.block = 50 * time.Millisecond
	return notifier
}

func TestRedisStreamNotifier_TailEmpty(t *testing.T) {
	t.Parallel()

	notifier := newTestNotifier(t, "versions", 100)
	id, err := notifier.Tail(context.Background())
	require.NoError(t, err)
	assert.Equal(t, streamStart, id)
}

func TestRedisStreamNotifier_PublishTailWatch(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	notifier := newTestNotifier(t, "versions", 100)

	firstID, err := notifier.Publish(ctx, "v1")
	require.NoError(t, err)
	assert.NotEmpty(t, firstID)

	secondID, err := notifier.Publish(ctx, "v2")
	require.NoError(t, err)

	tailID, err := notifier.Tail(ctx)
	require.NoError(t, err)
	assert.Equal(t, secondID, tailID)

	id, version, err := notifier.Watch(ctx, firstID)
	require.NoError(t, err)
	assert.Equal(t, secondID, id)
	assert.Equal(t, "v2", version)
}

func TestRedisStreamNotifier_WatchTimeoutNoEntry(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	notifier := newTestNotifier(t, "versions", 100)

	id, err := notifier.Publish(ctx, "v1")
	require.NoError(t, err)

	gotID, version, err := notifier.Watch(ctx, id)
	require.NoError(t, err)
	assert.Empty(t, gotID)
	assert.Empty(t, version)
}

func TestRedisStreamNotifier_PublishTrimsStream(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	const maxLen = 5
	notifier := newTestNotifier(t, "versions", maxLen)

	for i := 0; i < 50; i++ {
		_, err := notifier.Publish(ctx, "v")
		require.NoError(t, err)
	}

	length, err := notifier.client.XLen(ctx, "versions").Result()
	require.NoError(t, err)
	assert.LessOrEqual(t, length, int64(maxLen))
}
