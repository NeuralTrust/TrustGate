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

package topiccache

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/domain/topic"
	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var testSecret = []byte("0123456789abcdef0123456789abcdef")

func newTestCache(t *testing.T, ttl time.Duration) (*Cache, *miniredis.Miniredis) {
	t.Helper()
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	return New(client, ttl, testSecret), mr
}

func TestCache_RoundTripAndExpiry(t *testing.T) {
	t.Parallel()
	cache, mr := newTestCache(t, 10*time.Minute)
	ctx := context.Background()

	cls := topic.Classification{
		Scores:       []topic.Score{{Topic: "billing", Probability: 0.9, Matched: true}},
		Matched:      []string{"billing"},
		Windows:      1,
		ModelVersion: "topic-guard@r7",
	}
	key := topic.CacheKey("gw-1", topic.HashText("refund"), topic.CatalogHash(nil), nil, "topic-guard@r7")
	require.NoError(t, cache.SetMany(ctx, map[string]topic.Classification{key: cls}))

	got, err := cache.GetMany(ctx, []string{key, "absent"})
	require.NoError(t, err)
	assert.Equal(t, map[string]topic.Classification{key: cls}, got, "missing keys are left out")
	assert.Equal(t, 10*time.Minute, mr.TTL(cache.redisKey(key)))

	mr.FastForward(11 * time.Minute)
	got, err = cache.GetMany(ctx, []string{key})
	require.NoError(t, err)
	assert.Empty(t, got, "an expired entry must read as a miss")
}

func TestCache_BatchesInOneRoundTrip(t *testing.T) {
	t.Parallel()
	cache, mr := newTestCache(t, time.Minute)
	ctx := context.Background()
	entries := map[string]topic.Classification{
		"a": {ModelVersion: "a"},
		"b": {ModelVersion: "b"},
		"c": {ModelVersion: "c"},
	}
	require.NoError(t, cache.SetMany(ctx, entries))
	got, err := cache.GetMany(ctx, []string{"a", "b", "c"})
	require.NoError(t, err)
	assert.Equal(t, entries, got)
	assert.Len(t, mr.Keys(), 3)
}

func TestCache_KeysAreSigned(t *testing.T) {
	t.Parallel()
	cache, mr := newTestCache(t, time.Minute)
	key := topic.CacheKey("gw-1", topic.HashText("refund"), topic.CatalogHash(nil), nil, "v1")
	require.NoError(t, cache.SetMany(context.Background(), map[string]topic.Classification{key: {}}))

	stored := mr.Keys()
	require.Len(t, stored, 1)
	assert.True(t, strings.HasPrefix(stored[0], keyPrefix))
	assert.NotContains(t, stored[0], key, "Redis must not see the unsigned key, which is derived from the prompt")

	other := New(cache.redis, time.Minute, []byte("another-secret-another-secret-00"))
	got, err := other.GetMany(context.Background(), []string{key})
	require.NoError(t, err)
	assert.Empty(t, got, "another secret reads nothing, so rotating it empties the cache")
}

func TestCache_EmptyCallsAndDefaults(t *testing.T) {
	t.Parallel()
	cache, mr := newTestCache(t, 0)
	ctx := context.Background()

	got, err := cache.GetMany(ctx, nil)
	require.NoError(t, err)
	assert.Empty(t, got)
	require.NoError(t, cache.SetMany(ctx, nil))

	require.NoError(t, cache.SetMany(ctx, map[string]topic.Classification{"k": {}}))
	assert.Equal(t, defaultTTL, mr.TTL(cache.redisKey("k")))
}

func TestCache_CorruptEntryIsAMiss(t *testing.T) {
	t.Parallel()
	cache, mr := newTestCache(t, time.Minute)
	require.NoError(t, mr.Set(cache.redisKey("bad"), "{not json"))

	got, err := cache.GetMany(context.Background(), []string{"bad"})
	require.NoError(t, err)
	assert.Empty(t, got)
}

func TestCache_RedisDownIsAnError(t *testing.T) {
	t.Parallel()
	cache, mr := newTestCache(t, time.Minute)
	mr.Close()

	_, err := cache.GetMany(context.Background(), []string{"k"})
	require.Error(t, err)
	require.Error(t, cache.SetMany(context.Background(), map[string]topic.Classification{"k": {}}))
}

func TestCacheKey_SeparatesWhatChangesTheResult(t *testing.T) {
	t.Parallel()
	text, catalog := topic.HashText("refund"), topic.CatalogHash([]topic.Topic{{Name: "billing", Definition: "d"}})
	low, high := 0.3, 0.7
	base := topic.CacheKey("gw-1", text, catalog, nil, "v1")

	assert.Equal(t, base, topic.CacheKey("gw-1", text, catalog, nil, "v1"))
	for name, other := range map[string]string{
		"gateway":   topic.CacheKey("gw-2", text, catalog, nil, "v1"),
		"text":      topic.CacheKey("gw-1", topic.HashText("other"), catalog, nil, "v1"),
		"catalog":   topic.CacheKey("gw-1", text, topic.CatalogHash(nil), nil, "v1"),
		"threshold": topic.CacheKey("gw-1", text, catalog, &low, "v1"),
		"model":     topic.CacheKey("gw-1", text, catalog, nil, "v2"),
	} {
		assert.NotEqual(t, base, other, "a change of %s must change the key", name)
	}
	assert.NotEqual(t, topic.CacheKey("gw-1", text, catalog, &low, "v1"), topic.CacheKey("gw-1", text, catalog, &high, "v1"))
}
