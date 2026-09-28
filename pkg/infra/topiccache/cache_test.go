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
	"testing"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/domain/topic"
	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestCache(t *testing.T, ttl time.Duration) (*Cache, *miniredis.Miniredis) {
	t.Helper()
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	return New(client, ttl), mr
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
	key := topic.CacheKey(topic.HashText("refund"), topic.CatalogHash(nil), nil, "topic-guard@r7")
	require.NoError(t, cache.Set(ctx, key, cls))

	got, ok, err := cache.Get(ctx, key)
	require.NoError(t, err)
	require.True(t, ok)
	assert.Equal(t, cls, got)
	assert.Equal(t, 10*time.Minute, mr.TTL(keyPrefix+key))

	mr.FastForward(11 * time.Minute)
	_, ok, err = cache.Get(ctx, key)
	require.NoError(t, err)
	assert.False(t, ok, "an expired entry must read as a miss")
}

func TestCache_MissAndDefaults(t *testing.T) {
	t.Parallel()
	cache, mr := newTestCache(t, 0)

	_, ok, err := cache.Get(context.Background(), "absent")
	require.NoError(t, err)
	assert.False(t, ok)

	require.NoError(t, cache.Set(context.Background(), "k", topic.Classification{}))
	assert.Equal(t, defaultTTL, mr.TTL(keyPrefix+"k"))
}

func TestCache_CorruptEntryIsAnError(t *testing.T) {
	t.Parallel()
	cache, mr := newTestCache(t, time.Minute)
	require.NoError(t, mr.Set(keyPrefix+"bad", "{not json"))

	_, ok, err := cache.Get(context.Background(), "bad")
	require.Error(t, err)
	assert.False(t, ok)
}

func TestCache_RedisDownIsAnError(t *testing.T) {
	t.Parallel()
	cache, mr := newTestCache(t, time.Minute)
	mr.Close()

	_, _, err := cache.Get(context.Background(), "k")
	require.Error(t, err)
	require.Error(t, cache.Set(context.Background(), "k", topic.Classification{}))
}

func TestCacheKey_SeparatesWhatChangesTheResult(t *testing.T) {
	t.Parallel()
	text, catalog := topic.HashText("refund"), topic.CatalogHash([]topic.Topic{{Name: "billing", Definition: "d"}})
	low, high := 0.3, 0.7
	base := topic.CacheKey(text, catalog, nil, "v1")

	assert.Equal(t, base, topic.CacheKey(text, catalog, nil, "v1"))
	for name, other := range map[string]string{
		"text":      topic.CacheKey(topic.HashText("other"), catalog, nil, "v1"),
		"catalog":   topic.CacheKey(text, topic.CatalogHash(nil), nil, "v1"),
		"threshold": topic.CacheKey(text, catalog, &low, "v1"),
		"model":     topic.CacheKey(text, catalog, nil, "v2"),
	} {
		assert.NotEqual(t, base, other, "a change of %s must change the key", name)
	}
	assert.NotEqual(t, topic.CacheKey(text, catalog, &low, "v1"), topic.CacheKey(text, catalog, &high, "v1"))
}
