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

package labelcache

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/domain/trafficlabel"
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

	cls := trafficlabel.Classification{LabelIDs: []string{"label-1", "label-2"}}
	key := trafficlabel.CacheKey("gw-1", trafficlabel.HashText("refund"), trafficlabel.CatalogHash(nil), "reg-1", "gpt-4o-mini")
	require.NoError(t, cache.SetMany(ctx, map[string]trafficlabel.Classification{key: cls}))

	got, err := cache.GetMany(ctx, []string{key, "absent"})
	require.NoError(t, err)
	assert.Equal(t, map[string]trafficlabel.Classification{key: cls}, got, "missing keys are left out")
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
	entries := map[string]trafficlabel.Classification{
		"a": {LabelIDs: []string{"a"}},
		"b": {LabelIDs: []string{"b"}},
		"c": {LabelIDs: []string{}},
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
	key := trafficlabel.CacheKey("gw-1", trafficlabel.HashText("refund"), trafficlabel.CatalogHash(nil), "reg-1", "m")
	require.NoError(t, cache.SetMany(context.Background(), map[string]trafficlabel.Classification{key: {}}))

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

	require.NoError(t, cache.SetMany(ctx, map[string]trafficlabel.Classification{"k": {}}))
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
	require.Error(t, cache.SetMany(context.Background(), map[string]trafficlabel.Classification{"k": {}}))
}

func TestCacheKey_SeparatesWhatChangesTheResult(t *testing.T) {
	t.Parallel()
	text := trafficlabel.HashText("refund")
	catalog := trafficlabel.CatalogHash([]trafficlabel.Label{{ID: "1", Name: "billing", Instructions: "d"}})
	base := trafficlabel.CacheKey("gw-1", text, catalog, "reg-1", "m1")

	assert.Equal(t, base, trafficlabel.CacheKey("gw-1", text, catalog, "reg-1", "m1"))
	for name, other := range map[string]string{
		"gateway":  trafficlabel.CacheKey("gw-2", text, catalog, "reg-1", "m1"),
		"text":     trafficlabel.CacheKey("gw-1", trafficlabel.HashText("other"), catalog, "reg-1", "m1"),
		"catalog":  trafficlabel.CacheKey("gw-1", text, trafficlabel.CatalogHash(nil), "reg-1", "m1"),
		"registry": trafficlabel.CacheKey("gw-1", text, catalog, "reg-2", "m1"),
		"model":    trafficlabel.CacheKey("gw-1", text, catalog, "reg-1", "m2"),
	} {
		assert.NotEqual(t, base, other, "a change of %s must change the key", name)
	}
}
