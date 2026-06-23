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

package semantic

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/go-redis/redis/v8"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newRedisStore(t *testing.T) (*RedisStore, *miniredis.Miniredis) {
	t.Helper()
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	return NewRedisStore(rdb, nil), mr
}

func TestRedisStoreExactRoundTrip(t *testing.T) {
	ctx := context.Background()
	store, mr := newRedisStore(t)

	const (
		rule = "registry|c:consumer-1"
		key  = "abc123"
	)

	val, hit, err := store.GetExact(ctx, rule, key)
	require.NoError(t, err)
	assert.False(t, hit)
	assert.Empty(t, val)

	require.NoError(t, store.PutExact(ctx, rule, key, "cached body", time.Minute))

	val, hit, err = store.GetExact(ctx, rule, key)
	require.NoError(t, err)
	assert.True(t, hit)
	assert.Equal(t, "cached body", val)

	val, hit, err = store.GetExact(ctx, rule, "missing")
	require.NoError(t, err)
	assert.False(t, hit)
	assert.Empty(t, val)

	require.False(t, strings.HasPrefix(exactKeyPrefix, keyPrefix))
	for _, k := range mr.Keys() {
		assert.True(t, strings.HasPrefix(k, exactKeyPrefix))
		assert.False(t, strings.HasPrefix(k, keyPrefix))
	}
}

func TestParseSearch(t *testing.T) {
	tests := []struct {
		name string
		res  []interface{}
		want []Candidate
	}{
		{
			name: "empty",
			res:  []interface{}{int64(0)},
			want: nil,
		},
		{
			name: "single hit",
			res: []interface{}{
				int64(1),
				"semantic_cache:abc:1",
				[]interface{}{"response", "cached body", "__embedding_score", "0.05"},
			},
			want: []Candidate{{Response: "cached body", Similarity: 0.95}},
		},
		{
			name: "skips entries without response",
			res: []interface{}{
				int64(1),
				"semantic_cache:abc:1",
				[]interface{}{"__embedding_score", "0.10"},
			},
			want: []Candidate{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseSearch(tt.res)
			if len(tt.want) == 0 {
				assert.Empty(t, got)
				return
			}
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestHashID_Deterministic(t *testing.T) {
	assert.Equal(t, hashID("rule-1"), hashID("rule-1"))
	assert.NotEqual(t, hashID("rule-1"), hashID("rule-2"))
	assert.Len(t, hashID("x"), 64)
}
