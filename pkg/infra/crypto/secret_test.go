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

package crypto

import (
	"context"
	"sync"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"
)

func TestResolveSharedSecretKey_GeneratesAndPersists(t *testing.T) {
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	ctx := context.Background()

	first, err := ResolveSharedSecretKey(ctx, rdb, nil)
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(first), minSecretLen)

	stored, err := mr.Get(SharedSecretKeyRedisKey)
	require.NoError(t, err)
	require.Equal(t, first, stored)

	second, err := ResolveSharedSecretKey(ctx, rdb, nil)
	require.NoError(t, err)
	require.Equal(t, first, second, "existing secret must be reused, not regenerated")
}

func TestResolveSharedSecretKey_ConcurrentReplicasConverge(t *testing.T) {
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	ctx := context.Background()

	const replicas = 8
	results := make([]string, replicas)
	var wg sync.WaitGroup
	wg.Add(replicas)
	for i := 0; i < replicas; i++ {
		go func(idx int) {
			defer wg.Done()
			key, err := ResolveSharedSecretKey(ctx, rdb, nil)
			require.NoError(t, err)
			results[idx] = key
		}(i)
	}
	wg.Wait()

	for i := 1; i < replicas; i++ {
		require.Equal(t, results[0], results[i], "all replicas must converge on one secret")
	}
}

func TestResolveSharedSecretKey_NilClient(t *testing.T) {
	_, err := ResolveSharedSecretKey(context.Background(), nil, nil)
	require.Error(t, err)
}

func TestResolveSharedSecretKey_UsableByCipher(t *testing.T) {
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})

	secret, err := ResolveSharedSecretKey(context.Background(), rdb, nil)
	require.NoError(t, err)

	cipher, err := NewCipher(secret)
	require.NoError(t, err)

	enc, err := cipher.Encrypt("vault-material")
	require.NoError(t, err)
	plain, err := cipher.Decrypt(enc)
	require.NoError(t, err)
	require.Equal(t, "vault-material", plain)
}
