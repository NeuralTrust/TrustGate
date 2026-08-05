// Copyright 2026 NeuralTrust
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package firewall

import (
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTokenProvider_NotConfigured(t *testing.T) {
	t.Parallel()
	provider := NewTokenProvider(" ")
	assert.False(t, provider.Configured())
	_, err := provider.Token()
	assert.ErrorIs(t, err, ErrNotConfigured)
}

func TestTokenProvider_CachesAndRefreshesToken(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, time.August, 5, 8, 0, 0, 0, time.UTC)
	provider := NewTokenProvider("test-secret")
	provider.now = func() time.Time { return now }
	first, err := provider.Token()
	require.NoError(t, err)
	now = now.Add(tokenTTL - tokenRefreshSkew - time.Second)
	cached, err := provider.Token()
	require.NoError(t, err)
	assert.Equal(t, first, cached)
	now = now.Add(2 * time.Second)
	refreshed, err := provider.Token()
	require.NoError(t, err)
	assert.NotEqual(t, first, refreshed)
}

func TestTokenProvider_MintsExpectedClaims(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, time.August, 5, 8, 0, 0, 0, time.UTC)
	provider := NewTokenProvider("test-secret")
	provider.now = func() time.Time { return now }
	signed, err := provider.Token()
	require.NoError(t, err)
	parsed, err := jwt.Parse(signed, func(token *jwt.Token) (any, error) {
		assert.Equal(t, jwt.SigningMethodHS256, token.Method)
		return []byte("test-secret"), nil
	}, jwt.WithTimeFunc(func() time.Time { return now }),
		jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}))
	require.NoError(t, err)
	require.True(t, parsed.Valid)
	claims, ok := parsed.Claims.(jwt.MapClaims)
	require.True(t, ok)
	assert.Equal(t, "firewall", claims["purpose"])
	assert.Equal(t, float64(now.Unix()), claims["iat"])
	assert.Equal(t, float64(now.Add(tokenTTL).Unix()), claims["exp"])
}

func TestTokenProvider_Invalidate(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, time.August, 5, 8, 0, 0, 0, time.UTC)
	provider := NewTokenProvider("test-secret")
	provider.now = func() time.Time { return now }
	first, err := provider.Token()
	require.NoError(t, err)
	now = now.Add(time.Second)
	provider.Invalidate()
	refreshed, err := provider.Token()
	require.NoError(t, err)
	assert.NotEqual(t, first, refreshed)
}

func TestTokenProvider_ConcurrentAccess(t *testing.T) {
	t.Parallel()
	provider := NewTokenProvider("test-secret")
	const workers = 64
	tokens := make(chan string, workers)
	errs := make(chan error, workers)
	var wg sync.WaitGroup
	wg.Add(workers)
	for range workers {
		go func() {
			defer wg.Done()
			token, err := provider.Token()
			tokens <- token
			errs <- err
		}()
	}
	wg.Wait()
	close(tokens)
	close(errs)
	for err := range errs {
		require.NoError(t, err)
	}
	var first string
	for token := range tokens {
		require.NotEmpty(t, token)
		if first == "" {
			first = token
		}
		assert.Equal(t, first, token)
	}
}

func TestTokenProvider_NilReceiver(t *testing.T) {
	t.Parallel()
	var provider *TokenProvider
	assert.False(t, provider.Configured())
	_, err := provider.Token()
	assert.ErrorIs(t, err, ErrNotConfigured)
}
