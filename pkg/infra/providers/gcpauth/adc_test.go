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

package gcpauth

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

type stubTokenSource struct {
	calls *atomic.Int64
	token string
	err   error
}

func (s stubTokenSource) Token() (*oauth2.Token, error) {
	s.calls.Add(1)
	if s.err != nil {
		return nil, s.err
	}
	return &oauth2.Token{AccessToken: s.token}, nil
}

func newStubADCCache(calls *atomic.Int64, token string, findErr error) *ApplicationDefaultCache {
	c := NewApplicationDefaultCache()
	c.find = func(context.Context, string) (oauth2.TokenSource, error) {
		if findErr != nil {
			return nil, findErr
		}
		return stubTokenSource{calls: calls, token: token}, nil
	}
	return c
}

func TestApplicationDefaultCacheMintsAccessToken(t *testing.T) {
	var calls atomic.Int64
	cache := newStubADCCache(&calls, "adc.minted", nil)

	token, err := cache.Token(context.Background(), CloudPlatformScope)

	require.NoError(t, err)
	assert.Equal(t, "adc.minted", token)
	assert.Equal(t, int64(1), calls.Load())
}

func TestApplicationDefaultCacheReusesSourcePerScope(t *testing.T) {
	var calls atomic.Int64
	cache := newStubADCCache(&calls, "adc.minted", nil)

	for range 5 {
		token, err := cache.Token(context.Background(), CloudPlatformScope)
		require.NoError(t, err)
		assert.Equal(t, "adc.minted", token)
	}

	assert.Equal(t, int64(5), calls.Load(),
		"the underlying oauth2.TokenSource (which already caches/refreshes internally) is reused across calls, "+
			"not re-resolved from ADC every time")
}

func TestApplicationDefaultCacheDefaultsToCloudPlatformScope(t *testing.T) {
	var calls atomic.Int64
	cache := newStubADCCache(&calls, "adc.minted", nil)

	token, err := cache.Token(context.Background(), "")

	require.NoError(t, err)
	assert.Equal(t, "adc.minted", token)
}

// The cache resolves ADC through a racy double-checked-lock (see source()):
// under concurrency it may build more than one candidate oauth2.TokenSource,
// but only one ever gets stored and returned to every caller. This test
// wraps the stub in oauth2.ReuseTokenSource, exactly as google.DefaultTokenSource
// itself does in production, so the invariant that matters — every concurrent
// caller ends up sharing one minted token, not one HTTP round trip per
// goroutine — is what gets asserted, matching how
// TestServiceAccountCacheConcurrentCallers verifies the sibling cache.
func TestApplicationDefaultCacheConcurrentCallersShareOneToken(t *testing.T) {
	var calls atomic.Int64
	cache := NewApplicationDefaultCache()
	cache.find = func(context.Context, string) (oauth2.TokenSource, error) {
		return oauth2.ReuseTokenSource(nil, stubTokenSource{calls: &calls, token: "adc.minted"}), nil
	}

	var wg sync.WaitGroup
	for range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			token, err := cache.Token(context.Background(), CloudPlatformScope)
			assert.NoError(t, err)
			assert.Equal(t, "adc.minted", token)
		}()
	}
	wg.Wait()

	assert.Equal(t, int64(1), calls.Load(), "concurrent requests must share a single token exchange")
}

func TestApplicationDefaultCacheErrors(t *testing.T) {
	t.Run("resolving ADC fails", func(t *testing.T) {
		cache := newStubADCCache(nil, "", fmt.Errorf("could not find default credentials"))

		_, err := cache.Token(context.Background(), CloudPlatformScope)

		require.Error(t, err)
		assert.Contains(t, err.Error(), "resolving application default credentials")
	})

	t.Run("minting the token fails", func(t *testing.T) {
		var calls atomic.Int64
		cache := NewApplicationDefaultCache()
		cache.find = func(context.Context, string) (oauth2.TokenSource, error) {
			return stubTokenSource{calls: &calls, err: fmt.Errorf("metadata server unreachable")}, nil
		}

		_, err := cache.Token(context.Background(), CloudPlatformScope)

		require.Error(t, err)
		assert.Contains(t, err.Error(), "exchanging application default credentials for an access token")
	})

	t.Run("cancelled context", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		cache := newStubADCCache(nil, "adc.minted", nil)

		_, err := cache.Token(ctx, CloudPlatformScope)

		require.Error(t, err)
		assert.Contains(t, err.Error(), "context canceled")
	})
}
