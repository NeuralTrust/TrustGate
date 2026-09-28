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
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

// iamCredentialsStub answers generateAccessToken, recording every call's path
// and Authorization header so tests can assert the caller's own ADC token was
// forwarded as the bearer that authorizes the impersonation.
type iamCredentialsStub struct {
	mu    sync.Mutex
	calls int64
	paths []string
	auths []string
}

func newIAMCredentialsStub(t *testing.T, accessToken string) (*httptest.Server, *iamCredentialsStub) {
	t.Helper()
	stub := &iamCredentialsStub{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		stub.mu.Lock()
		stub.calls++
		stub.paths = append(stub.paths, r.URL.Path)
		stub.auths = append(stub.auths, r.Header.Get("Authorization"))
		stub.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"accessToken":%q,"expireTime":"2099-01-01T00:00:00Z"}`, accessToken)
	}))
	t.Cleanup(server.Close)
	return server, stub
}

func newImpersonationCacheForTest(server *httptest.Server, adcToken string, adcErr error) *ImpersonationCache {
	adc := NewApplicationDefaultCache()
	if adcErr != nil {
		adc.find = func(context.Context, string) (oauth2.TokenSource, error) {
			return nil, adcErr
		}
	} else {
		var calls atomic.Int64
		adc = newStubADCCache(&calls, adcToken, nil)
	}
	cache := NewImpersonationCache(adc)
	cache.endpoint = server.URL
	return cache
}

func TestImpersonationCacheMintsAccessToken(t *testing.T) {
	server, stub := newIAMCredentialsStub(t, "impersonated.token")
	cache := newImpersonationCacheForTest(server, "adc.caller.token", nil)

	token, err := cache.Token(context.Background(), "target@customer.iam.gserviceaccount.com", CloudPlatformScope)

	require.NoError(t, err)
	assert.Equal(t, "impersonated.token", token)
	stub.mu.Lock()
	defer stub.mu.Unlock()
	assert.Equal(t, int64(1), stub.calls)
	assert.Equal(t, "/projects/-/serviceAccounts/target@customer.iam.gserviceaccount.com:generateAccessToken", stub.paths[0])
	assert.Equal(t, "Bearer adc.caller.token", stub.auths[0],
		"generateAccessToken must be authorized by our own ambient credentials, not the target's")
}

func TestImpersonationCacheReusesValidToken(t *testing.T) {
	server, stub := newIAMCredentialsStub(t, "impersonated.token")
	cache := newImpersonationCacheForTest(server, "adc.caller.token", nil)
	email := "target@customer.iam.gserviceaccount.com"

	for range 5 {
		token, err := cache.Token(context.Background(), email, CloudPlatformScope)
		require.NoError(t, err)
		assert.Equal(t, "impersonated.token", token)
	}

	stub.mu.Lock()
	defer stub.mu.Unlock()
	assert.Equal(t, int64(1), stub.calls,
		"a valid impersonated token must be reused instead of calling generateAccessToken on every request")
}

func TestImpersonationCacheIsolatesServiceAccounts(t *testing.T) {
	server, stub := newIAMCredentialsStub(t, "impersonated.token")
	cache := newImpersonationCacheForTest(server, "adc.caller.token", nil)

	for _, email := range []string{"one@customer.iam.gserviceaccount.com", "two@customer.iam.gserviceaccount.com"} {
		_, err := cache.Token(context.Background(), email, CloudPlatformScope)
		require.NoError(t, err)
	}

	stub.mu.Lock()
	defer stub.mu.Unlock()
	assert.Equal(t, int64(2), stub.calls, "each target service account needs its own impersonated token")
}

func TestImpersonationCacheIsolatesScopes(t *testing.T) {
	server, stub := newIAMCredentialsStub(t, "impersonated.token")
	cache := newImpersonationCacheForTest(server, "adc.caller.token", nil)
	email := "target@customer.iam.gserviceaccount.com"

	for _, scope := range []string{CloudPlatformScope, "https://www.googleapis.com/auth/other"} {
		_, err := cache.Token(context.Background(), email, scope)
		require.NoError(t, err)
	}

	stub.mu.Lock()
	defer stub.mu.Unlock()
	assert.Equal(t, int64(2), stub.calls, "each scope needs its own token even for the same target service account")
}

func TestImpersonationCacheConcurrentCallers(t *testing.T) {
	server, stub := newIAMCredentialsStub(t, "impersonated.token")
	cache := newImpersonationCacheForTest(server, "adc.caller.token", nil)
	email := "target@customer.iam.gserviceaccount.com"

	var wg sync.WaitGroup
	for range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			token, err := cache.Token(context.Background(), email, CloudPlatformScope)
			assert.NoError(t, err)
			assert.Equal(t, "impersonated.token", token)
		}()
	}
	wg.Wait()

	stub.mu.Lock()
	defer stub.mu.Unlock()
	assert.Equal(t, int64(1), stub.calls, "concurrent requests must share a single impersonated token exchange")
}

func TestImpersonationCacheEvictsPastCapacity(t *testing.T) {
	server, _ := newIAMCredentialsStub(t, "impersonated.token")
	cache := newImpersonationCacheForTest(server, "adc.caller.token", nil)

	for i := range maxCachedTokenSources + 1 {
		email := fmt.Sprintf("sa-%d@customer.iam.gserviceaccount.com", i)
		_, err := cache.Token(context.Background(), email, CloudPlatformScope)
		require.NoError(t, err)
	}

	cache.mu.RLock()
	size := len(cache.sources)
	cache.mu.RUnlock()
	assert.LessOrEqual(t, size, maxCachedTokenSources, "cache must not grow without bound")
}

func TestImpersonationCacheErrors(t *testing.T) {
	t.Run("empty email", func(t *testing.T) {
		server, _ := newIAMCredentialsStub(t, "impersonated.token")
		cache := newImpersonationCacheForTest(server, "adc.caller.token", nil)

		_, err := cache.Token(context.Background(), "  ", CloudPlatformScope)

		require.Error(t, err)
		assert.Contains(t, err.Error(), "required")
	})

	t.Run("resolving our own ambient credentials fails", func(t *testing.T) {
		server, _ := newIAMCredentialsStub(t, "impersonated.token")
		cache := newImpersonationCacheForTest(server, "", fmt.Errorf("no ambient credentials"))

		_, err := cache.Token(context.Background(), "target@customer.iam.gserviceaccount.com", CloudPlatformScope)

		require.Error(t, err)
		assert.Contains(t, err.Error(), "resolving ambient credentials to impersonate")
	})

	t.Run("iam credentials rejects the call", func(t *testing.T) {
		rejecting := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusForbidden)
			_, _ = fmt.Fprint(w, `{"error":{"message":"caller does not have permission"}}`)
		}))
		t.Cleanup(rejecting.Close)
		cache := newImpersonationCacheForTest(rejecting, "adc.caller.token", nil)

		_, err := cache.Token(context.Background(), "target@customer.iam.gserviceaccount.com", CloudPlatformScope)

		require.Error(t, err)
		assert.Contains(t, err.Error(), "unexpected status 403")
	})

	t.Run("cancelled context", func(t *testing.T) {
		server, _ := newIAMCredentialsStub(t, "impersonated.token")
		cache := newImpersonationCacheForTest(server, "adc.caller.token", nil)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		_, err := cache.Token(ctx, "target@customer.iam.gserviceaccount.com", CloudPlatformScope)

		require.Error(t, err)
		assert.Contains(t, err.Error(), "context canceled")
	})
}

func TestImpersonationCacheDefaultsToCloudPlatformScope(t *testing.T) {
	server, _ := newIAMCredentialsStub(t, "impersonated.token")
	cache := newImpersonationCacheForTest(server, "adc.caller.token", nil)

	token, err := cache.Token(context.Background(), "target@customer.iam.gserviceaccount.com", "")

	require.NoError(t, err)
	assert.Equal(t, "impersonated.token", token)
}
