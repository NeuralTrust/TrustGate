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

package watsonx

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/NeuralTrust/TrustGate/pkg/domain/registry"
)

type fakeIAM struct {
	srv      *httptest.Server
	calls    atomic.Int32
	status   atomic.Int32
	lifetime int64
	lastKey  atomic.Value
}

func newFakeIAM(t *testing.T) *fakeIAM {
	t.Helper()
	f := &fakeIAM{lifetime: 3600}
	f.status.Store(http.StatusOK)
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := f.calls.Add(1)
		if err := r.ParseForm(); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		f.lastKey.Store(r.PostForm.Get("apikey"))
		if r.PostForm.Get("grant_type") != iamAPIKeyGrant || r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		status := int(f.status.Load())
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		if status != http.StatusOK {
			_, _ = fmt.Fprint(w, `{"errorCode":"BXNIM0415E","errorMessage":"Provided API key could not be found."}`)
			return
		}
		_, _ = fmt.Fprintf(w, `{"access_token":"token-%d","refresh_token":"not-used","token_type":"Bearer","expires_in":%d,"expiration":%d}`,
			n, f.lifetime, time.Now().Unix()+f.lifetime)
	}))
	t.Cleanup(f.srv.Close)
	return f
}

type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

func newTestCache(iam *fakeIAM) (*tokenCache, *fakeClock) {
	clock := &fakeClock{now: time.Now()}
	cache := newTokenCache(iam.srv.URL)
	cache.now = clock.Now
	return cache, clock
}

func TestTokenCache_ReusesTokenUntilRefreshPoint(t *testing.T) {
	iam := newFakeIAM(t)
	cache, clock := newTestCache(iam)

	first, err := cache.token(context.Background(), "ibm-key")
	require.NoError(t, err)
	assert.Equal(t, "token-1", first)
	assert.Equal(t, "ibm-key", iam.lastKey.Load())

	clock.Advance(47 * time.Minute)
	again, err := cache.token(context.Background(), "ibm-key")
	require.NoError(t, err)
	assert.Equal(t, first, again)
	assert.EqualValues(t, 1, iam.calls.Load())

	clock.Advance(2 * time.Minute)
	refreshed, err := cache.token(context.Background(), "ibm-key")
	require.NoError(t, err)
	assert.Equal(t, "token-2", refreshed, "a token past 80%% of its lifetime is refreshed")
	assert.EqualValues(t, 2, iam.calls.Load())
}

func TestTokenCache_KeysDoNotShareTokens(t *testing.T) {
	iam := newFakeIAM(t)
	cache, _ := newTestCache(iam)

	a, err := cache.token(context.Background(), "key-a")
	require.NoError(t, err)
	b, err := cache.token(context.Background(), "key-b")
	require.NoError(t, err)
	assert.NotEqual(t, a, b)
	assert.EqualValues(t, 2, iam.calls.Load())
}

func TestTokenCache_ConcurrentCallersShareOneExchange(t *testing.T) {
	iam := newFakeIAM(t)
	cache, _ := newTestCache(iam)

	var wg sync.WaitGroup
	tokens := make([]string, 20)
	for i := range tokens {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			tok, err := cache.token(context.Background(), "ibm-key")
			assert.NoError(t, err)
			tokens[i] = tok
		}(i)
	}
	wg.Wait()
	for _, tok := range tokens {
		assert.Equal(t, tokens[0], tok)
	}
	assert.LessOrEqual(t, iam.calls.Load(), int32(2))
}

func TestTokenCache_KeepsValidTokenWhenRefreshFailsTransiently(t *testing.T) {
	iam := newFakeIAM(t)
	cache, clock := newTestCache(iam)

	first, err := cache.token(context.Background(), "ibm-key")
	require.NoError(t, err)

	iam.status.Store(http.StatusServiceUnavailable)
	clock.Advance(50 * time.Minute)
	tok, err := cache.token(context.Background(), "ibm-key")
	require.NoError(t, err)
	assert.Equal(t, first, tok, "an IAM outage must not fail calls while the token is still valid")

	clock.Advance(10 * time.Minute)
	_, err = cache.token(context.Background(), "ibm-key")
	require.Error(t, err)
	assert.ErrorIs(t, err, registry.ErrCredentialAcquisition)
}

func TestTokenCache_RejectedKeyFailsEvenWithCachedToken(t *testing.T) {
	iam := newFakeIAM(t)
	cache, clock := newTestCache(iam)

	_, err := cache.token(context.Background(), "ibm-key")
	require.NoError(t, err)

	iam.status.Store(http.StatusBadRequest)
	clock.Advance(50 * time.Minute)
	_, err = cache.token(context.Background(), "ibm-key")
	require.Error(t, err)
	assert.ErrorIs(t, err, registry.ErrCredentialAcquisition)
	assert.ErrorIs(t, err, errIAMRejected)
	assert.Contains(t, err.Error(), "BXNIM0415E")
	assert.NotContains(t, err.Error(), "ibm-key")
}

func TestTokenCache_InvalidateOnlyDropsTheRefusedToken(t *testing.T) {
	iam := newFakeIAM(t)
	cache, _ := newTestCache(iam)

	first, err := cache.token(context.Background(), "ibm-key")
	require.NoError(t, err)

	cache.invalidate("ibm-key", "some-older-token")
	same, err := cache.token(context.Background(), "ibm-key")
	require.NoError(t, err)
	assert.Equal(t, first, same)

	cache.invalidate("ibm-key", first)
	fresh, err := cache.token(context.Background(), "ibm-key")
	require.NoError(t, err)
	assert.NotEqual(t, first, fresh)
}

func TestTokenCache_RequiresAPIKey(t *testing.T) {
	iam := newFakeIAM(t)
	cache, _ := newTestCache(iam)

	_, err := cache.token(context.Background(), "  ")
	require.Error(t, err)
	assert.ErrorIs(t, err, registry.ErrCredentialAcquisition)
	assert.Zero(t, iam.calls.Load())
}

func TestTokenCache_CallerCancellationDoesNotPoisonExchange(t *testing.T) {
	iam := newFakeIAM(t)
	cache, _ := newTestCache(iam)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := cache.token(ctx, "ibm-key")
	require.ErrorIs(t, err, context.Canceled)

	tok, err := cache.token(context.Background(), "ibm-key")
	require.NoError(t, err)
	assert.NotEmpty(t, tok)
}
