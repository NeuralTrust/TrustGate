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

package firewall

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testClientID     = "client-7f3a"
	testClientSecret = "oauth-secret-that-must-never-leak" // #nosec G101 -- test fixture
)

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
	c.now = c.now.Add(d)
	c.mu.Unlock()
}

type tokenServer struct {
	calls   atomic.Int32
	status  atomic.Int32
	body    atomic.Value
	release chan struct{}
}

func newTokenServer(t *testing.T) (*tokenServer, *httptest.Server) {
	t.Helper()
	ts := &tokenServer{}
	ts.status.Store(http.StatusOK)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := ts.calls.Add(1)
		if ts.release != nil {
			<-ts.release
		}
		assert.Equal(t, oauthTokenPath, r.URL.Path)
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "application/x-www-form-urlencoded", r.Header.Get("Content-Type"))
		id, secret, ok := r.BasicAuth()
		assert.True(t, ok)
		assert.Equal(t, testClientID, id)
		assert.Equal(t, testClientSecret, secret)
		require.NoError(t, r.ParseForm())
		assert.Equal(t, "client_credentials", r.PostForm.Get("grant_type"))
		w.WriteHeader(int(ts.status.Load()))
		if body, _ := ts.body.Load().(string); body != "" {
			_, _ = w.Write([]byte(body))
			return
		}
		_, _ = fmt.Fprintf(w, `{"access_token":"access-%d","token_type":"Bearer","expires_in":3600}`, n)
	}))
	t.Cleanup(srv.Close)
	return ts, srv
}

func newTestSource(t *testing.T, baseURL string, logs *bytes.Buffer) (*OAuthTokenSource, *fakeClock) {
	t.Helper()
	var logger *slog.Logger
	if logs != nil {
		logger = slog.New(slog.NewTextHandler(logs, nil))
	}
	src := NewOAuthTokenSource(baseURL+"/", testClientID, testClientSecret, logger)
	clock := &fakeClock{now: time.Unix(1_800_000_000, 0)}
	src.now = clock.Now
	return src, clock
}

func authorize(t *testing.T, src *OAuthTokenSource) (*http.Request, error) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "http://fw/v1/complexity", nil)
	return req, src.Authorize(context.Background(), req)
}

func TestOAuthTokenSource_Configured(t *testing.T) {
	t.Parallel()
	assert.True(t, NewOAuthTokenSource("http://fw", "id", "secret", nil).Configured())
	assert.False(t, NewOAuthTokenSource("", "id", "secret", nil).Configured())
	assert.False(t, NewOAuthTokenSource("http://fw", "", "secret", nil).Configured())
	assert.False(t, NewOAuthTokenSource("http://fw", "id", "", nil).Configured())
	var nilSource *OAuthTokenSource
	assert.False(t, nilSource.Configured())
	req := httptest.NewRequest(http.MethodPost, "http://fw", nil)
	assert.ErrorIs(t, nilSource.Authorize(context.Background(), req), ErrNotConfigured)
}

func TestOAuthTokenSource_FetchesAndReuses(t *testing.T) {
	t.Parallel()
	ts, srv := newTokenServer(t)
	src, _ := newTestSource(t, srv.URL, nil)

	for range 3 {
		req, err := authorize(t, src)
		require.NoError(t, err)
		assert.Equal(t, "Bearer access-1", req.Header.Get("Authorization"))
		assert.Empty(t, req.Header.Get("token"))
	}
	assert.EqualValues(t, 1, ts.calls.Load())
}

func TestOAuthTokenSource_RefreshesBeforeExpiry(t *testing.T) {
	t.Parallel()
	ts, srv := newTokenServer(t)
	src, clock := newTestSource(t, srv.URL, nil)

	_, err := authorize(t, src)
	require.NoError(t, err)
	clock.Advance(54 * time.Minute)
	req, err := authorize(t, src)
	require.NoError(t, err)
	assert.Equal(t, "Bearer access-1", req.Header.Get("Authorization"))

	clock.Advance(time.Minute)
	req, err = authorize(t, src)
	require.NoError(t, err)
	assert.Equal(t, "Bearer access-2", req.Header.Get("Authorization"))
	assert.EqualValues(t, 2, ts.calls.Load())
}

func TestOAuthTokenSource_SingleFlight(t *testing.T) {
	t.Parallel()
	ts, srv := newTokenServer(t)
	ts.release = make(chan struct{})
	src, _ := newTestSource(t, srv.URL, nil)

	const callers = 16
	var wg sync.WaitGroup
	headers := make(chan string, callers)
	for range callers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req := httptest.NewRequest(http.MethodPost, "http://fw/v1/complexity", nil)
			if err := src.Authorize(context.Background(), req); err != nil {
				headers <- "error: " + err.Error()
				return
			}
			headers <- req.Header.Get("Authorization")
		}()
	}
	require.Eventually(t, func() bool { return ts.calls.Load() == 1 }, time.Second, time.Millisecond)
	close(ts.release)
	wg.Wait()
	close(headers)
	for h := range headers {
		assert.Equal(t, "Bearer access-1", h)
	}
	assert.EqualValues(t, 1, ts.calls.Load())
}

func TestOAuthTokenSource_CallerCancelDoesNotFailOthers(t *testing.T) {
	t.Parallel()
	ts, srv := newTokenServer(t)
	ts.release = make(chan struct{})
	src, _ := newTestSource(t, srv.URL, nil)

	ctx, cancel := context.WithCancel(context.Background())
	cancelled := make(chan error, 1)
	go func() {
		req := httptest.NewRequest(http.MethodPost, "http://fw", nil)
		cancelled <- src.Authorize(ctx, req)
	}()
	require.Eventually(t, func() bool { return ts.calls.Load() == 1 }, time.Second, time.Millisecond)

	other := make(chan error, 1)
	go func() {
		req := httptest.NewRequest(http.MethodPost, "http://fw", nil)
		other <- src.Authorize(context.Background(), req)
	}()
	cancel()
	assert.ErrorIs(t, <-cancelled, context.Canceled)
	close(ts.release)
	require.NoError(t, <-other)
	assert.EqualValues(t, 1, ts.calls.Load())
}

func TestOAuthTokenSource_InvalidClientBacksOff(t *testing.T) {
	t.Parallel()
	ts, srv := newTokenServer(t)
	ts.status.Store(http.StatusUnauthorized)
	ts.body.Store(`{"error":"invalid_client"}`)
	var logs bytes.Buffer
	src, clock := newTestSource(t, srv.URL, &logs)

	_, err := authorize(t, src)
	require.ErrorIs(t, err, ErrInvalidClient)
	clock.Advance(59 * time.Second)
	_, err = authorize(t, src)
	require.ErrorIs(t, err, ErrInvalidClient)
	assert.EqualValues(t, 1, ts.calls.Load())

	clock.Advance(time.Second)
	ts.status.Store(http.StatusOK)
	ts.body.Store("")
	req, err := authorize(t, src)
	require.NoError(t, err)
	assert.Equal(t, "Bearer access-2", req.Header.Get("Authorization"))
	assert.Contains(t, logs.String(), testClientID)
	assert.NotContains(t, logs.String(), testClientSecret)
}

func TestOAuthTokenSource_EndpointFailuresBackOff(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name   string
		status int
		body   string
	}{
		{"server error", http.StatusBadGateway, `{"detail":"down"}`},
		{"oauth disabled", http.StatusServiceUnavailable, `{"detail":"OAuth is not enabled"}`},
		{"malformed body", http.StatusOK, `not json`},
		{"no access token", http.StatusOK, `{"token_type":"Bearer","expires_in":3600}`},
		{"wrong token type", http.StatusOK, `{"access_token":"a","token_type":"mac","expires_in":3600}`},
		{"no expiry", http.StatusOK, `{"access_token":"a","token_type":"Bearer","expires_in":0}`},
		{"bad request", http.StatusBadRequest, `{"error":"invalid_request"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ts, srv := newTokenServer(t)
			ts.status.Store(int32(tc.status))
			ts.body.Store(tc.body)
			src, clock := newTestSource(t, srv.URL, nil)

			_, err := authorize(t, src)
			require.ErrorIs(t, err, ErrTokenEndpoint)
			assert.NotContains(t, err.Error(), testClientSecret)
			clock.Advance(9 * time.Second)
			_, err = authorize(t, src)
			require.ErrorIs(t, err, ErrTokenEndpoint)
			assert.EqualValues(t, 1, ts.calls.Load())

			clock.Advance(time.Second)
			_, _ = authorize(t, src)
			assert.EqualValues(t, 2, ts.calls.Load())
		})
	}
}

func TestOAuthTokenSource_UnreachableFirewall(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.NotFoundHandler())
	srv.Close()
	src, _ := newTestSource(t, srv.URL, nil)
	_, err := authorize(t, src)
	require.ErrorIs(t, err, ErrTokenEndpoint)
	assert.NotContains(t, err.Error(), testClientSecret)
}

func TestOAuthTokenSource_InvalidateDropsOnlyTheRejectedToken(t *testing.T) {
	t.Parallel()
	ts, srv := newTokenServer(t)
	src, clock := newTestSource(t, srv.URL, nil)

	first, err := authorize(t, src)
	require.NoError(t, err)
	clock.Advance(time.Minute)

	stale := httptest.NewRequest(http.MethodPost, "http://fw", nil)
	stale.Header.Set("Authorization", "Bearer some-older-token")
	src.Invalidate(stale)
	req, err := authorize(t, src)
	require.NoError(t, err)
	assert.Equal(t, "Bearer access-1", req.Header.Get("Authorization"))

	src.Invalidate(first)
	req, err = authorize(t, src)
	require.NoError(t, err)
	assert.Equal(t, "Bearer access-2", req.Header.Get("Authorization"))
	assert.EqualValues(t, 2, ts.calls.Load())
}

func TestOAuthTokenSource_FreshRejectionBacksOff(t *testing.T) {
	t.Parallel()
	ts, srv := newTokenServer(t)
	src, clock := newTestSource(t, srv.URL, nil)

	first, err := authorize(t, src)
	require.NoError(t, err)
	clock.Advance(time.Second)
	src.Invalidate(first)

	_, err = authorize(t, src)
	require.ErrorIs(t, err, ErrTokenRejected)
	clock.Advance(9 * time.Second)
	_, err = authorize(t, src)
	require.ErrorIs(t, err, ErrTokenRejected)
	assert.EqualValues(t, 1, ts.calls.Load())

	clock.Advance(time.Second)
	req, err := authorize(t, src)
	require.NoError(t, err)
	assert.Equal(t, "Bearer access-2", req.Header.Get("Authorization"))
}

func TestOAuthTokenSource_InvalidateIgnoresForeignRequests(t *testing.T) {
	t.Parallel()
	_, srv := newTokenServer(t)
	src, _ := newTestSource(t, srv.URL, nil)
	src.Invalidate(nil)
	src.Invalidate(httptest.NewRequest(http.MethodPost, "http://fw", nil))
	var nilSource *OAuthTokenSource
	nilSource.Invalidate(nil)
}

func TestUsableWindow(t *testing.T) {
	t.Parallel()
	assert.Equal(t, 55*time.Minute, usableWindow(time.Hour))
	assert.Equal(t, tokenTTL, usableWindow(3*time.Hour))
	assert.Equal(t, 2*time.Minute, usableWindow(4*time.Minute))
}

func TestUnusableSource(t *testing.T) {
	t.Parallel()
	cause := errors.New("FIREWALL_JWT has expired")
	var logs bytes.Buffer
	src := NewUnusableSource(cause, slog.New(slog.NewTextHandler(&logs, nil)))
	clock := &fakeClock{now: time.Unix(1_800_000_000, 0)}
	src.now = clock.Now

	assert.True(t, src.Configured())
	for range 3 {
		req := httptest.NewRequest(http.MethodPost, "http://fw", nil)
		require.ErrorIs(t, src.Authorize(context.Background(), req), cause)
		assert.Empty(t, req.Header.Get("Authorization"))
		assert.Empty(t, req.Header.Get("token"))
	}
	assert.Equal(t, 1, bytes.Count(logs.Bytes(), []byte("invalid firewall credential")))
	clock.Advance(time.Minute)
	_ = src.Authorize(context.Background(), httptest.NewRequest(http.MethodPost, "http://fw", nil))
	assert.Equal(t, 2, bytes.Count(logs.Bytes(), []byte("invalid firewall credential")))
	src.Invalidate(nil)
}
