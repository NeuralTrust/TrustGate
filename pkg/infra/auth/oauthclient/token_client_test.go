package oauthclient

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	domain "github.com/NeuralTrust/AgentGateway/pkg/domain/auth"
	"github.com/stretchr/testify/require"
)

func testConfig(tokenURL string) domain.OAuth2ClientConfig {
	return domain.OAuth2ClientConfig{
		TokenURL:     tokenURL,
		ClientID:     "client-id",
		ClientSecret: "client-secret",
		Scopes:       []string{"chat", "search"},
		Audience:     "https://api.example.com",
	}
}

func TestTokenClient_AcquiresAndCachesToken(t *testing.T) {
	t.Parallel()
	var calls atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		require.Equal(t, http.MethodPost, r.Method)
		user, pass, ok := r.BasicAuth()
		require.True(t, ok, "expected client_secret_basic authentication")
		require.Equal(t, "client-id", user)
		require.Equal(t, "client-secret", pass)
		require.NoError(t, r.ParseForm())
		require.Equal(t, "client_credentials", r.PostForm.Get("grant_type"))
		require.Equal(t, "chat search", r.PostForm.Get("scope"))
		require.Equal(t, "https://api.example.com", r.PostForm.Get("audience"))
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"access_token":"acquired-token","token_type":"Bearer","expires_in":3600}`)
	}))
	defer server.Close()

	client := NewTokenClient(server.Client())
	cfg := testConfig(server.URL)

	token, err := client.Token(context.Background(), cfg)
	require.NoError(t, err)
	require.Equal(t, "acquired-token", token)

	token, err = client.Token(context.Background(), cfg)
	require.NoError(t, err)
	require.Equal(t, "acquired-token", token)
	require.Equal(t, int64(1), calls.Load(), "second call must be served from cache")
}

func TestTokenClient_RefreshesExpiredToken(t *testing.T) {
	t.Parallel()
	var calls atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n := calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"access_token":"token-%d","expires_in":3600}`, n)
	}))
	defer server.Close()

	client := NewTokenClient(server.Client())
	now := time.Now()
	client.now = func() time.Time { return now }
	cfg := testConfig(server.URL)

	token, err := client.Token(context.Background(), cfg)
	require.NoError(t, err)
	require.Equal(t, "token-1", token)

	now = now.Add(3600*time.Second - expiryMargin)
	token, err = client.Token(context.Background(), cfg)
	require.NoError(t, err)
	require.Equal(t, "token-2", token, "token within the expiry margin must be refreshed")
	require.Equal(t, int64(2), calls.Load())
}

func TestTokenClient_ShortLivedTokenGetsBriefReuse(t *testing.T) {
	t.Parallel()
	var calls atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n := calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"access_token":"token-%d","expires_in":10}`, n)
	}))
	defer server.Close()

	client := NewTokenClient(server.Client())
	now := time.Now()
	client.now = func() time.Time { return now }
	cfg := testConfig(server.URL)

	token, err := client.Token(context.Background(), cfg)
	require.NoError(t, err)
	require.Equal(t, "token-1", token)

	token, err = client.Token(context.Background(), cfg)
	require.NoError(t, err)
	require.Equal(t, "token-1", token, "a short-lived token must be served from cache for the floor window")
	require.Equal(t, int64(1), calls.Load())

	now = now.Add(minCacheTTL + time.Second)
	token, err = client.Token(context.Background(), cfg)
	require.NoError(t, err)
	require.Equal(t, "token-2", token, "the floor window elapsed, a fresh token must be fetched")
}

func TestTokenClient_DoesNotCacheNonPositiveExpiresIn(t *testing.T) {
	t.Parallel()
	var calls atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n := calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"access_token":"token-%d","expires_in":0}`, n)
	}))
	defer server.Close()

	client := NewTokenClient(server.Client())
	cfg := testConfig(server.URL)

	token, err := client.Token(context.Background(), cfg)
	require.NoError(t, err)
	require.Equal(t, "token-1", token)

	token, err = client.Token(context.Background(), cfg)
	require.NoError(t, err)
	require.Equal(t, "token-2", token, "expires_in <= 0 must never be cached")
	require.Equal(t, int64(2), calls.Load())
}

func TestTokenClient_WaiterHonorsContextCancellation(t *testing.T) {
	t.Parallel()
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		<-release
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"access_token":"slow-token","expires_in":3600}`)
	}))
	defer server.Close()
	defer close(release)

	client := NewTokenClient(server.Client())
	cfg := testConfig(server.URL)

	started := make(chan struct{})
	go func() {
		close(started)
		_, _ = client.Token(context.Background(), cfg)
	}()
	<-started
	time.Sleep(20 * time.Millisecond) // let the first caller start the fetch

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	_, err := client.Token(ctx, cfg)
	require.ErrorIs(t, err, ErrTokenAcquisition)
	require.ErrorIs(t, ctx.Err(), context.DeadlineExceeded)
}

func TestTokenClient_ErrorStatus(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, `{"error":"invalid_client"}`, http.StatusUnauthorized)
	}))
	defer server.Close()

	client := NewTokenClient(server.Client())
	_, err := client.Token(context.Background(), testConfig(server.URL))
	require.ErrorIs(t, err, ErrTokenAcquisition)
}

func TestTokenClient_MissingAccessToken(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"token_type":"Bearer","expires_in":3600}`)
	}))
	defer server.Close()

	client := NewTokenClient(server.Client())
	_, err := client.Token(context.Background(), testConfig(server.URL))
	require.ErrorIs(t, err, ErrTokenAcquisition)
}

func TestTokenClient_UnreachableServer(t *testing.T) {
	t.Parallel()
	client := NewTokenClient(&http.Client{Timeout: time.Second})
	_, err := client.Token(context.Background(), testConfig("http://127.0.0.1:1/token"))
	require.ErrorIs(t, err, ErrTokenAcquisition)
}

func TestTokenClient_ConcurrentCallersSingleFetch(t *testing.T) {
	t.Parallel()
	var calls atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		time.Sleep(20 * time.Millisecond)
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"access_token":"shared-token","expires_in":3600}`)
	}))
	defer server.Close()

	client := NewTokenClient(server.Client())
	cfg := testConfig(server.URL)

	const goroutines = 16
	var wg sync.WaitGroup
	errs := make([]error, goroutines)
	tokens := make([]string, goroutines)
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			tokens[i], errs[i] = client.Token(context.Background(), cfg)
		}(i)
	}
	wg.Wait()

	for i := 0; i < goroutines; i++ {
		require.NoError(t, errs[i])
		require.Equal(t, "shared-token", tokens[i])
	}
	require.Equal(t, int64(1), calls.Load(), "concurrent callers must not stampede the token endpoint")
}

func TestTokenClient_CacheIsPerConfig(t *testing.T) {
	t.Parallel()
	var calls atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n := calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"access_token":"token-%d","expires_in":3600}`, n)
	}))
	defer server.Close()

	client := NewTokenClient(server.Client())
	cfgA := testConfig(server.URL)
	cfgB := testConfig(server.URL)
	cfgB.ClientID = "other-client"

	tokenA, err := client.Token(context.Background(), cfgA)
	require.NoError(t, err)
	tokenB, err := client.Token(context.Background(), cfgB)
	require.NoError(t, err)
	require.NotEqual(t, tokenA, tokenB)
	require.Equal(t, int64(2), calls.Load())
}
