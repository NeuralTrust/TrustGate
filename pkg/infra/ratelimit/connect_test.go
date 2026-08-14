package ratelimit

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	appoauth "github.com/NeuralTrust/TrustGate/pkg/app/oauth"
	"github.com/NeuralTrust/TrustGate/pkg/config"
	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

func newConnectLimiterTest(
	t *testing.T,
	cfg config.MCPConnectRateLimitConfig,
) (appoauth.ConnectAttemptLimiter, *miniredis.Miniredis) {
	t.Helper()
	server := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: server.Addr()})
	t.Cleanup(func() {
		if err := client.Close(); err != nil {
			t.Errorf("close redis client: %v", err)
		}
	})
	return NewConnectAttemptLimiter(client, "server-secret", cfg), server
}

func TestConnectAttemptLimiterThresholds(t *testing.T) {
	cfg := config.MCPConnectRateLimitConfig{
		SourceLimit:   10,
		ConsumerLimit: 100,
		Window:        time.Minute,
	}
	tests := []struct {
		name    string
		scope   appoauth.ConnectAttemptScope
		subject string
		limit   int
	}{
		{name: "source", scope: appoauth.ConnectAttemptScopeSource, subject: "192.0.2.1", limit: 10},
		{name: "consumer", scope: appoauth.ConnectAttemptScopeConsumer, subject: "d99dcf57-8bbe-41de-aaae-c503f448a2f0", limit: 100},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			limiter, _ := newConnectLimiterTest(t, cfg)
			for attempt := 1; attempt <= tc.limit; attempt++ {
				if err := limiter.Check(context.Background(), tc.scope, tc.subject); err != nil {
					t.Fatalf("attempt %d: %v", attempt, err)
				}
			}

			err := limiter.Check(context.Background(), tc.scope, tc.subject)
			var exceeded *appoauth.ConnectRateLimitExceeded
			if !errors.As(err, &exceeded) {
				t.Fatalf("error = %v, want ConnectRateLimitExceeded", err)
			}
			if exceeded.RetryAfter != time.Minute {
				t.Fatalf("RetryAfter = %s, want 1m", exceeded.RetryAfter)
			}
			if strings.Contains(err.Error(), tc.subject) {
				t.Fatalf("error exposes subject: %v", err)
			}
		})
	}
}

func TestConnectAttemptLimiterConcurrentThreshold(t *testing.T) {
	const attempts = 128
	tests := []struct {
		name  string
		scope appoauth.ConnectAttemptScope
		limit int
	}{
		{name: "source", scope: appoauth.ConnectAttemptScopeSource, limit: 10},
		{name: "consumer", scope: appoauth.ConnectAttemptScopeConsumer, limit: 100},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := config.MCPConnectRateLimitConfig{
				SourceLimit:   10,
				ConsumerLimit: 100,
				Window:        time.Minute,
			}
			limiter, _ := newConnectLimiterTest(t, cfg)
			start := make(chan struct{})
			results := make(chan error, attempts)
			var workers sync.WaitGroup
			workers.Add(attempts)

			for range attempts {
				go func() {
					defer workers.Done()
					<-start
					results <- limiter.Check(context.Background(), tc.scope, "shared-subject")
				}()
			}
			close(start)
			workers.Wait()
			close(results)

			allowed := 0
			rejected := 0
			for err := range results {
				if err == nil {
					allowed++
					continue
				}
				var exceeded *appoauth.ConnectRateLimitExceeded
				if !errors.As(err, &exceeded) {
					t.Fatalf("unexpected error: %v", err)
				}
				rejected++
			}
			if allowed != tc.limit {
				t.Fatalf("allowed = %d, want %d", allowed, tc.limit)
			}
			if rejected != attempts-tc.limit {
				t.Fatalf("rejected = %d, want %d", rejected, attempts-tc.limit)
			}
		})
	}
}

func TestConnectAttemptLimiterWindowExpiry(t *testing.T) {
	cfg := config.MCPConnectRateLimitConfig{
		SourceLimit:   1,
		ConsumerLimit: 1,
		Window:        time.Minute,
	}
	limiter, server := newConnectLimiterTest(t, cfg)
	ctx := context.Background()

	if err := limiter.Check(ctx, appoauth.ConnectAttemptScopeSource, "192.0.2.1"); err != nil {
		t.Fatalf("first check: %v", err)
	}
	var exceeded *appoauth.ConnectRateLimitExceeded
	if err := limiter.Check(ctx, appoauth.ConnectAttemptScopeSource, "192.0.2.1"); !errors.As(err, &exceeded) {
		t.Fatalf("second check = %v, want ConnectRateLimitExceeded", err)
	}

	server.FastForward(time.Minute + time.Millisecond)
	if err := limiter.Check(ctx, appoauth.ConnectAttemptScopeSource, "192.0.2.1"); err != nil {
		t.Fatalf("check after expiry: %v", err)
	}
}

func TestConnectAttemptLimiterHMACDomains(t *testing.T) {
	cfg := config.MCPConnectRateLimitConfig{
		SourceLimit:   10,
		ConsumerLimit: 100,
		Window:        time.Minute,
	}
	limiter, server := newConnectLimiterTest(t, cfg)
	ctx := context.Background()
	subject := "shared-subject"

	if err := limiter.Check(ctx, appoauth.ConnectAttemptScopeSource, subject); err != nil {
		t.Fatalf("source check: %v", err)
	}
	if err := limiter.Check(ctx, appoauth.ConnectAttemptScopeConsumer, subject); err != nil {
		t.Fatalf("consumer check: %v", err)
	}

	keys := server.Keys()
	if len(keys) != 2 {
		t.Fatalf("keys = %v, want two", keys)
	}
	wantSource, err := expectedConnectBucketKey("server-secret", "source", subject)
	if err != nil {
		t.Fatalf("source key: %v", err)
	}
	wantConsumer, err := expectedConnectBucketKey("server-secret", "consumer", subject)
	if err != nil {
		t.Fatalf("consumer key: %v", err)
	}
	if !server.Exists(wantSource) || !server.Exists(wantConsumer) {
		t.Fatalf("keys = %v, want %q and %q", keys, wantSource, wantConsumer)
	}
	for _, key := range keys {
		if strings.Contains(key, subject) || strings.Contains(key, "server-secret") {
			t.Fatalf("key exposes raw input: %q", key)
		}
	}
}

func TestResolveConnectSource(t *testing.T) {
	trusted := []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("2001:db8:ffff::/48"),
	}
	tests := []struct {
		name           string
		peer           string
		forwardedFor   string
		trustedProxies []netip.Prefix
		want           string
	}{
		{name: "bare peer", peer: "192.0.2.10", want: "192.0.2.10"},
		{name: "peer port", peer: "192.0.2.10:54321", want: "192.0.2.10"},
		{name: "mapped peer port", peer: "[::ffff:192.0.2.10]:54321", want: "192.0.2.10"},
		{name: "canonical IPv6 peer", peer: "[2001:db8::1]:54321", want: "2001:db8::1"},
		{
			name:           "untrusted peer ignores forwarding",
			peer:           "192.0.2.10:54321",
			forwardedFor:   "198.51.100.20",
			trustedProxies: trusted,
			want:           "192.0.2.10",
		},
		{
			name:           "trusted chain selects first untrusted from right",
			peer:           "10.0.0.2:54321",
			forwardedFor:   "198.51.100.20, 203.0.113.30, 10.1.0.4",
			trustedProxies: trusted,
			want:           "203.0.113.30",
		},
		{
			name:           "trusted chain canonicalizes mapped address",
			peer:           "10.0.0.2:54321",
			forwardedFor:   "::ffff:198.51.100.20, 10.1.0.4",
			trustedProxies: trusted,
			want:           "198.51.100.20",
		},
		{
			name:           "missing forwarding falls back",
			peer:           "10.0.0.2:54321",
			trustedProxies: trusted,
			want:           "10.0.0.2",
		},
		{
			name:           "invalid forwarding falls back",
			peer:           "10.0.0.2:54321",
			forwardedFor:   "198.51.100.20, invalid",
			trustedProxies: trusted,
			want:           "10.0.0.2",
		},
		{
			name:           "all trusted forwarding falls back",
			peer:           "10.0.0.2:54321",
			forwardedFor:   "10.2.0.3, 10.1.0.4",
			trustedProxies: trusted,
			want:           "10.0.0.2",
		},
		{name: "invalid peer", peer: "invalid", forwardedFor: "198.51.100.20", trustedProxies: trusted},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := ResolveConnectSource(tc.peer, tc.forwardedFor, tc.trustedProxies)
			if got != tc.want {
				t.Fatalf("ResolveConnectSource() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestConnectAttemptLimiterRedisErrorsAreOpaque(t *testing.T) {
	client := redis.NewClient(&redis.Options{
		Addr:        "127.0.0.1:0",
		DialTimeout: time.Millisecond,
		MaxRetries:  -1,
	})
	t.Cleanup(func() {
		if err := client.Close(); err != nil {
			t.Errorf("close redis client: %v", err)
		}
	})
	cfg := config.MCPConnectRateLimitConfig{
		SourceLimit:   10,
		ConsumerLimit: 100,
		Window:        time.Minute,
	}
	limiter := NewConnectAttemptLimiter(client, "server-secret", cfg)
	subject := "198.51.100.77"

	err := limiter.Check(context.Background(), appoauth.ConnectAttemptScopeSource, subject)
	if err == nil {
		t.Fatal("expected redis error")
	}
	if err.Error() != "check connect rate limit: connect rate limit unavailable" {
		t.Fatalf("error = %q, want opaque backend error", err)
	}
	if strings.Contains(err.Error(), subject) || strings.Contains(err.Error(), "127.0.0.1") {
		t.Fatalf("error exposes backend or subject: %v", err)
	}
	if !errors.Is(err, errConnectRateLimitUnavailable) {
		t.Fatalf("error must match unavailable sentinel: %v", err)
	}
}

func TestConnectAttemptLimiterPreservesOpaqueErrorCauses(t *testing.T) {
	cfg := config.MCPConnectRateLimitConfig{
		SourceLimit:   10,
		ConsumerLimit: 100,
		Window:        time.Minute,
	}
	limiter, _ := newConnectLimiterTest(t, cfg)

	canceledContext, cancel := context.WithCancel(context.Background())
	cancel()
	canceledErr := limiter.Check(canceledContext, appoauth.ConnectAttemptScopeSource, "canceled")
	if !errors.Is(canceledErr, context.Canceled) {
		t.Fatalf("error = %v, want context.Canceled cause", canceledErr)
	}
	if canceledErr.Error() != "check connect rate limit: connect rate limit unavailable" {
		t.Fatalf("canceled error leaks detail: %q", canceledErr)
	}

	expiredContext, stop := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer stop()
	deadlineErr := limiter.Check(expiredContext, appoauth.ConnectAttemptScopeSource, "deadline")
	if !errors.Is(deadlineErr, context.DeadlineExceeded) {
		t.Fatalf("error = %v, want context.DeadlineExceeded cause", deadlineErr)
	}
	if deadlineErr.Error() != "check connect rate limit: connect rate limit unavailable" {
		t.Fatalf("deadline error leaks detail: %q", deadlineErr)
	}
}

func TestConnectAttemptLimiterPreservesRedisCause(t *testing.T) {
	server := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: server.Addr()})
	if err := client.Close(); err != nil {
		t.Fatalf("close redis client: %v", err)
	}
	cfg := config.MCPConnectRateLimitConfig{
		SourceLimit:   10,
		ConsumerLimit: 100,
		Window:        time.Minute,
	}
	limiter := NewConnectAttemptLimiter(client, "server-secret", cfg)

	err := limiter.Check(context.Background(), appoauth.ConnectAttemptScopeSource, "subject")
	if !errors.Is(err, redis.ErrClosed) {
		t.Fatalf("error = %v, want redis.ErrClosed cause", err)
	}
	if err.Error() != "check connect rate limit: connect rate limit unavailable" {
		t.Fatalf("error leaks Redis cause: %q", err)
	}
}

func TestConnectAttemptLimiterRejectsInvalidInputs(t *testing.T) {
	cfg := config.MCPConnectRateLimitConfig{
		SourceLimit:   10,
		ConsumerLimit: 100,
		Window:        time.Minute,
	}
	limiter, _ := newConnectLimiterTest(t, cfg)
	tests := []struct {
		name    string
		scope   appoauth.ConnectAttemptScope
		subject string
	}{
		{name: "unknown scope", scope: 99, subject: "subject"},
		{name: "empty subject", scope: appoauth.ConnectAttemptScopeSource},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := limiter.Check(context.Background(), tc.scope, tc.subject)
			if err == nil || err.Error() != "check connect rate limit: invalid connect rate limit input" {
				t.Fatalf("error = %v, want opaque invalid input", err)
			}
		})
	}
}

func expectedConnectBucketKey(secret, domain, subject string) (string, error) {
	mac := hmac.New(sha256.New, []byte(secret))
	if _, err := mac.Write([]byte(domain)); err != nil {
		return "", err
	}
	if _, err := mac.Write([]byte{0}); err != nil {
		return "", err
	}
	if _, err := mac.Write([]byte(subject)); err != nil {
		return "", err
	}
	return connectBucketPrefix + ":" + domain + ":" + hex.EncodeToString(mac.Sum(nil)), nil
}
