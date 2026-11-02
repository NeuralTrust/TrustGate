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
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/infra/o11y"
)

const (
	oauthTokenPath = "/oauth/token" // #nosec G101 -- endpoint path, not a credential

	oauthTokenTimeout     = 10 * time.Second
	oauthMaxResponseBytes = 64 << 10
	oauthSkew             = 5 * time.Minute

	// A failed /oauth/token is remembered so a revoked client or an OAuth-less
	// firewall is not asked on every scored request.
	oauthInvalidClientBackoff = time.Minute
	oauthErrorBackoff         = 10 * time.Second

	// A token refused this soon after it was issued points at the firewall
	// rather than at expiry, so refetching at once would only loop.
	oauthFreshRejectionWindow = 30 * time.Second

	oauthPeerService = "firewall-gateway"
	oauthSpanName    = "firewall.oauth_token"

	unusableLogInterval = time.Minute
)

var (
	// ErrInvalidClient is returned when the firewall refuses the OAuth client.
	ErrInvalidClient = errors.New("firewall: OAuth client rejected (invalid_client)")
	// ErrTokenEndpoint is returned when /oauth/token fails or answers unusably.
	ErrTokenEndpoint = errors.New("firewall: OAuth token endpoint failed")
	// ErrTokenRejected is returned while backing off after the firewall refused
	// a token it had just issued.
	ErrTokenRejected = errors.New("firewall: freshly issued OAuth token rejected")
)

type oauthToken struct {
	value       string
	fetchedAt   time.Time
	usableUntil time.Time
}

type oauthFlight struct {
	done chan struct{}
	tok  *oauthToken
	err  error
}

// OAuthTokenSource authenticates firewall calls with an access token obtained
// from /oauth/token with the client_credentials grant. Tokens are cached in
// memory and fetched by one request at a time.
type OAuthTokenSource struct {
	baseURL      string
	clientID     string
	clientSecret string
	client       *http.Client
	logger       *slog.Logger
	now          func() time.Time

	mu           sync.Mutex
	cached       *oauthToken
	inflight     *oauthFlight
	failedUntil  time.Time
	failureCause error
}

// NewOAuthTokenSource builds a token source for one firewall OAuth client.
func NewOAuthTokenSource(baseURL, clientID, clientSecret string, logger *slog.Logger) *OAuthTokenSource {
	if logger == nil {
		logger = slog.Default()
	}
	return &OAuthTokenSource{
		baseURL:      strings.TrimRight(baseURL, "/"),
		clientID:     clientID,
		clientSecret: clientSecret,
		client: &http.Client{
			Timeout:   oauthTokenTimeout,
			Transport: o11y.InternalTransport(oauthPeerService, oauthSpanName),
		},
		logger: logger,
		now:    time.Now,
	}
}

// Configured reports whether the source has a client to authenticate with.
func (s *OAuthTokenSource) Configured() bool {
	return s != nil && s.baseURL != "" && s.clientID != "" && s.clientSecret != ""
}

// Authorize sets the bearer access token, fetching one when none is usable.
func (s *OAuthTokenSource) Authorize(ctx context.Context, req *http.Request) error {
	if !s.Configured() {
		return ErrNotConfigured
	}
	tok, err := s.token(ctx)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+tok.value)
	return nil
}

// Invalidate drops the token req carried, but only while it is still the
// cached one, so a token fetched meanwhile by a concurrent call survives.
func (s *OAuthTokenSource) Invalidate(req *http.Request) {
	if s == nil || req == nil {
		return
	}
	value, ok := strings.CutPrefix(req.Header.Get("Authorization"), "Bearer ")
	if !ok || value == "" {
		return
	}
	s.mu.Lock()
	if s.cached == nil || s.cached.value != value {
		s.mu.Unlock()
		return
	}
	fresh := s.now().Sub(s.cached.fetchedAt) < oauthFreshRejectionWindow
	s.cached = nil
	if fresh {
		s.failedUntil = s.now().Add(oauthErrorBackoff)
		s.failureCause = ErrTokenRejected
	}
	s.mu.Unlock()
	if fresh {
		s.logger.Warn("firewall rejected a freshly issued OAuth token, backing off",
			slog.String("client_id", s.clientID), slog.Duration("backoff", oauthErrorBackoff))
	}
}

func (s *OAuthTokenSource) token(ctx context.Context) (*oauthToken, error) {
	s.mu.Lock()
	now := s.now()
	if s.cached != nil && now.Before(s.cached.usableUntil) {
		tok := s.cached
		s.mu.Unlock()
		return tok, nil
	}
	if now.Before(s.failedUntil) {
		err := s.failureCause
		s.mu.Unlock()
		return nil, err
	}
	f := s.inflight
	if f == nil {
		f = &oauthFlight{done: make(chan struct{})}
		s.inflight = f
		go s.acquire(context.WithoutCancel(ctx), f)
	}
	s.mu.Unlock()

	select {
	case <-f.done:
		return f.tok, f.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (s *OAuthTokenSource) acquire(ctx context.Context, f *oauthFlight) {
	tok, err := s.fetch(ctx)

	s.mu.Lock()
	s.inflight = nil
	if err != nil {
		backoff := oauthErrorBackoff
		if errors.Is(err, ErrInvalidClient) {
			backoff = oauthInvalidClientBackoff
		}
		s.failedUntil = s.now().Add(backoff)
		s.failureCause = err
	} else {
		s.cached = tok
		s.failedUntil = time.Time{}
		s.failureCause = nil
	}
	s.mu.Unlock()

	defer func() {
		f.tok, f.err = tok, err
		close(f.done)
	}()

	switch {
	case errors.Is(err, ErrInvalidClient):
		s.logger.Error("firewall rejected the OAuth client",
			slog.String("client_id", s.clientID), slog.String("oauth_error", "invalid_client"))
	case err != nil:
		s.logger.Warn("firewall OAuth token request failed",
			slog.String("client_id", s.clientID), slog.String("error", err.Error()))
	default:
		s.logger.Info("firewall OAuth token fetched",
			slog.String("client_id", s.clientID), slog.Time("usable_until", tok.usableUntil.UTC()))
	}
}

func (s *OAuthTokenSource) fetch(ctx context.Context) (*oauthToken, error) {
	ctx, cancel := context.WithTimeout(ctx, oauthTokenTimeout)
	defer cancel()

	form := url.Values{"grant_type": {"client_credentials"}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.baseURL+oauthTokenPath, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("%w: build request", ErrTokenEndpoint)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(s.clientID, s.clientSecret)

	issuedAt := s.now()
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrTokenEndpoint, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, oauthMaxResponseBytes))
	if err != nil {
		return nil, fmt.Errorf("%w: read response", ErrTokenEndpoint)
	}

	if resp.StatusCode != http.StatusOK {
		if (resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusBadRequest) && oauthErrorCode(body) == "invalid_client" {
			return nil, ErrInvalidClient
		}
		return nil, fmt.Errorf("%w: status %d", ErrTokenEndpoint, resp.StatusCode)
	}

	var out struct {
		AccessToken string `json:"access_token"` // #nosec G117 -- response field, not a hardcoded credential
		TokenType   string `json:"token_type"`
		ExpiresIn   int64  `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("%w: malformed response", ErrTokenEndpoint)
	}
	if out.AccessToken == "" || !strings.EqualFold(out.TokenType, "bearer") || out.ExpiresIn <= 0 {
		return nil, fmt.Errorf("%w: unusable response", ErrTokenEndpoint)
	}
	return &oauthToken{
		value:       out.AccessToken,
		fetchedAt:   issuedAt,
		usableUntil: issuedAt.Add(usableWindow(time.Duration(out.ExpiresIn) * time.Second)),
	}, nil
}

func oauthErrorCode(body []byte) string {
	var e struct {
		Error string `json:"error"`
	}
	if json.Unmarshal(body, &e) != nil {
		return ""
	}
	return e.Error
}

// usableWindow is expires_in minus the skew, capped at tokenTTL. A token that
// lives no longer than the skew keeps half its life so it is still reused.
func usableWindow(expiresIn time.Duration) time.Duration {
	window := expiresIn / 2
	if expiresIn > oauthSkew {
		window = expiresIn - oauthSkew
	}
	return min(window, tokenTTL)
}

// UnusableSource stands in for a firewall credential that failed validation:
// every call fails with that error, logged at most once a minute.
type UnusableSource struct {
	err    error
	logger *slog.Logger
	now    func() time.Time

	mu      sync.Mutex
	logNext time.Time
}

// NewUnusableSource builds a source that always fails with err.
func NewUnusableSource(err error, logger *slog.Logger) *UnusableSource {
	if logger == nil {
		logger = slog.Default()
	}
	return &UnusableSource{err: err, logger: logger, now: time.Now}
}

// Configured is true so callers try, and fail, rather than skip silently.
func (s *UnusableSource) Configured() bool { return s != nil }

// Authorize always returns the validation error.
func (s *UnusableSource) Authorize(_ context.Context, _ *http.Request) error {
	s.mu.Lock()
	now := s.now()
	shouldLog := !now.Before(s.logNext)
	if shouldLog {
		s.logNext = now.Add(unusableLogInterval)
	}
	s.mu.Unlock()
	if shouldLog {
		s.logger.Warn("firewall call skipped: invalid firewall credential", slog.String("error", s.err.Error()))
	}
	return s.err
}

// Invalidate does nothing: there is no token to drop.
func (s *UnusableSource) Invalidate(_ *http.Request) {}
