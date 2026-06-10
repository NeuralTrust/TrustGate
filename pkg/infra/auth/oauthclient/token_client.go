package oauthclient

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	appauth "github.com/NeuralTrust/AgentGateway/pkg/app/auth"
	domain "github.com/NeuralTrust/AgentGateway/pkg/domain/auth"
)

const (
	defaultFetchTimeout = 10 * time.Second
	expiryMargin        = 30 * time.Second
	defaultTokenTTL     = 60 * time.Second
	minCacheTTL         = 5 * time.Second
)

var ErrTokenAcquisition = appauth.ErrTokenAcquisition

type TokenClient struct {
	client *http.Client
	now    func() time.Time
	mu     sync.Mutex
	items  map[string]*tokenEntry
}

type tokenEntry struct {
	token     string
	expiresAt time.Time
	inflight  *tokenFetch
}

type tokenFetch struct {
	done  chan struct{}
	token string
	err   error
}

var _ appauth.OAuth2ClientTokenSource = (*TokenClient)(nil)

func NewTokenClient(client *http.Client) *TokenClient {
	if client == nil {
		client = &http.Client{Timeout: defaultFetchTimeout}
	} else if client.Timeout <= 0 {
		clone := *client
		clone.Timeout = defaultFetchTimeout
		client = &clone
	}
	return &TokenClient{
		client: client,
		now:    time.Now,
		items:  make(map[string]*tokenEntry),
	}
}

func NewTokenSource(client *http.Client) appauth.OAuth2ClientTokenSource {
	return NewTokenClient(client)
}

func (c *TokenClient) Token(ctx context.Context, cfg domain.OAuth2ClientConfig) (string, error) {
	c.mu.Lock()
	entry := c.entryLocked(cacheKey(cfg))
	if entry.token != "" && c.now().Before(entry.expiresAt) {
		token := entry.token
		c.mu.Unlock()
		return token, nil
	}
	fetch := entry.inflight
	if fetch == nil {
		fetch = &tokenFetch{done: make(chan struct{})}
		entry.inflight = fetch
		go c.runFetch(cfg, entry, fetch)
	}
	c.mu.Unlock()

	select {
	case <-fetch.done:
		return fetch.token, fetch.err
	case <-ctx.Done():
		return "", fmt.Errorf("%w: %v", ErrTokenAcquisition, ctx.Err())
	}
}

func (c *TokenClient) entryLocked(key string) *tokenEntry {
	entry, ok := c.items[key]
	if !ok {
		entry = &tokenEntry{}
		c.items[key] = entry
	}
	return entry
}

func (c *TokenClient) runFetch(cfg domain.OAuth2ClientConfig, entry *tokenEntry, fetch *tokenFetch) {
	token, cacheTTL, err := c.fetch(cfg)
	c.mu.Lock()
	if err == nil {
		fetch.token = token
		if cacheTTL > 0 {
			entry.token = token
			entry.expiresAt = c.now().Add(cacheTTL)
		}
	} else {
		fetch.err = err
	}
	entry.inflight = nil
	c.mu.Unlock()
	close(fetch.done)
}

type tokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   *int64 `json:"expires_in"`
}

func (c *TokenClient) fetch(cfg domain.OAuth2ClientConfig) (string, time.Duration, error) {
	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	if scope := strings.Join(cfg.Scopes, " "); scope != "" {
		form.Set("scope", scope)
	}
	if cfg.Audience != "" {
		form.Set("audience", cfg.Audience)
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, cfg.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", 0, fmt.Errorf("%w: build token request: %v", ErrTokenAcquisition, err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.SetBasicAuth(cfg.ClientID, cfg.ClientSecret)
	resp, err := c.client.Do(req)
	if err != nil {
		return "", 0, fmt.Errorf("%w: post token request: %v", ErrTokenAcquisition, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", 0, fmt.Errorf("%w: token endpoint status %d", ErrTokenAcquisition, resp.StatusCode)
	}
	var body tokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return "", 0, fmt.Errorf("%w: decode token response: %v", ErrTokenAcquisition, err)
	}
	if strings.TrimSpace(body.AccessToken) == "" {
		return "", 0, fmt.Errorf("%w: token response missing access_token", ErrTokenAcquisition)
	}
	return body.AccessToken, cacheTTLFor(body.ExpiresIn), nil
}

func cacheTTLFor(expiresIn *int64) time.Duration {
	if expiresIn == nil {
		return defaultTokenTTL - expiryMargin
	}
	if *expiresIn <= 0 {
		return 0
	}
	ttl := time.Duration(*expiresIn)*time.Second - expiryMargin
	if ttl < minCacheTTL {
		return minCacheTTL
	}
	return ttl
}

func cacheKey(cfg domain.OAuth2ClientConfig) string {
	h := sha256.New()
	for _, part := range []string{cfg.TokenURL, cfg.ClientID, cfg.ClientSecret, strings.Join(cfg.Scopes, " "), cfg.Audience} {
		h.Write([]byte(part))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}
