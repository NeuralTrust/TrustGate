// Package introspection validates opaque/reference tokens against an IdP's
// RFC 7662 introspection endpoint, caching results until token expiry so the
// IdP is not hit on every request.
package introspection

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	authdomain "github.com/NeuralTrust/AgentGateway/pkg/domain/auth"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/identity"
)

var ErrInvalidToken = errors.New("introspection: invalid token")

const (
	// fallbackTTL bounds cache entries when the IdP returns no exp claim.
	fallbackTTL = time.Minute
	// maxTTL bounds cache entries so revocation is observed within this window
	// even for long-lived tokens.
	maxTTL = 5 * time.Minute
	// sweepInterval bounds how often expired entries are purged; without a
	// sweep the cache grows for every distinct token ever seen.
	sweepInterval = time.Minute
)

type result struct {
	Active   bool   `json:"active"`
	Sub      string `json:"sub"`
	Username string `json:"username"`
	Scope    string `json:"scope"`
	Aud      any    `json:"aud"`
	Iss      string `json:"iss"`
	Exp      int64  `json:"exp"`
}

type cacheEntry struct {
	res       result
	expiresAt time.Time
}

// Validator introspects bearer tokens per Auth entry config.
type Validator struct {
	client *http.Client

	mu        sync.Mutex
	cache     map[string]cacheEntry
	lastSweep time.Time
}

func NewValidator(client *http.Client) *Validator {
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	return &Validator{client: client, cache: map[string]cacheEntry{}}
}

// Validate introspects raw against cfg's introspection endpoint and returns
// the authenticated Principal.
func (v *Validator) Validate(ctx context.Context, raw string, cfg *authdomain.OAuth2Config) (*identity.Principal, error) {
	if cfg == nil || cfg.IntrospectionURL == "" {
		return nil, fmt.Errorf("%w: no introspection endpoint configured", ErrInvalidToken)
	}

	res, err := v.introspect(ctx, raw, cfg)
	if err != nil {
		return nil, err
	}
	if !res.Active {
		return nil, fmt.Errorf("%w: token inactive", ErrInvalidToken)
	}
	if len(cfg.Audiences) > 0 && !audMatch(res.Aud, cfg.Audiences) {
		return nil, fmt.Errorf("%w: audience mismatch", ErrInvalidToken)
	}

	subject := res.Sub
	if subject == "" {
		subject = res.Username
	}
	principal := &identity.Principal{
		Subject:  subject,
		Method:   identity.MethodIntrospection,
		Issuer:   res.Iss,
		Scopes:   strings.Fields(res.Scope),
		RawToken: raw,
	}
	if !principal.HasScopes(cfg.RequiredScopes) {
		return nil, fmt.Errorf("%w: missing required scopes", ErrInvalidToken)
	}
	return principal, nil
}

func (v *Validator) introspect(ctx context.Context, raw string, cfg *authdomain.OAuth2Config) (result, error) {
	// Key by endpoint + token so the same token introspected against two IdPs
	// cannot poison each other's cache.
	sum := sha256.Sum256([]byte(cfg.IntrospectionURL + "\x00" + raw))
	key := hex.EncodeToString(sum[:])

	v.mu.Lock()
	if e, ok := v.cache[key]; ok && time.Now().Before(e.expiresAt) {
		v.mu.Unlock()
		return e.res, nil
	}
	v.mu.Unlock()

	form := url.Values{"token": {raw}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.IntrospectionURL, strings.NewReader(form.Encode()))
	if err != nil {
		return result{}, fmt.Errorf("introspection: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if cfg.ClientID != "" {
		req.SetBasicAuth(cfg.ClientID, cfg.ClientSecret)
	}
	httpRes, err := v.client.Do(req)
	if err != nil {
		return result{}, fmt.Errorf("introspection: %s: %w", cfg.IntrospectionURL, err)
	}
	defer func() { _ = httpRes.Body.Close() }()
	if httpRes.StatusCode != http.StatusOK {
		return result{}, fmt.Errorf("introspection: %s: status %d", cfg.IntrospectionURL, httpRes.StatusCode)
	}
	var res result
	if err := json.NewDecoder(httpRes.Body).Decode(&res); err != nil {
		return result{}, fmt.Errorf("introspection: decode response: %w", err)
	}

	// Cache for the token's remaining lifetime, clamped to maxTTL so
	// revocation is observed; fallbackTTL covers responses without exp.
	ttl := fallbackTTL
	if res.Exp > 0 {
		ttl = time.Until(time.Unix(res.Exp, 0))
	}
	if ttl > maxTTL {
		ttl = maxTTL
	}
	if ttl <= 0 {
		return res, nil
	}
	v.mu.Lock()
	v.sweepLocked()
	v.cache[key] = cacheEntry{res: res, expiresAt: time.Now().Add(ttl)}
	v.mu.Unlock()
	return res, nil
}

// sweepLocked drops expired entries at most once per sweepInterval; expired
// entries were previously only skipped on read, never deleted, so the cache
// leaked one entry per distinct token forever. Callers must hold v.mu.
func (v *Validator) sweepLocked() {
	now := time.Now()
	if now.Sub(v.lastSweep) < sweepInterval {
		return
	}
	v.lastSweep = now
	for k, e := range v.cache {
		if now.After(e.expiresAt) {
			delete(v.cache, k)
		}
	}
}

// audMatch handles RFC 7662 aud being either a string or an array.
func audMatch(aud any, want []string) bool {
	switch a := aud.(type) {
	case string:
		for _, w := range want {
			if a == w {
				return true
			}
		}
	case []any:
		for _, item := range a {
			s, ok := item.(string)
			if !ok {
				continue
			}
			for _, w := range want {
				if s == w {
					return true
				}
			}
		}
	}
	return false
}
