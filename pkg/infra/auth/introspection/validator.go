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
	"golang.org/x/sync/singleflight"
)

var ErrInvalidToken = errors.New("introspection: invalid token")

const (
	fallbackTTL   = time.Minute
	maxTTL        = 5 * time.Minute
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

type Validator struct {
	client *http.Client

	sf        singleflight.Group
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
	if len(cfg.Audiences) > 0 && !identity.AudienceMatches(identity.AudiencesFromClaim(res.Aud), cfg.Audiences) {
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
	sum := sha256.Sum256([]byte(cfg.IntrospectionURL + "\x00" + raw))
	key := hex.EncodeToString(sum[:])

	v.mu.Lock()
	if e, ok := v.cache[key]; ok && time.Now().Before(e.expiresAt) {
		v.mu.Unlock()
		return e.res, nil
	}
	v.mu.Unlock()

	out, err, _ := v.sf.Do(key, func() (any, error) {
		v.mu.Lock()
		if e, ok := v.cache[key]; ok && time.Now().Before(e.expiresAt) {
			v.mu.Unlock()
			return e.res, nil
		}
		v.mu.Unlock()
		return v.introspectRemote(ctx, raw, key, cfg)
	})
	if err != nil {
		return result{}, err
	}
	res, ok := out.(result)
	if !ok {
		return result{}, errors.New("introspection: unexpected singleflight result type")
	}
	return res, nil
}

func (v *Validator) introspectRemote(ctx context.Context, raw, key string, cfg *authdomain.OAuth2Config) (result, error) {
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
