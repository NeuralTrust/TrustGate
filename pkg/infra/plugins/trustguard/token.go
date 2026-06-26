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

package trustguard

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"
)

const (
	tokenPath        = "/v1/token"
	grantType        = "client_credentials"
	tokenRefreshSkew = 30 * time.Second
	tokenMinTTL      = time.Minute
)

type tokenRequest struct {
	GrantType    string `json:"grant_type"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
}

type tokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
}

type tokenEntry struct {
	token     string
	expiresAt time.Time
}

type tokenManager struct {
	httpClient   *http.Client
	clientID     string
	clientSecret string

	mu    sync.Mutex
	cache map[string]tokenEntry

	group singleflight.Group
}

func newTokenManager(httpClient *http.Client, clientID, clientSecret string) *tokenManager {
	return &tokenManager{
		httpClient:   httpClient,
		clientID:     clientID,
		clientSecret: clientSecret,
		cache:        make(map[string]tokenEntry),
	}
}

func (m *tokenManager) configured() bool {
	return strings.TrimSpace(m.clientID) != "" && strings.TrimSpace(m.clientSecret) != ""
}

func (m *tokenManager) token(ctx context.Context, baseURL string) (string, error) {
	tokenURL := strings.TrimRight(baseURL, "/") + tokenPath
	if tok, ok := m.cachedToken(tokenURL); ok {
		return tok, nil
	}
	fetchCtx := context.WithoutCancel(ctx)
	v, err, _ := m.group.Do(tokenURL, func() (any, error) {
		if tok, ok := m.cachedToken(tokenURL); ok {
			return tok, nil
		}
		entry, err := m.fetch(fetchCtx, tokenURL)
		if err != nil {
			return "", err
		}
		m.mu.Lock()
		m.cache[tokenURL] = entry
		m.mu.Unlock()
		return entry.token, nil
	})
	if err != nil {
		return "", err
	}
	return v.(string), nil
}

func (m *tokenManager) cachedToken(tokenURL string) (string, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	entry, ok := m.cache[tokenURL]
	if !ok || entry.token == "" {
		return "", false
	}
	if time.Until(entry.expiresAt) <= tokenRefreshSkew {
		return "", false
	}
	return entry.token, true
}

func (m *tokenManager) invalidate(baseURL string) {
	tokenURL := strings.TrimRight(baseURL, "/") + tokenPath
	m.mu.Lock()
	delete(m.cache, tokenURL)
	m.mu.Unlock()
}

func (m *tokenManager) fetch(ctx context.Context, tokenURL string) (tokenEntry, error) {
	payload, err := json.Marshal(tokenRequest{ // #nosec G117 -- client_secret must be sent in the OAuth2 client-credentials token request body
		GrantType:    grantType,
		ClientID:     m.clientID,
		ClientSecret: m.clientSecret,
	})
	if err != nil {
		return tokenEntry{}, fmt.Errorf("trustguard: marshal token request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, bytes.NewReader(payload))
	if err != nil {
		return tokenEntry{}, fmt.Errorf("trustguard: build token request: %w", err)
	}
	req.Header.Set("Content-Type", contentTypeJSON)
	res, err := m.httpClient.Do(req)
	if err != nil {
		return tokenEntry{}, fmt.Errorf("trustguard: token call: %w", err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, io.LimitReader(res.Body, maxResponseBytes))
		_ = res.Body.Close()
	}()
	raw, err := io.ReadAll(io.LimitReader(res.Body, maxResponseBytes))
	if err != nil {
		return tokenEntry{}, fmt.Errorf("trustguard: read token response: %w", err)
	}
	if res.StatusCode < http.StatusOK || res.StatusCode >= http.StatusMultipleChoices {
		return tokenEntry{}, fmt.Errorf("trustguard: token endpoint status %d", res.StatusCode)
	}
	var out tokenResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		return tokenEntry{}, fmt.Errorf("trustguard: decode token response: %w", err)
	}
	if strings.TrimSpace(out.AccessToken) == "" {
		return tokenEntry{}, fmt.Errorf("trustguard: token endpoint returned empty access_token")
	}
	ttl := time.Duration(out.ExpiresIn) * time.Second
	if ttl < tokenMinTTL {
		ttl = tokenMinTTL
	}
	return tokenEntry{token: out.AccessToken, expiresAt: time.Now().Add(ttl)}, nil
}
