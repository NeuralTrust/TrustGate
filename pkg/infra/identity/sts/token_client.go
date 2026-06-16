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

package sts

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	appsts "github.com/NeuralTrust/AgentGateway/pkg/app/identity/sts"
)

var _ appsts.IdPTokenClient = (*TokenClient)(nil)

type TokenClient struct {
	client *http.Client

	mu        sync.Mutex
	endpoints map[string]endpointEntry
}

type endpointEntry struct {
	tokenEndpoint string
	fetchedAt     time.Time
}

const endpointTTL = time.Hour

func NewTokenClient(client *http.Client) *TokenClient {
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	return &TokenClient{client: client, endpoints: map[string]endpointEntry{}}
}

func (c *TokenClient) Call(ctx context.Context, issuer string, form url.Values) (*appsts.Token, error) {
	endpoint, err := c.tokenEndpointFor(ctx, issuer)
	if err != nil {
		return nil, err
	}
	return c.tokenCall(ctx, endpoint, form)
}

func (c *TokenClient) tokenEndpointFor(ctx context.Context, issuer string) (string, error) {
	c.mu.Lock()
	if ent, ok := c.endpoints[issuer]; ok && time.Since(ent.fetchedAt) < endpointTTL {
		c.mu.Unlock()
		return ent.tokenEndpoint, nil
	}
	c.mu.Unlock()

	endpoint := c.discoverTokenEndpoint(ctx, issuer)
	if endpoint == "" {
		if fb, ok := entraTokenEndpoint(issuer); ok {
			return fb, nil
		}
		return "", fmt.Errorf("sts: OIDC discovery failed for issuer %s and no known token endpoint convention applies", issuer)
	}
	c.mu.Lock()
	c.endpoints[issuer] = endpointEntry{tokenEndpoint: endpoint, fetchedAt: time.Now()}
	c.mu.Unlock()
	return endpoint, nil
}

func (c *TokenClient) discoverTokenEndpoint(ctx context.Context, issuer string) string {
	wellKnown := strings.TrimSuffix(issuer, "/") + "/.well-known/openid-configuration"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, wellKnown, nil)
	if err != nil {
		return ""
	}
	res, err := c.client.Do(req)
	if err != nil {
		return ""
	}
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusOK {
		return ""
	}
	var doc struct {
		TokenEndpoint string `json:"token_endpoint"`
	}
	if err := json.NewDecoder(io.LimitReader(res.Body, 1<<20)).Decode(&doc); err != nil {
		return ""
	}
	return doc.TokenEndpoint
}

func entraTokenEndpoint(issuer string) (string, bool) {
	base := strings.TrimSuffix(issuer, "/")
	if strings.HasPrefix(base, "https://login.microsoftonline.com/") {
		return strings.TrimSuffix(base, "/v2.0") + "/oauth2/v2.0/token", true
	}
	return "", false
}

func (c *TokenClient) tokenCall(ctx context.Context, endpoint string, form url.Values) (*appsts.Token, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	res, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("sts: IdP exchange call: %w", err)
	}
	defer func() { _ = res.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("sts: read IdP response: %w", err)
	}
	var doc struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int    `json:"expires_in"`
		Error       string `json:"error"`
		ErrorDesc   string `json:"error_description"`
		Claims      string `json:"claims"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("sts: IdP response is not JSON (status %d)", res.StatusCode)
	}
	if res.StatusCode != http.StatusOK {
		if doc.Error == "interaction_required" || doc.Error == "invalid_grant" {
			return nil, fmt.Errorf("%w: %s", appsts.ErrInteractionRequired, doc.ErrorDesc)
		}
		return nil, fmt.Errorf("sts: IdP exchange failed (%s): %s", doc.Error, doc.ErrorDesc)
	}
	if doc.AccessToken == "" {
		return nil, fmt.Errorf("sts: IdP returned 200 with no access_token")
	}
	ttl := time.Duration(doc.ExpiresIn) * time.Second
	if ttl <= 0 {
		ttl = appsts.DefaultTokenTTL
	}
	tokenType := doc.TokenType
	if tokenType == "" {
		tokenType = "Bearer"
	}
	return &appsts.Token{AccessToken: doc.AccessToken, TokenType: tokenType, ExpiresAt: time.Now().Add(ttl)}, nil
}
