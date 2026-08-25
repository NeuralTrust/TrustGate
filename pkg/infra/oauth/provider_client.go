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

package oauth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	appoauth "github.com/NeuralTrust/TrustGate/pkg/app/oauth"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
)

var _ appoauth.ProviderClient = (*providerClient)(nil)

const defaultProviderTokenTTL = time.Hour

type providerClient struct {
	client *http.Client
}

func NewProviderClient(client *http.Client) appoauth.ProviderClient {
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	return &providerClient{client: client}
}

func (p *providerClient) AuthorizeURL(cfg *registrydomain.MCPAuth, redirectURI, state, challenge string) string {
	base, err := url.Parse(cfg.AuthorizeURL)
	if err != nil || base.Scheme == "" || base.Host == "" {
		// Fall back to string join for non-absolute catalog URLs.
		return authorizeURLJoin(cfg.AuthorizeURL, authorizeQuery(cfg, redirectURI, state, challenge, false))
	}
	q := base.Query()
	for k, vs := range authorizeQuery(cfg, redirectURI, state, challenge, isGoogleHost(base.Hostname())) {
		// Standard OAuth params always win; Google offline defaults only fill gaps
		// so a catalog authorize_url can override access_type/prompt.
		if k == "access_type" || k == "prompt" {
			if q.Get(k) != "" {
				continue
			}
		}
		for _, v := range vs {
			q.Set(k, v)
		}
	}
	base.RawQuery = q.Encode()
	return base.String()
}

func authorizeQuery(cfg *registrydomain.MCPAuth, redirectURI, state, challenge string, google bool) url.Values {
	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", cfg.ClientID)
	q.Set("redirect_uri", redirectURI)
	q.Set("state", state)
	if len(cfg.Scopes) > 0 {
		q.Set("scope", strings.Join(cfg.Scopes, " "))
	}
	if challenge != "" {
		q.Set("code_challenge", challenge)
		q.Set("code_challenge_method", "S256")
	}
	if cfg.Resource != "" {
		q.Set("resource", cfg.Resource)
	}
	// Google only issues a refresh_token with access_type=offline. prompt=consent
	// forces a fresh grant so reconnect after a dead vault row still gets one
	// (Google otherwise reuses the prior approval and omits refresh_token).
	if google {
		q.Set("access_type", "offline")
		q.Set("prompt", "consent")
	}
	return q
}

func authorizeURLJoin(base string, q url.Values) string {
	sep := "?"
	if strings.Contains(base, "?") {
		sep = "&"
	}
	return base + sep + q.Encode()
}

// isGoogleHost reports whether the authorize host is Google's accounts endpoint
// (Workspace MCP, Gmail, Calendar, etc.).
func isGoogleHost(host string) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	return host == "accounts.google.com" || strings.HasSuffix(host, ".accounts.google.com")
}

// isGoogleAuthorizeURL reports whether the authorize endpoint is Google's
// accounts host. Kept for tests and call sites that only have the full URL.
func isGoogleAuthorizeURL(authorizeURL string) bool {
	u, err := url.Parse(authorizeURL)
	if err != nil || u.Host == "" {
		return false
	}
	return isGoogleHost(u.Hostname())
}

func (p *providerClient) ExchangeCode(ctx context.Context, cfg *registrydomain.MCPAuth, code, redirectURI, verifier string) (*appoauth.ProviderToken, error) {
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", redirectURI)
	form.Set("client_id", cfg.ClientID)
	if cfg.ClientSecret != "" {
		form.Set("client_secret", cfg.ClientSecret)
	}
	if verifier != "" {
		form.Set("code_verifier", verifier)
	}
	if cfg.Resource != "" {
		form.Set("resource", cfg.Resource)
	}
	return p.tokenCall(ctx, cfg.TokenURL, form, "", "")
}

func (p *providerClient) Refresh(ctx context.Context, cfg *registrydomain.MCPAuth, refreshToken string) (*appoauth.ProviderToken, error) {
	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", refreshToken)
	form.Set("client_id", cfg.ClientID)
	if cfg.ClientSecret != "" {
		form.Set("client_secret", cfg.ClientSecret)
	}
	if cfg.Resource != "" {
		form.Set("resource", cfg.Resource)
	}
	return p.tokenCall(ctx, cfg.TokenURL, form, "", "")
}

func (p *providerClient) ClientCredentials(ctx context.Context, cfg *registrydomain.MCPAuth) (*appoauth.ProviderToken, error) {
	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	if len(cfg.Scopes) > 0 {
		form.Set("scope", strings.Join(cfg.Scopes, " "))
	}
	if cfg.Resource != "" {
		form.Set("resource", cfg.Resource)
	}
	method := cfg.TokenEndpointAuthMethod
	if method == "" {
		method = registrydomain.TokenEndpointAuthClientSecretBasic
	}
	var basicUser, basicPass string
	switch method {
	case registrydomain.TokenEndpointAuthClientSecretBasic:
		basicUser, basicPass = cfg.ClientID, cfg.ClientSecret
	case registrydomain.TokenEndpointAuthClientSecretPost:
		form.Set("client_id", cfg.ClientID)
		form.Set("client_secret", cfg.ClientSecret)
	default:
		return nil, fmt.Errorf("oauth provider: unsupported token_endpoint_auth_method %q", method)
	}
	return p.tokenCall(ctx, cfg.TokenURL, form, basicUser, basicPass)
}

func (p *providerClient) tokenCall(ctx context.Context, endpoint string, form url.Values, basicUser, basicPass string) (*appoauth.ProviderToken, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	if basicUser != "" {
		req.SetBasicAuth(basicUser, basicPass)
	}
	res, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("oauth provider: token call: %w", err)
	}
	defer func() { _ = res.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("oauth provider: read response: %w", err)
	}
	var doc struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		TokenType    string `json:"token_type"`
		ExpiresIn    int    `json:"expires_in"`
		Scope        string `json:"scope"`
		Error        string `json:"error"`
		ErrorDesc    string `json:"error_description"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("oauth provider: non-JSON token response (status %d)", res.StatusCode)
	}
	if res.StatusCode != http.StatusOK || doc.Error != "" || doc.AccessToken == "" {
		if doc.Error == "invalid_grant" {
			return nil, fmt.Errorf("%w: %s", appoauth.ErrInvalidGrant, doc.ErrorDesc)
		}
		return nil, fmt.Errorf("oauth provider: token exchange failed (%s): %s", doc.Error, doc.ErrorDesc)
	}
	if doc.TokenType != "" && !strings.EqualFold(doc.TokenType, "Bearer") {
		return nil, fmt.Errorf("oauth provider: unsupported token_type %q", doc.TokenType)
	}
	out := &appoauth.ProviderToken{AccessToken: doc.AccessToken, RefreshToken: doc.RefreshToken}
	switch {
	case doc.ExpiresIn > 0:
		out.ExpiresAt = time.Now().Add(time.Duration(doc.ExpiresIn) * time.Second)
	case doc.RefreshToken != "":
		out.ExpiresAt = time.Now().Add(defaultProviderTokenTTL)
	default:
		out.ExpiresAt = time.Now().Add(defaultProviderTokenTTL)
	}
	if doc.Scope != "" {
		out.Scopes = strings.FieldsFunc(doc.Scope, func(r rune) bool { return r == ' ' || r == ',' })
	}
	return out, nil
}
