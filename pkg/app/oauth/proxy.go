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
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	appauth "github.com/NeuralTrust/AgentGateway/pkg/app/auth"
	appconsumer "github.com/NeuralTrust/AgentGateway/pkg/app/consumer"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
	"github.com/golang-jwt/jwt/v5"
)

var _ AuthProxy = (*authProxy)(nil)

type authProxy struct {
	credentials appauth.CredentialFinder
	paths       appconsumer.PathResolver
	client      *http.Client
	store       FlowStore
	idp         *metadataService
	chainer     ConsentChainer
}

func NewAuthProxy(
	credentials appauth.CredentialFinder,
	paths appconsumer.PathResolver,
	client *http.Client,
	store FlowStore,
	chainer ConsentChainer,
) AuthProxy {
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	return &authProxy{
		credentials: credentials,
		paths:       paths,
		client:      client,
		store:       store,
		idp:         &metadataService{credentials: credentials, client: client, asCache: map[string]asCacheEntry{}},
		chainer:     chainer,
	}
}

func (p *authProxy) Authorize(ctx context.Context, baseURL string, req AuthorizeRequest) (string, error) {
	if req.ResponseType != "code" {
		return "", oauthErr("unsupported_response_type", "only response_type=code is supported")
	}
	if req.RedirectURI == "" {
		return "", oauthErr("invalid_request", "redirect_uri is required")
	}
	if req.CodeChallenge == "" || (req.CodeChallengeMethod != "" && req.CodeChallengeMethod != "S256") {
		return "", oauthErr("invalid_request", "PKCE with code_challenge_method=S256 is required")
	}
	auth, err := p.authForResource(ctx, req.Resource)
	if err != nil {
		return "", err
	}
	cfg := auth.Config.OAuth2
	if err := p.validateClientRedirect(ctx, req.ClientID, req.RedirectURI); err != nil {
		return "", err
	}
	endpoints, err := p.idpEndpoints(ctx, cfg.Issuer)
	if err != nil {
		return "", err
	}

	state, err := randomToken()
	if err != nil {
		return "", err
	}
	verifier, err := randomToken()
	if err != nil {
		return "", err
	}
	pending := PendingAuthorization{
		ClientID:            req.ClientID,
		RedirectURI:         req.RedirectURI,
		State:               req.State,
		CodeChallenge:       req.CodeChallenge,
		CodeChallengeMethod: "S256",
		Scope:               req.Scope,
		CodeVerifier:         verifier,
		Resource:            req.Resource,
		AuthID:              auth.ID.String(),
	}
	if err := p.store.SavePending(ctx, state, pending); err != nil {
		return "", fmt.Errorf("oauth: park authorization: %w", err)
	}

	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", cfg.ClientID)
	q.Set("redirect_uri", baseURL+CallbackPath)
	q.Set("state", state)
	q.Set("code_challenge", s256(verifier))
	q.Set("code_challenge_method", "S256")
	if scope := mergeScopes(req.Scope, cfg.RequiredScopes); scope != "" {
		q.Set("scope", scope)
	}
	return endpoints.authorize + "?" + q.Encode(), nil
}

func (p *authProxy) Callback(ctx context.Context, baseURL, state, code, idpErr, idpErrDesc string) (string, error) {
	pending, err := p.store.TakePending(ctx, state)
	if err != nil {
		return "", fmt.Errorf("oauth: load pending authorization: %w", err)
	}
	if pending == nil {
		return "", oauthErr("invalid_request", "unknown or expired authorization request")
	}
	if idpErr != "" {
		return clientRedirect(pending.RedirectURI, url.Values{
			"error":             {idpErr},
			"error_description": {idpErrDesc},
		}, pending.State), nil
	}

	auth, err := p.pendingAuth(ctx, pending)
	if err != nil {
		return "", err
	}
	cfg := auth.Config.OAuth2
	endpoints, err := p.idpEndpoints(ctx, cfg.Issuer)
	if err != nil {
		return "", err
	}

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", baseURL+CallbackPath)
	form.Set("client_id", cfg.ClientID)
	form.Set("code_verifier", pending.CodeVerifier)
	if cfg.ClientSecret != "" {
		form.Set("client_secret", cfg.ClientSecret)
	}
	token, err := p.idpTokenCall(ctx, endpoints.token, form)
	if err != nil {
		return "", err
	}

	gwCode, err := randomToken()
	if err != nil {
		return "", err
	}
	grant := CodeGrant{
		ClientID:      pending.ClientID,
		RedirectURI:   pending.RedirectURI,
		CodeChallenge: pending.CodeChallenge,
		Token:         token,
	}
	if err := p.store.SaveCode(ctx, gwCode, grant); err != nil {
		return "", fmt.Errorf("oauth: store code grant: %w", err)
	}
	resume := clientRedirect(pending.RedirectURI, url.Values{"code": {gwCode}}, pending.State)
	if detour := p.consentDetour(ctx, baseURL, auth.GatewayID, pending.Resource, token, resume); detour != "" {
		return detour, nil
	}
	return resume, nil
}

func (p *authProxy) consentDetour(ctx context.Context, baseURL string, gatewayID ids.GatewayID, resource string, token map[string]any, resume string) string {
	if p.chainer == nil {
		return ""
	}
	sub := subjectFromToken(token)
	if sub == "" {
		slog.Warn("oauth: consent chaining skipped: no subject in IdP access token")
		return ""
	}
	detour, err := p.chainer.ChainURL(ctx, baseURL, gatewayID, resource, sub, resume)
	if err != nil {
		slog.Warn("oauth: consent chaining skipped", "error", err)
		return ""
	}
	if detour != "" {
		slog.Info("oauth: detouring to downstream consent page", "sub", sub, "resource", resource)
	}
	return detour
}

func subjectFromToken(token map[string]any) string {
	raw, _ := token["access_token"].(string)
	if raw == "" {
		return ""
	}
	claims := jwt.MapClaims{}
	if _, _, err := jwt.NewParser().ParseUnverified(raw, claims); err != nil {
		return ""
	}
	if oid, ok := claims["oid"].(string); ok && oid != "" {
		return oid
	}
	sub, _ := claims.GetSubject()
	return sub
}

func (p *authProxy) Exchange(ctx context.Context, baseURL string, req TokenRequest) (map[string]any, error) {
	switch req.GrantType {
	case "authorization_code":
		return p.exchangeCode(ctx, req)
	case "refresh_token":
		return p.refresh(ctx, req)
	default:
		return nil, oauthErr("unsupported_grant_type", "supported: authorization_code, refresh_token")
	}
}

func (p *authProxy) exchangeCode(ctx context.Context, req TokenRequest) (map[string]any, error) {
	if req.Code == "" {
		return nil, oauthErr("invalid_request", "code is required")
	}
	grant, err := p.store.TakeCode(ctx, req.Code)
	if err != nil {
		return nil, fmt.Errorf("oauth: load code grant: %w", err)
	}
	if grant == nil {
		return nil, oauthErr("invalid_grant", "unknown, expired or already used code")
	}
	if grant.RedirectURI != req.RedirectURI {
		return nil, oauthErr("invalid_grant", "redirect_uri mismatch")
	}
	if grant.ClientID != "" && req.ClientID != "" && grant.ClientID != req.ClientID {
		return nil, oauthErr("invalid_client", "client_id mismatch")
	}
	if req.CodeVerifier == "" || s256(req.CodeVerifier) != grant.CodeChallenge {
		return nil, oauthErr("invalid_grant", "PKCE verification failed")
	}
	return grant.Token, nil
}

func (p *authProxy) refresh(ctx context.Context, req TokenRequest) (map[string]any, error) {
	if req.RefreshToken == "" {
		return nil, oauthErr("invalid_request", "refresh_token is required")
	}
	auth, err := p.authForResource(ctx, req.Resource)
	if err != nil {
		return nil, err
	}
	cfg := auth.Config.OAuth2
	endpoints, err := p.idpEndpoints(ctx, cfg.Issuer)
	if err != nil {
		return nil, err
	}
	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", req.RefreshToken)
	form.Set("client_id", cfg.ClientID)
	if cfg.ClientSecret != "" {
		form.Set("client_secret", cfg.ClientSecret)
	}
	if scope := mergeScopes("", cfg.RequiredScopes); scope != "" {
		form.Set("scope", scope)
	}
	return p.idpTokenCall(ctx, endpoints.token, form)
}

type idpEndpoints struct {
	authorize string
	token     string
}

func (p *authProxy) idpEndpoints(ctx context.Context, issuer string) (*idpEndpoints, error) {
	doc, err := p.idp.fetchASMetadata(ctx, issuer)
	if err != nil {
		return nil, fmt.Errorf("oauth: resolve IdP endpoints: %w", err)
	}
	authorize, _ := doc["authorization_endpoint"].(string)
	token, _ := doc["token_endpoint"].(string)
	if authorize == "" || token == "" {
		return nil, fmt.Errorf("oauth: IdP metadata for %s lacks authorization/token endpoints", issuer)
	}
	return &idpEndpoints{authorize: authorize, token: token}, nil
}

func (p *authProxy) idpTokenCall(ctx context.Context, endpoint string, form url.Values) (map[string]any, error) {
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	res, err := p.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("oauth: IdP token call: %w", err)
	}
	defer func() { _ = res.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("oauth: read IdP token response: %w", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("oauth: IdP token response is not JSON (status %d)", res.StatusCode)
	}
	if res.StatusCode != http.StatusOK {
		code, _ := doc["error"].(string)
		desc, _ := doc["error_description"].(string)
		if code == "" {
			code = "server_error"
		}
		return nil, oauthErr(code, desc)
	}
	return doc, nil
}
