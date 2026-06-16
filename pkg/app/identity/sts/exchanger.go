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
	"errors"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"

	appauth "github.com/NeuralTrust/AgentGateway/pkg/app/auth"
	authdomain "github.com/NeuralTrust/AgentGateway/pkg/domain/auth"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/identity"
	registrydomain "github.com/NeuralTrust/AgentGateway/pkg/domain/registry"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/sync/singleflight"
)

var (
	ErrInteractionRequired = errors.New("sts: interaction required")
	ErrNoUserIdentity      = errors.New("sts: exchange requires an inbound user token")
)

const DefaultTokenTTL = 5 * time.Minute

type Token struct {
	AccessToken string
	TokenType   string
	ExpiresAt   time.Time
}

//go:generate mockery --name=Exchanger --dir=. --output=./mocks --filename=sts_exchanger_mock.go --case=underscore --with-expecter
type Exchanger interface {
	Exchange(ctx context.Context, principal *identity.Principal, cfg *registrydomain.MCPAuth, cacheKey string) (*Token, error)
}

var _ Exchanger = (*exchanger)(nil)

type exchanger struct {
	signer      TokenSigner
	credentials appauth.CredentialFinder
	idp         IdPTokenClient

	sf        singleflight.Group
	mu        sync.Mutex
	cache     map[string]*Token
	lastSweep time.Time
}

func NewExchanger(signer TokenSigner, credentials appauth.CredentialFinder, idp IdPTokenClient) Exchanger {
	return &exchanger{
		signer:      signer,
		credentials: credentials,
		idp:         idp,
		cache:       map[string]*Token{},
	}
}

const refreshSkew = 30 * time.Second

func (e *exchanger) Exchange(ctx context.Context, principal *identity.Principal, cfg *registrydomain.MCPAuth, cacheKey string) (*Token, error) {
	if principal == nil {
		return nil, ErrNoUserIdentity
	}
	if t, ok := e.cached(cacheKey); ok {
		return t, nil
	}
	v, err, _ := e.sf.Do(cacheKey, func() (any, error) {
		if t, ok := e.cached(cacheKey); ok {
			return t, nil
		}
		token, err := e.exchange(ctx, principal, cfg)
		if err != nil {
			return nil, err
		}
		e.mu.Lock()
		e.sweepLocked()
		e.cache[cacheKey] = token
		e.mu.Unlock()
		return token, nil
	})
	if err != nil {
		return nil, err
	}
	token, ok := v.(*Token)
	if !ok {
		return nil, errors.New("sts: unexpected singleflight result type")
	}
	return token, nil
}

func (e *exchanger) cached(cacheKey string) (*Token, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if t, ok := e.cache[cacheKey]; ok && time.Now().Add(refreshSkew).Before(t.ExpiresAt) {
		return t, true
	}
	return nil, false
}

func (e *exchanger) exchange(ctx context.Context, principal *identity.Principal, cfg *registrydomain.MCPAuth) (*Token, error) {
	switch cfg.Pattern {
	case registrydomain.ExchangeImpersonation:
		return e.mint(principal, cfg, false)
	case registrydomain.ExchangeDelegation:
		return e.mint(principal, cfg, true)
	case registrydomain.ExchangeOBO:
		return e.entraOBO(ctx, principal, cfg)
	case registrydomain.ExchangeTokenExchange:
		return e.tokenExchange(ctx, principal, cfg)
	default:
		return nil, fmt.Errorf("sts: unknown exchange pattern %q", cfg.Pattern)
	}
}

const cacheSweepInterval = time.Minute

func (e *exchanger) sweepLocked() {
	now := time.Now()
	if now.Sub(e.lastSweep) < cacheSweepInterval {
		return
	}
	e.lastSweep = now
	for k, t := range e.cache {
		if now.After(t.ExpiresAt) {
			delete(e.cache, k)
		}
	}
}

func (e *exchanger) mint(principal *identity.Principal, cfg *registrydomain.MCPAuth, delegation bool) (*Token, error) {
	claims := jwt.MapClaims{
		"sub": principal.Subject,
		"aud": cfg.Audience,
	}
	if principal.Issuer != "" {
		claims["orig_iss"] = principal.Issuer
	}
	if len(principal.Scopes) > 0 {
		claims["scope"] = strings.Join(principal.Scopes, " ")
	}
	if delegation {
		claims["act"] = map[string]any{"sub": cfg.Actor}
	}
	signed, err := e.signer.MintClaims(claims, DefaultTokenTTL)
	if err != nil {
		return nil, err
	}
	return &Token{AccessToken: signed, TokenType: "Bearer", ExpiresAt: time.Now().Add(DefaultTokenTTL)}, nil
}

func (e *exchanger) entraOBO(ctx context.Context, principal *identity.Principal, cfg *registrydomain.MCPAuth) (*Token, error) {
	if principal.RawToken == "" || principal.Method != identity.MethodJWT {
		return nil, ErrNoUserIdentity
	}
	idp, err := e.idpFor(ctx, principal.Issuer)
	if err != nil {
		return nil, err
	}
	form := url.Values{}
	form.Set("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer")
	form.Set("requested_token_use", "on_behalf_of")
	form.Set("assertion", principal.RawToken)
	form.Set("scope", cfg.Scope)
	form.Set("client_id", idp.ClientID)
	form.Set("client_secret", idp.ClientSecret)
	return e.idp.Call(ctx, principal.Issuer, form)
}

func (e *exchanger) tokenExchange(ctx context.Context, principal *identity.Principal, cfg *registrydomain.MCPAuth) (*Token, error) {
	if principal.RawToken == "" ||
		(principal.Method != identity.MethodJWT && principal.Method != identity.MethodIntrospection) {
		return nil, ErrNoUserIdentity
	}
	idp, err := e.idpFor(ctx, principal.Issuer)
	if err != nil {
		return nil, err
	}
	form := url.Values{}
	form.Set("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange")
	form.Set("subject_token", principal.RawToken)
	form.Set("subject_token_type", "urn:ietf:params:oauth:token-type:access_token")
	form.Set("audience", cfg.Audience)
	if cfg.Scope != "" {
		form.Set("scope", cfg.Scope)
	}
	form.Set("client_id", idp.ClientID)
	form.Set("client_secret", idp.ClientSecret)
	return e.idp.Call(ctx, principal.Issuer, form)
}

func (e *exchanger) idpFor(ctx context.Context, issuer string) (*authdomain.OAuth2Config, error) {
	auths, err := e.credentials.OAuth2Auths(ctx)
	if err != nil {
		return nil, fmt.Errorf("sts: load oauth2 auths: %w", err)
	}
	for _, a := range auths {
		if a.Config.OAuth2 != nil && a.Config.OAuth2.Issuer == issuer {
			if a.Config.OAuth2.ClientID == "" || a.Config.OAuth2.ClientSecret == "" {
				return nil, fmt.Errorf("sts: oauth2 auth for %s lacks client_id/client_secret needed for exchange", issuer)
			}
			return a.Config.OAuth2, nil
		}
	}
	return nil, fmt.Errorf("sts: no oauth2 auth configured for issuer %s", issuer)
}
