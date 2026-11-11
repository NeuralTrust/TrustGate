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

package a2a

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"time"

	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/app/identity/sts"
	appoauth "github.com/NeuralTrust/TrustGate/pkg/app/oauth"
	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/domain/identity"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	"golang.org/x/sync/singleflight"
)

// Reasons of the -32092 answers the credentials give.
const (
	ReasonAuthUnsupported         = "auth_unsupported"
	ReasonIdentityExchangeFailed  = "identity_exchange_failed"
	ReasonSigningKeyUnavailable   = "signing_key_unavailable"
	ReasonClientCredentialsFailed = "client_credentials_failed"
)

// Subject kinds of IdentityTrace.
const (
	SubjectUser = "user"
	SubjectApp  = "app"
)

const (
	defaultTokenTTL  = time.Hour
	tokenRefreshSkew = 30 * time.Second
)

// IdentityTrace is how a call identified itself to the agent: the identity
// mode and whether the subject is a user or the application.
type IdentityTrace struct {
	Mode        string
	SubjectKind string
}

// Credentials builds the credential an A2A registry's auth mode sends.
type Credentials struct {
	exchanger    sts.Exchanger
	provider     appoauth.ProviderClient
	ephemeralKey bool

	tokens sync.Map
	flight singleflight.Group
}

type cachedToken struct {
	value     string
	expiresAt time.Time
	updatedAt time.Time
}

// NewCredentials builds the agent plane's credentials. With ephemeralKey the
// gateway's signing key is not shared between pods, so delegation, whose
// tokens another pod could not verify, is refused.
func NewCredentials(exchanger sts.Exchanger, provider appoauth.ProviderClient, ephemeralKey bool) *Credentials {
	return &Credentials{exchanger: exchanger, provider: provider, ephemeralKey: ephemeralKey}
}

// For returns the headers that carry the credential of a call by p to reg.
func (c *Credentials) For(ctx context.Context, rc *appconsumer.RoutableConsumer, reg *registrydomain.Registry, p *identity.Principal) (http.Header, IdentityTrace, *RPCError) {
	auth := reg.A2ATarget.Auth
	app := consumerdomain.AppSubject(rc.Consumer.ID)
	trace := IdentityTrace{Mode: string(auth.Mode), SubjectKind: SubjectUser}
	if p == nil || p.Subject == app {
		trace.SubjectKind = SubjectApp
	}
	header := http.Header{}
	switch auth.Mode {
	case registrydomain.MCPAuthModeNone:
		return header, trace, nil
	case registrydomain.MCPAuthModeStatic:
		header.Set(auth.Header, auth.Value)
		return header, trace, nil
	case registrydomain.MCPAuthModeClientCredentials:
		token, err := c.clientCredentials(ctx, reg)
		if err != nil {
			return nil, trace, GatewayFailure(ReasonClientCredentialsFailed)
		}
		header.Set("Authorization", "Bearer "+token)
		return header, trace, nil
	case registrydomain.MCPAuthModeExchange:
		trace.Mode = string(auth.Pattern)
		cfg := *auth
		if cfg.Audience == "" {
			cfg.Audience = reg.A2ATarget.Endpoint()
		}
		if cfg.Pattern == registrydomain.ExchangeDelegation {
			if c.ephemeralKey {
				return nil, trace, GatewayFailure(ReasonSigningKeyUnavailable)
			}
			if trace.SubjectKind == SubjectApp {
				cfg.Pattern = registrydomain.ExchangeImpersonation
			} else {
				cfg.Actor = app
			}
		}
		var subject string
		if p != nil {
			subject = p.Subject
		}
		key := "a2a|" + reg.ID.String() + "|" + subject + "|" + cfg.Audience + "|" + string(cfg.Pattern)
		token, err := c.exchanger.Exchange(ctx, p, rc.Consumer.GatewayID, &cfg, key)
		switch {
		case errors.Is(err, sts.ErrNoUserIdentity), errors.Is(err, sts.ErrIdentityIssuerMismatch):
			return nil, trace, IdentityRequired()
		case err != nil:
			return nil, trace, GatewayFailure(ReasonIdentityExchangeFailed)
		}
		header.Set("Authorization", "Bearer "+token.AccessToken)
		return header, trace, nil
	}
	return nil, trace, GatewayFailure(ReasonAuthUnsupported)
}

// clientCredentials returns the registry's client_credentials token, cached
// until shortly before it expires or the registry changes.
func (c *Credentials) clientCredentials(ctx context.Context, reg *registrydomain.Registry) (string, error) {
	key := reg.ID.String()
	if token, ok := c.cached(key, reg.UpdatedAt); ok {
		return token, nil
	}
	v, err, _ := c.flight.Do(key+"|"+reg.UpdatedAt.String(), func() (any, error) {
		if token, ok := c.cached(key, reg.UpdatedAt); ok {
			return token, nil
		}
		tok, err := c.provider.ClientCredentials(ctx, reg.A2ATarget.Auth)
		if err != nil {
			return nil, err
		}
		if tok.AccessToken == "" {
			return nil, errors.New("a2a: client_credentials returned no access token")
		}
		expiresAt := tok.ExpiresAt
		if expiresAt.IsZero() {
			expiresAt = time.Now().Add(defaultTokenTTL)
		}
		c.tokens.Store(key, &cachedToken{value: tok.AccessToken, expiresAt: expiresAt, updatedAt: reg.UpdatedAt})
		return tok.AccessToken, nil
	})
	if err != nil {
		return "", err
	}
	token, _ := v.(string)
	return token, nil
}

func (c *Credentials) cached(key string, updatedAt time.Time) (string, bool) {
	v, ok := c.tokens.Load(key)
	if !ok {
		return "", false
	}
	t, _ := v.(*cachedToken)
	if !t.updatedAt.Equal(updatedAt) || !time.Now().Add(tokenRefreshSkew).Before(t.expiresAt) {
		return "", false
	}
	return t.value, true
}
