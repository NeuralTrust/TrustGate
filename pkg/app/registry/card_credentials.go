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

package registry

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	domain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
)

// ClientCredentialsGrant returns an access token for the OAuth client
// credentials in auth.
type ClientCredentialsGrant func(ctx context.Context, auth *domain.MCPAuth) (string, error)

// CloudSigner signs a request to a hosted agent with t's cloud credential,
// and refuses one that is not https to the host of t's endpoint.
type CloudSigner func(ctx context.Context, t *domain.A2ATarget, req *http.Request) error

//go:generate mockery --name=CardCredentials --dir=. --output=./mocks --filename=registry_card_credentials_mock.go --case=underscore --with-expecter
type CardCredentials interface {
	// Authorizer returns what signs the requests that read t's card, or nil
	// to read it anonymously.
	Authorizer(ctx context.Context, t *domain.A2ATarget) (CardAuthorizer, error)
	// CallAuthorizer returns what signs a call to a generic agent's endpoint
	// as the gateway signs it, or false when that credential is a user's
	// (an exchange), which no request has at registration.
	CallAuthorizer(ctx context.Context, t *domain.A2ATarget) (CardAuthorizer, bool, error)
}

var _ CardCredentials = (*cardCredentials)(nil)

type cardCredentials struct {
	grant ClientCredentialsGrant
	sign  CloudSigner
}

// NewCardCredentials returns the card credentials of A2A registries. A
// generic agent's card is read anonymously, or with card_auth "same" with the
// registry's static header or client-credentials token, sent only over https
// to the card's own host. A hosted agent's card is always read with a
// credential: the cloud one signed by sign with auth mode or card_auth cloud,
// else a client-credentials token sent only over https to the agent's host.
func NewCardCredentials(grant ClientCredentialsGrant, sign CloudSigner) CardCredentials {
	return &cardCredentials{grant: grant, sign: sign}
}

func (c *cardCredentials) Authorizer(ctx context.Context, t *domain.A2ATarget) (CardAuthorizer, error) {
	if t.Provider == domain.A2AProviderGeneric {
		return c.generic(ctx, t)
	}
	if t.Auth.Mode == domain.A2AAuthModeCloud || t.CardAuth == domain.A2ACardAuthCloud {
		return func(r *http.Request) error {
			agentCoreSession(t, r)
			if err := c.sign(r.Context(), t, r); err != nil {
				return fmt.Errorf("%w: card credential: %w", domain.ErrAgentCardUnavailable, err)
			}
			return nil
		}, nil
	}
	if t.Auth.Mode == domain.MCPAuthModeClientCredentials || t.CardAuth == domain.A2ACardAuthClientCredentials {
		authorize, err := c.bearer(ctx, t.Auth, cardHost(t.Endpoint()))
		if err != nil {
			return nil, err
		}
		return func(r *http.Request) error {
			agentCoreSession(t, r)
			return authorize(r)
		}, nil
	}
	return nil, fmt.Errorf("%w: a %s agent needs a credential to read its card", domain.ErrAgentCardUnavailable, t.Provider)
}

func (c *cardCredentials) CallAuthorizer(ctx context.Context, t *domain.A2ATarget) (CardAuthorizer, bool, error) {
	host := cardHost(t.Endpoint())
	switch t.Auth.Mode {
	case domain.MCPAuthModeNone:
		return nil, true, nil
	case domain.MCPAuthModeStatic:
		return toHost(host, t.Auth.Header, t.Auth.Value), true, nil
	case domain.MCPAuthModeClientCredentials:
		token, err := c.grant(ctx, t.Auth)
		if err != nil {
			return nil, false, fmt.Errorf("%w: the agent's credential: %w", domain.ErrAgentEndpointUnavailable, err)
		}
		return toHost(host, "Authorization", "Bearer "+token), true, nil
	default:
		return nil, false, nil
	}
}

// toHost sets header on a request to host only: the endpoint's own, over the
// scheme the gateway will call it with.
func toHost(host, header, value string) CardAuthorizer {
	return func(r *http.Request) error {
		if !strings.EqualFold(r.URL.Host, host) {
			return fmt.Errorf("%w: the agent's credential is sent only to %s", domain.ErrAgentEndpointUnavailable, host)
		}
		r.Header.Set(header, value)
		return nil
	}
}

func (c *cardCredentials) generic(ctx context.Context, t *domain.A2ATarget) (CardAuthorizer, error) {
	if t.CardAuth != domain.A2ACardAuthSame {
		return nil, nil
	}
	if t.Auth.Mode == domain.MCPAuthModeClientCredentials {
		return c.bearer(ctx, t.Auth, cardHost(t.CardURL))
	}
	return onlyTo(cardHost(t.CardURL), t.Auth.Header, t.Auth.Value), nil
}

func (c *cardCredentials) bearer(ctx context.Context, auth *domain.MCPAuth, host string) (CardAuthorizer, error) {
	token, err := c.grant(ctx, auth)
	if err != nil {
		return nil, fmt.Errorf("%w: card credential: %w", domain.ErrAgentCardUnavailable, err)
	}
	return onlyTo(host, "Authorization", "Bearer "+token), nil
}

// agentCoreSession gives an AgentCore card read the runtime session AgentCore
// requires, before the request is signed.
func agentCoreSession(t *domain.A2ATarget, r *http.Request) {
	if t.Provider == domain.A2AProviderBedrockAgentCore {
		r.Header.Set(domain.AgentCoreSessionHeader, domain.NewAgentCoreSession())
	}
}

func onlyTo(host, header, value string) CardAuthorizer {
	return func(r *http.Request) error {
		if r.URL.Scheme != "https" || !strings.EqualFold(r.URL.Host, host) {
			return fmt.Errorf("%w: the card credential is sent only over https to %s", domain.ErrAgentCardUnavailable, host)
		}
		r.Header.Set(header, value)
		return nil
	}
}

func cardHost(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return u.Host
}
