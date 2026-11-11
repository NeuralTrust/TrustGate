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

//go:generate mockery --name=CardCredentials --dir=. --output=./mocks --filename=registry_card_credentials_mock.go --case=underscore --with-expecter
type CardCredentials interface {
	// Authorizer returns what signs the requests that read t's card, or nil
	// to read it anonymously.
	Authorizer(ctx context.Context, t *domain.A2ATarget) (CardAuthorizer, error)
}

var _ CardCredentials = (*genericCardCredentials)(nil)

type genericCardCredentials struct {
	grant ClientCredentialsGrant
}

// NewCardCredentials returns the card credentials of generic agents: none, or
// with card_auth "same" the registry's static header or client-credentials
// token, sent only over https to the card's own host. Hosted providers are
// refused until their signers are wired.
func NewCardCredentials(grant ClientCredentialsGrant) CardCredentials {
	return &genericCardCredentials{grant: grant}
}

func (c *genericCardCredentials) Authorizer(ctx context.Context, t *domain.A2ATarget) (CardAuthorizer, error) {
	if t.Provider != domain.A2AProviderGeneric {
		return nil, fmt.Errorf("%w: reading the card of a %s agent is not supported yet", domain.ErrAgentCardUnavailable, t.Provider)
	}
	if t.CardAuth != domain.A2ACardAuthSame {
		return nil, nil
	}
	header, value := t.Auth.Header, t.Auth.Value
	if t.Auth.Mode == domain.MCPAuthModeClientCredentials {
		token, err := c.grant(ctx, t.Auth)
		if err != nil {
			return nil, fmt.Errorf("%w: card credential: %w", domain.ErrAgentCardUnavailable, err)
		}
		header, value = "Authorization", "Bearer "+token
	}
	host := cardHost(t.CardURL)
	return func(r *http.Request) error {
		if r.URL.Scheme != "https" || !strings.EqualFold(r.URL.Host, host) {
			return fmt.Errorf("%w: the card credential is sent only over https to %s", domain.ErrAgentCardUnavailable, host)
		}
		r.Header.Set(header, value)
		return nil
	}, nil
}

func cardHost(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return u.Host
}
