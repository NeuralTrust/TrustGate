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
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/NeuralTrust/TrustGate/pkg/domain/secretref"

	domain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
)

// FetchedCard is an agent card as received and the URL that served it.
type FetchedCard struct {
	URL  string
	Card json.RawMessage
}

// CardAuthorizer sets the credential a card request carries. A nil
// authorizer reads the card anonymously.
type CardAuthorizer func(*http.Request) error

//go:generate mockery --name=CardFetcher --dir=. --output=./mocks --filename=registry_card_fetcher_mock.go --case=underscore --with-expecter
type CardFetcher interface {
	// Resolve reads the card at cardURL when it names a card document, or
	// else the first well-known card path under it that serves a JSON object.
	Resolve(ctx context.Context, cardURL string, authorize CardAuthorizer) (*FetchedCard, error)
	// Fetch reads the card at exactly cardURL.
	Fetch(ctx context.Context, cardURL string, authorize CardAuthorizer) (*FetchedCard, error)
}

// agentCards reads and pins the cards of A2A registries.
type agentCards struct {
	fetcher     CardFetcher
	credentials CardCredentials
	// secrets resolves the secret references of a target whose card is read
	// with its auth, once refs has accepted them as a write would; either nil
	// refuses such a read.
	secrets RegistryMaterializer
	refs    SecretRefValidator
}

// fetch reads t's card, a target of gatewayID, with its card credential.
// With resolve, a generic agent's card is resolved from card_url; otherwise
// it is read from the pinned or derived location.
func (a agentCards) fetch(ctx context.Context, gatewayID ids.GatewayID, t *domain.A2ATarget, resolve bool) (*FetchedCard, error) {
	credTarget, err := a.withSecrets(ctx, gatewayID, t)
	if err != nil {
		return nil, err
	}
	authorize, err := a.credentials.Authorizer(ctx, credTarget)
	if err != nil {
		return nil, err
	}
	if resolve && t.Provider == domain.A2AProviderGeneric {
		return a.fetcher.Resolve(ctx, t.CardURL, authorize)
	}
	return a.fetcher.Fetch(ctx, t.CardLocation(), authorize)
}

// pin resolves t's card and pins it.
func (a agentCards) pin(ctx context.Context, gatewayID ids.GatewayID, t *domain.A2ATarget) error {
	card, err := a.fetch(ctx, gatewayID, t, true)
	if err != nil {
		return err
	}
	return t.Pin(card.URL, card.Card, time.Now())
}

// withSecrets returns t with the secret references of its auth resolved when
// the card is read with that auth, and t itself otherwise. A reference that
// cannot be resolved here, as on a control plane without stores, refuses the
// read rather than sending the reference as the credential; the message says
// so, since on a gateway served by its own data planes it stays refused.
func (a agentCards) withSecrets(ctx context.Context, gatewayID ids.GatewayID, t *domain.A2ATarget) (*domain.A2ATarget, error) {
	if t.Auth == nil || !cardReadUsesAuth(t) || (!secretref.IsRef(t.Auth.Value) && !secretref.IsRef(t.Auth.ClientSecret)) {
		return t, nil
	}
	if a.secrets == nil || a.refs == nil {
		return nil, fmt.Errorf("%w: the card is read with a secret reference this plane cannot resolve", domain.ErrSecretUnavailable)
	}
	// Only the auth is read: the card request carries no static header, so a
	// header reference that does not resolve must not refuse the read.
	authOnly := *t
	authOnly.Headers = nil
	probe := &domain.Registry{GatewayID: gatewayID, Type: domain.TypeA2A, A2ATarget: &authOnly}
	// The card URL can come from the caller, so the reference must pass the
	// write checks (scope, store, allowed path) before its value is read and
	// sent there.
	if _, err := a.refs.ValidateRegistry(ctx, probe, nil); err != nil {
		return nil, err
	}
	resolved := a.secrets.Registries(ctx, gatewayID, map[ids.RegistryID]*domain.Registry{probe.ID: probe})[probe.ID]
	if resolved == nil || resolved.CredentialUnavailable() {
		return nil, fmt.Errorf("%w: the card credential's secret reference did not resolve", domain.ErrSecretUnavailable)
	}
	return resolved.A2ATarget, nil
}

// cardReadUsesAuth reports whether reading t's card sends its auth: a generic
// agent's with card_auth "same", a hosted agent's unless it is signed with
// the cloud credential.
func cardReadUsesAuth(t *domain.A2ATarget) bool {
	if t.Provider == domain.A2AProviderGeneric {
		return t.CardAuth == domain.A2ACardAuthSame
	}
	return t.Auth.Mode != domain.A2AAuthModeCloud && t.CardAuth != domain.A2ACardAuthCloud
}
