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
	"net/http"
	"time"

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
	// Probe checks that endpoint answers A2A JSON-RPC in version v: it asks
	// for a task that does not exist, which an agent answers with a JSON-RPC
	// error and changes nothing.
	Probe(ctx context.Context, endpoint string, v domain.A2AProtocolVersion, authorize CardAuthorizer) error
}

// agentCards reads and pins the cards of A2A registries.
type agentCards struct {
	fetcher     CardFetcher
	credentials CardCredentials
}

// fetch reads t's card with its card credential. With resolve, a generic
// agent's card is resolved from card_url; otherwise it is read from the
// pinned or derived location.
func (a agentCards) fetch(ctx context.Context, t *domain.A2ATarget, resolve bool) (*FetchedCard, error) {
	// An agent reached through its provider's API publishes no card: the
	// gateway builds it, and reads nothing.
	if t.Provider.BuildsCard() {
		return &FetchedCard{Card: t.BuiltCard()}, nil
	}
	authorize, err := a.credentials.Authorizer(ctx, t)
	if err != nil {
		return nil, err
	}
	if resolve && t.Provider == domain.A2AProviderGeneric {
		return a.fetcher.Resolve(ctx, t.CardURL, authorize)
	}
	return a.fetcher.Fetch(ctx, t.CardLocation(), authorize)
}

// pin resolves t's card, pins it and, for an agent at any URL, checks that the
// endpoint the card names answers A2A: a card can sit on a website that is
// not an agent, and that is better said now than on the first call.
func (a agentCards) pin(ctx context.Context, t *domain.A2ATarget) error {
	card, err := a.fetch(ctx, t, true)
	if err != nil {
		return err
	}
	if err := t.Pin(card.URL, card.Card, time.Now()); err != nil {
		return err
	}
	if t.Provider != domain.A2AProviderGeneric {
		return nil
	}
	authorize, ok, err := a.credentials.CallAuthorizer(ctx, t)
	if err != nil || !ok {
		// Without the call's own credential (one a user's token sets) the
		// endpoint cannot be asked as the gateway will ask it.
		return err
	}
	return a.fetcher.Probe(ctx, t.Endpoint(), t.ProtocolVersion, authorize)
}
