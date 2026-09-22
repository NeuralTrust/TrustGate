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

package consumer

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	appauth "github.com/NeuralTrust/TrustGate/pkg/app/auth"
	authdomain "github.com/NeuralTrust/TrustGate/pkg/domain/auth"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
)

// ErrAPIKeyUnknown: no enabled api key of this gateway matches. It is the
// single answer for a key that does not exist, one that belongs to another
// gateway and one that has been disabled, so the endpoint never confirms which
// of those is true.
var ErrAPIKeyUnknown = errors.New("consumer: no consumer is reachable with this api key")

// KeyConsumer is one consumer an api key reaches, as its holder may know it.
//
// It carries no identifiers: the caller holds the key, so the slugs and names
// are already theirs, and the ids behind them are the gateway's business.
type KeyConsumer struct {
	Slug   string
	Name   string
	Type   domain.Type
	Active bool
}

// APIKeyConsumers answers what an api key reaches.
//
// A key is attached to consumers, and a consumer has one type, so an agent
// that calls both tools and models holds two of them — an MCP consumer and an
// LLM one — behind the same key. Nothing told the holder of that key which
// slugs those are; they were chosen by whoever created them, in the console.
// This is how a client stops having to be told.
//
//go:generate mockery --name=APIKeyConsumers --dir=. --output=./mocks --filename=consumer_api_key_consumers_mock.go --case=underscore --with-expecter
type APIKeyConsumers interface {
	ForAPIKey(ctx context.Context, gatewayID ids.GatewayID, rawKey string) ([]KeyConsumer, error)
}

type apiKeyConsumers struct {
	consumers DataFinder
	apiKeys   appauth.APIKeyFinder
}

func NewAPIKeyConsumers(consumers DataFinder, apiKeys appauth.APIKeyFinder) (APIKeyConsumers, error) {
	if consumers == nil || apiKeys == nil {
		return nil, errors.New("consumer api key consumers: consumers and api keys are required")
	}
	return &apiKeyConsumers{consumers: consumers, apiKeys: apiKeys}, nil
}

func (s *apiKeyConsumers) ForAPIKey(
	ctx context.Context,
	gatewayID ids.GatewayID,
	rawKey string,
) ([]KeyConsumer, error) {
	key := strings.TrimSpace(rawKey)
	if gatewayID.IsNil() || key == "" {
		return nil, ErrAPIKeyUnknown
	}
	auth, err := s.apiKeys.FindByAPIKey(ctx, key)
	if err != nil {
		if errors.Is(err, authdomain.ErrNotFound) {
			return nil, ErrAPIKeyUnknown
		}
		return nil, fmt.Errorf("consumer api key consumers: find api key: %w", err)
	}
	if auth == nil || !auth.Enabled ||
		auth.Type != authdomain.TypeAPIKey || auth.GatewayID != gatewayID {
		return nil, ErrAPIKeyUnknown
	}
	data, err := s.consumers.FindByGateway(ctx, gatewayID)
	if err != nil {
		return nil, fmt.Errorf("consumer api key consumers: find consumers: %w", err)
	}

	out := make([]KeyConsumer, 0, 2)
	for i := range data.Consumers {
		cons := data.Consumers[i].Consumer
		if cons == nil || cons.GatewayID != gatewayID || !holdsAuth(cons, auth.ID) {
			continue
		}
		out = append(out, KeyConsumer{
			Slug:   cons.Slug,
			Name:   cons.Name,
			Type:   cons.Type,
			Active: cons.Active,
		})
	}
	if len(out) == 0 {
		// The key verified but reaches nothing. Saying so is not a leak — the
		// holder proved it is theirs — and it is the one answer that sends
		// them to the right place, which is an admin, not their own code.
		return out, nil
	}
	// Stable order: a client that has to pick between two consumers of a type
	// should be told about them the same way every time.
	sort.Slice(out, func(i, j int) bool { return out[i].Slug < out[j].Slug })
	return out, nil
}

func holdsAuth(cons *domain.Consumer, authID ids.AuthID) bool {
	for _, id := range cons.AuthIDs {
		if id == authID {
			return true
		}
	}
	return false
}
