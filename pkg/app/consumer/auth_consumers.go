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

	domain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
)

// AuthConsumer names a consumer that holds an auth.
type AuthConsumer struct {
	ID   ids.ConsumerID
	Name string
	Slug string
	Type domain.Type
}

// AuthConsumers answers the question a consumer already answers backwards.
//
// A consumer carries the ids of the auths it accepts, so "which consumers does
// this key reach" has no index behind it — and it is the question an admin is
// really asking before revoking one. Without it the console can only say that a
// key is about to stop working, not what stops with it.
//
//go:generate mockery --name=AuthConsumers --dir=. --output=./mocks --filename=consumer_auth_consumers_mock.go --case=underscore --with-expecter
type AuthConsumers interface {
	// ForAuths reports the consumers holding each of the given auths. Every id
	// asked about appears in the result, with an empty list when nothing holds
	// it — "reaches nothing" is an answer, not a missing key.
	ForAuths(
		ctx context.Context,
		gatewayID ids.GatewayID,
		authIDs []ids.AuthID,
	) (map[ids.AuthID][]AuthConsumer, error)
}

var _ AuthConsumers = (*authConsumers)(nil)

type authConsumers struct {
	consumers DataFinder
}

func NewAuthConsumers(consumers DataFinder) (AuthConsumers, error) {
	if consumers == nil {
		return nil, errors.New("consumer auth consumers: consumers are required")
	}
	return &authConsumers{consumers: consumers}, nil
}

func (s *authConsumers) ForAuths(
	ctx context.Context,
	gatewayID ids.GatewayID,
	authIDs []ids.AuthID,
) (map[ids.AuthID][]AuthConsumer, error) {
	out := make(map[ids.AuthID][]AuthConsumer, len(authIDs))
	for _, id := range authIDs {
		out[id] = []AuthConsumer{}
	}
	if len(out) == 0 || gatewayID.IsNil() {
		return out, nil
	}
	// One read for the whole page: the consumer data is per gateway and cached,
	// so asking about twenty auths costs what asking about one does.
	data, err := s.consumers.FindByGateway(ctx, gatewayID)
	if err != nil {
		return nil, fmt.Errorf("consumer auth consumers: find consumers: %w", err)
	}
	for i := range data.Consumers {
		// The synthetic Store consumer is not in here (it hangs off
		// Data.StoreConsumer), which is correct: no key reaches it.
		cons := data.Consumers[i].Consumer
		if cons == nil || cons.GatewayID != gatewayID {
			continue
		}
		for _, authID := range cons.AuthIDs {
			held, ok := out[authID]
			if !ok {
				continue
			}
			out[authID] = append(held, AuthConsumer{
				ID:   cons.ID,
				Name: cons.Name,
				Slug: cons.Slug,
				Type: cons.Type,
			})
		}
	}
	// Named in a stable order, so a list does not reshuffle between reads.
	for id := range out {
		held := out[id]
		sort.Slice(held, func(a, b int) bool { return held[a].Slug < held[b].Slug })
	}
	return out, nil
}
