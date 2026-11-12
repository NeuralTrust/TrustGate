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

	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
)

// AgentCardRefresh compares a registry's live card with the pinned one.
type AgentCardRefresh struct {
	Changed       bool
	PinnedDigest  string
	FetchedDigest string
	ChangedFields []string
	SkillsAdded   []string
	SkillsRemoved []string
	FetchedCard   json.RawMessage
}

//go:generate mockery --name=RefreshAgentCard --dir=. --output=./mocks --filename=registry_refresh_agent_card_mock.go --case=underscore --with-expecter
type RefreshAgentCard interface {
	// Refresh reads a registry's live card and reports how it differs from
	// the pinned one. It writes nothing.
	Refresh(ctx context.Context, gatewayID ids.GatewayID, id ids.RegistryID) (*AgentCardRefresh, error)
}

type refreshAgentCard struct {
	repo   domain.Repository
	cards  agentCards
	shared sharedPlane
}

// NewRefreshAgentCard builds the card comparison. The card reader comes from
// WithAgentCards.
func NewRefreshAgentCard(repo domain.Repository, opts ...Option) RefreshAgentCard {
	o := applyOptions(opts)
	return &refreshAgentCard{repo: repo, cards: o.cards, shared: o.shared}
}

func (r *refreshAgentCard) Refresh(ctx context.Context, gatewayID ids.GatewayID, id ids.RegistryID) (*AgentCardRefresh, error) {
	reg, err := findAgentRegistry(ctx, r.repo, gatewayID, id)
	if err != nil {
		return nil, err
	}
	pinned := reg.A2ATarget
	if err := validateSharedDataPlane(ctx, r.shared, gatewayID, pinned); err != nil {
		return nil, err
	}
	fetched, err := r.cards.fetch(ctx, pinned, false)
	if err != nil {
		return nil, err
	}
	digest, err := liveDigest(fetched.Card)
	if err != nil {
		return nil, err
	}
	added, removed := domain.SkillDiff(pinned.Card, fetched.Card)
	return &AgentCardRefresh{
		Changed:       digest != pinned.CardDigest,
		PinnedDigest:  pinned.CardDigest,
		FetchedDigest: digest,
		ChangedFields: domain.ChangedFields(pinned.Card, fetched.Card),
		SkillsAdded:   added,
		SkillsRemoved: removed,
		FetchedCard:   fetched.Card,
	}, nil
}
