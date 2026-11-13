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

// AgentCardPreview is a card read without registering anything.
type AgentCardPreview struct {
	ResolvedCardURL string
	Card            json.RawMessage
	CardDigest      string
	Versions        []domain.A2AProtocolVersion
	DefaultVersion  domain.A2AProtocolVersion
	SkillScan       []domain.SkillVerdict
}

//go:generate mockery --name=PreviewAgentCard --dir=. --output=./mocks --filename=registry_preview_agent_card_mock.go --case=underscore --with-expecter
type PreviewAgentCard interface {
	// Preview reads the card target names, with the credentials it carries,
	// and writes nothing.
	Preview(ctx context.Context, gatewayID ids.GatewayID, target *domain.A2ATarget) (*AgentCardPreview, error)
}

type previewAgentCard struct {
	cards  agentCards
	shared sharedPlane
}

// NewPreviewAgentCard builds the card preview. The card reader comes from
// WithAgentCards.
func NewPreviewAgentCard(opts ...Option) PreviewAgentCard {
	o := applyOptions(opts)
	return &previewAgentCard{cards: o.cards, shared: o.shared}
}

func (p *previewAgentCard) Preview(ctx context.Context, gatewayID ids.GatewayID, target *domain.A2ATarget) (*AgentCardPreview, error) {
	target.Normalize()
	if err := target.Validate(); err != nil {
		return nil, err
	}
	if err := validateSharedDataPlane(ctx, p.shared, gatewayID, target); err != nil {
		return nil, err
	}
	fetched, err := p.cards.fetch(ctx, gatewayID, target, true)
	if err != nil {
		return nil, err
	}
	digest, err := liveDigest(fetched.Card)
	if err != nil {
		return nil, err
	}
	versions := target.OfferedVersions(fetched.Card)
	return &AgentCardPreview{
		ResolvedCardURL: fetched.URL,
		Card:            fetched.Card,
		CardDigest:      digest,
		Versions:        versions,
		DefaultVersion:  domain.DefaultVersion(versions),
		SkillScan:       p.cards.scanSkills(ctx, target, fetched.Card),
	}, nil
}
