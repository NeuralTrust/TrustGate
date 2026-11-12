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
	"log/slog"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/app/configsyncport"
	"github.com/NeuralTrust/TrustGate/pkg/app/invalidation"
	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache"
)

var (
	// ErrAgentCardChanged reports a live card whose digest is not the one
	// being approved.
	ErrAgentCardChanged = fmt.Errorf("registry: the agent card changed since it was reviewed: %w", commonerrors.ErrConflict)
	// ErrNotAgentRegistry reports an agent card operation on a registry that is not A2A.
	ErrNotAgentRegistry = fmt.Errorf("registry: not an A2A registry: %w", commonerrors.ErrValidation)
)

// AgentCardPreview is a card read without registering anything.
type AgentCardPreview struct {
	ResolvedCardURL string
	Card            json.RawMessage
	CardDigest      string
	Versions        []domain.A2AProtocolVersion
	DefaultVersion  domain.A2AProtocolVersion
}

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

//go:generate mockery --name=AgentCard --dir=. --output=./mocks --filename=registry_agent_card_mock.go --case=underscore --with-expecter
type AgentCard interface {
	// Preview reads the card target names, with the credentials it carries,
	// and writes nothing.
	Preview(ctx context.Context, gatewayID ids.GatewayID, target *domain.A2ATarget) (*AgentCardPreview, error)
	// Refresh reads a registry's live card and reports how it differs from
	// the pinned one. It writes nothing.
	Refresh(ctx context.Context, gatewayID ids.GatewayID, id ids.RegistryID) (*AgentCardRefresh, error)
	// Approve pins the live card when its digest is digest.
	Approve(ctx context.Context, gatewayID ids.GatewayID, id ids.RegistryID, digest string) (*domain.Registry, error)
}

var _ AgentCard = (*agentCard)(nil)

type agentCard struct {
	repo        domain.Repository
	memoryCache *cache.TTLMap
	publisher   cache.EventPublisher
	logger      *slog.Logger
	signaler    configsyncport.SnapshotSignaler
	cards       agentCards
	shared      GatewayLookup
}

func NewAgentCard(
	repo domain.Repository,
	manager *cache.TTLMapManager,
	publisher cache.EventPublisher,
	logger *slog.Logger,
	signaler configsyncport.SnapshotSignaler,
	opts ...Option,
) AgentCard {
	o := applyOptions(opts)
	return &agentCard{
		repo:        repo,
		memoryCache: manager.GetTTLMap(cache.RegistryTTLName),
		publisher:   publisher,
		logger:      logger,
		signaler:    signaler,
		cards:       o.cards,
		shared:      o.sharedGateways,
	}
}

func (a *agentCard) Preview(ctx context.Context, gatewayID ids.GatewayID, target *domain.A2ATarget) (*AgentCardPreview, error) {
	target.Normalize()
	if err := target.Validate(); err != nil {
		return nil, err
	}
	if err := validateSharedDataPlane(ctx, a.shared, gatewayID, target); err != nil {
		return nil, err
	}
	fetched, err := a.cards.fetch(ctx, target, true)
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
	}, nil
}

func (a *agentCard) Refresh(ctx context.Context, gatewayID ids.GatewayID, id ids.RegistryID) (*AgentCardRefresh, error) {
	reg, err := a.agentRegistry(ctx, gatewayID, id)
	if err != nil {
		return nil, err
	}
	pinned := reg.A2ATarget
	if err := validateSharedDataPlane(ctx, a.shared, gatewayID, pinned); err != nil {
		return nil, err
	}
	fetched, err := a.cards.fetch(ctx, pinned, false)
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

func (a *agentCard) Approve(ctx context.Context, gatewayID ids.GatewayID, id ids.RegistryID, digest string) (*domain.Registry, error) {
	reg, err := a.agentRegistry(ctx, gatewayID, id)
	if err != nil {
		return nil, err
	}
	if digest == reg.A2ATarget.CardDigest {
		return reg, nil
	}
	if err := validateSharedDataPlane(ctx, a.shared, gatewayID, reg.A2ATarget); err != nil {
		return nil, err
	}
	fetched, err := a.cards.fetch(ctx, reg.A2ATarget, false)
	if err != nil {
		return nil, err
	}
	live, err := liveDigest(fetched.Card)
	if err != nil {
		return nil, err
	}
	if live != digest {
		return nil, fmt.Errorf("%w: the live card is %s", ErrAgentCardChanged, live)
	}
	next := *reg.A2ATarget
	if err := next.Pin(fetched.URL, fetched.Card, time.Now()); err != nil {
		return nil, err
	}
	reg.A2ATarget = &next
	reg.UpdatedAt = time.Now().UTC()
	if err := a.repo.Update(ctx, reg); err != nil {
		return nil, err
	}
	a.memoryCache.Set(reg.ID.String(), reg)
	invalidation.Registry(ctx, a.publisher, a.logger, reg.GatewayID, reg.ID)
	if a.signaler != nil {
		a.signaler.Signal(ctx)
	}
	return reg, nil
}

func (a *agentCard) agentRegistry(ctx context.Context, gatewayID ids.GatewayID, id ids.RegistryID) (*domain.Registry, error) {
	reg, err := a.repo.FindByID(ctx, id)
	if err != nil {
		return nil, err
	}
	if reg.GatewayID != gatewayID {
		return nil, domain.ErrNotFound
	}
	if reg.Type != domain.TypeA2A || reg.A2ATarget == nil {
		return nil, ErrNotAgentRegistry
	}
	return reg, nil
}

func liveDigest(card []byte) (string, error) {
	if err := domain.ValidateCard(card); err != nil {
		return "", err
	}
	return domain.CardDigest(card)
}
