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
	"log/slog"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/app/invalidation"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache"
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
	// SkillScan is TrustGuard's verdict, now, on the pinned card's skills; it
	// is saved with the pinned card. Nil when they could not be scanned.
	SkillScan []domain.SkillVerdict
	// FetchedSkillScan is TrustGuard's verdict on the fetched card's skills,
	// when the card changed.
	FetchedSkillScan []domain.SkillVerdict
}

//go:generate mockery --name=RefreshAgentCard --dir=. --output=./mocks --filename=registry_refresh_agent_card_mock.go --case=underscore --with-expecter
type RefreshAgentCard interface {
	// Refresh reads a registry's live card and reports how it differs from
	// the pinned one, and scans the pinned card's skills again. It writes
	// only that scan.
	Refresh(ctx context.Context, gatewayID ids.GatewayID, id ids.RegistryID) (*AgentCardRefresh, error)
}

type refreshAgentCard struct {
	repo        domain.Repository
	pinner      A2ACardPinner
	memoryCache *cache.TTLMap
	publisher   cache.EventPublisher
	logger      *slog.Logger
	cards       agentCards
	shared      sharedPlane
}

// NewRefreshAgentCard builds the card comparison. The card reader comes from
// WithAgentCards. pinner may be nil on a plane that does not write
// registries; the skill scan is then not saved.
func NewRefreshAgentCard(
	repo domain.Repository,
	pinner A2ACardPinner,
	manager *cache.TTLMapManager,
	publisher cache.EventPublisher,
	logger *slog.Logger,
	opts ...Option,
) RefreshAgentCard {
	o := applyOptions(opts)
	return &refreshAgentCard{
		repo:        repo,
		pinner:      pinner,
		memoryCache: manager.GetTTLMap(cache.RegistryTTLName),
		publisher:   publisher,
		logger:      logger,
		cards:       o.cards,
		shared:      o.shared,
	}
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
	fetched, err := r.cards.fetch(ctx, gatewayID, pinned, false)
	if err != nil {
		return nil, err
	}
	digest, err := liveDigest(fetched.Card)
	if err != nil {
		return nil, err
	}
	added, removed := domain.SkillDiff(pinned.Card, fetched.Card)
	changed := digest != pinned.CardDigest
	scan := r.cards.scanSkills(ctx, gatewayID, pinned, pinned.Card)
	r.saveScan(ctx, reg, scan)
	var fetchedScan []domain.SkillVerdict
	if changed {
		fetchedScan = r.cards.scanSkills(ctx, gatewayID, pinned, fetched.Card)
	}
	return &AgentCardRefresh{
		Changed:          changed,
		PinnedDigest:     pinned.CardDigest,
		FetchedDigest:    digest,
		ChangedFields:    domain.ChangedFields(pinned.Card, fetched.Card),
		SkillsAdded:      added,
		SkillsRemoved:    removed,
		FetchedCard:      fetched.Card,
		SkillScan:        scan,
		FetchedSkillScan: fetchedScan,
	}, nil
}

// saveScan keeps scan with reg's pinned card, unless the card was pinned
// again meanwhile. A scan that could not be saved is still answered: the
// comparison does not fail for it.
func (r *refreshAgentCard) saveScan(ctx context.Context, reg *domain.Registry, scan []domain.SkillVerdict) {
	if scan == nil || r.pinner == nil {
		return
	}
	next := *reg.A2ATarget
	next.SkillScan = scan
	saved, err := r.pinner.PinA2ACard(ctx, reg.GatewayID, reg.ID, reg.A2ATarget.CardDigest, &next, time.Now().UTC())
	if err != nil || !saved {
		r.logger.WarnContext(ctx, "agent skill scan not saved", slog.String("registry_id", reg.ID.String()), slog.Any("error", err))
		return
	}
	updated := *reg
	updated.A2ATarget = &next
	r.memoryCache.Set(updated.ID.String(), &updated)
	invalidation.Registry(ctx, r.publisher, r.logger, updated.GatewayID, updated.ID)
}
