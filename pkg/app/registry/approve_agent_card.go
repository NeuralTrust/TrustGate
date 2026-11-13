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
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/app/configsyncport"
	"github.com/NeuralTrust/TrustGate/pkg/app/invalidation"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache"
)

// ErrCardPinUnavailable reports a plane whose registry store cannot pin a
// card on its own.
var ErrCardPinUnavailable = errors.New("registry: this plane cannot pin agent cards")

//go:generate mockery --name=A2ACardPinner --dir=. --output=./mocks --filename=registry_a2a_card_pinner_mock.go --case=underscore --with-expecter
type A2ACardPinner interface {
	// PinA2ACard writes pinned's card onto the registry while the stored
	// target still pins fromDigest from the same card URL, version and
	// locator, leaving everything else as stored. It reports false, writing
	// nothing, when the stored target moved.
	PinA2ACard(ctx context.Context, gatewayID ids.GatewayID, id ids.RegistryID, fromDigest string, pinned *domain.A2ATarget, updatedAt time.Time) (bool, error)
}

//go:generate mockery --name=ApproveAgentCard --dir=. --output=./mocks --filename=registry_approve_agent_card_mock.go --case=underscore --with-expecter
type ApproveAgentCard interface {
	// Approve pins the live card when its digest is digest.
	Approve(ctx context.Context, gatewayID ids.GatewayID, id ids.RegistryID, digest string) (*domain.Registry, error)
}

type approveAgentCard struct {
	repo        domain.Repository
	pinner      A2ACardPinner
	memoryCache *cache.TTLMap
	publisher   cache.EventPublisher
	logger      *slog.Logger
	signaler    configsyncport.SnapshotSignaler
	cards       agentCards
	shared      sharedPlane
}

// NewApproveAgentCard builds the card approval. pinner may be nil on a plane
// that does not write registries; Approve then fails. The card reader comes
// from WithAgentCards.
func NewApproveAgentCard(
	repo domain.Repository,
	pinner A2ACardPinner,
	manager *cache.TTLMapManager,
	publisher cache.EventPublisher,
	logger *slog.Logger,
	signaler configsyncport.SnapshotSignaler,
	opts ...Option,
) ApproveAgentCard {
	o := applyOptions(opts)
	return &approveAgentCard{
		repo:        repo,
		pinner:      pinner,
		memoryCache: manager.GetTTLMap(cache.RegistryTTLName),
		publisher:   publisher,
		logger:      logger,
		signaler:    signaler,
		cards:       o.cards,
		shared:      o.shared,
	}
}

func (a *approveAgentCard) Approve(ctx context.Context, gatewayID ids.GatewayID, id ids.RegistryID, digest string) (*domain.Registry, error) {
	reg, err := findAgentRegistry(ctx, a.repo, gatewayID, id)
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
	next.SkillScan = a.cards.scanSkills(ctx, &next, next.Card)
	if a.pinner == nil {
		return nil, ErrCardPinUnavailable
	}
	pinned, err := a.pinner.PinA2ACard(ctx, gatewayID, id, reg.A2ATarget.CardDigest, &next, time.Now().UTC())
	if err != nil {
		return nil, err
	}
	if !pinned {
		return nil, fmt.Errorf("%w: the registry changed while its card was read", ErrAgentCardChanged)
	}
	saved, err := findAgentRegistry(ctx, a.repo, gatewayID, id)
	if err != nil {
		return nil, err
	}
	a.memoryCache.Set(saved.ID.String(), saved)
	invalidation.Registry(ctx, a.publisher, a.logger, saved.GatewayID, saved.ID)
	if a.signaler != nil {
		a.signaler.Signal(ctx)
	}
	return saved, nil
}
