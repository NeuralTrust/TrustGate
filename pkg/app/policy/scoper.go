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

package policy

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/app/configsyncport"
	"github.com/NeuralTrust/TrustGate/pkg/app/invalidation"
	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache"
)

//go:generate mockery --name=Scoper --dir=. --output=./mocks --filename=policy_scoper_mock.go --case=underscore --with-expecter
type Scoper interface {
	SetGlobal(ctx context.Context, gatewayID ids.GatewayID, id ids.PolicyID) (*domain.Policy, error)
	UnsetGlobal(ctx context.Context, gatewayID ids.GatewayID, id ids.PolicyID) (*domain.Policy, error)
	SetMCPWide(ctx context.Context, gatewayID ids.GatewayID, id ids.PolicyID) (*domain.Policy, error)
	UnsetMCPWide(ctx context.Context, gatewayID ids.GatewayID, id ids.PolicyID) (*domain.Policy, error)
}

var _ Scoper = (*scoper)(nil)

type scoper struct {
	repo        domain.Repository
	levels      LevelGuard
	plugins     appplugins.Registry
	memoryCache *cache.TTLMap
	publisher   cache.EventPublisher
	logger      *slog.Logger
	signaler    configsyncport.SnapshotSignaler
}

func NewScoper(
	repo domain.Repository,
	levels LevelGuard,
	plugins appplugins.Registry,
	manager *cache.TTLMapManager,
	publisher cache.EventPublisher,
	logger *slog.Logger,
	signaler configsyncport.SnapshotSignaler,
) Scoper {
	return &scoper{
		repo:        repo,
		levels:      levels,
		plugins:     plugins,
		memoryCache: manager.GetTTLMap(cache.PolicyTTLName),
		publisher:   publisher,
		logger:      logger,
		signaler:    signaler,
	}
}

type flagWriter func(ctx context.Context, gatewayID ids.GatewayID, id ids.PolicyID, on bool, readAt time.Time) (domain.Placement, error)

type placementFlag struct {
	isSet  func(p *domain.Policy) bool
	set    func(p *domain.Policy, on bool)
	writer func(repo domain.Repository) flagWriter
	admits func(reg appplugins.Registry, slug string) error
}

var (
	globalFlag = placementFlag{
		isSet:  func(p *domain.Policy) bool { return p.Global },
		set:    (*domain.Policy).SetGlobal,
		writer: func(repo domain.Repository) flagWriter { return repo.SetGlobal },
	}
	mcpWideFlag = placementFlag{
		isSet:  func(p *domain.Policy) bool { return p.MCPWide },
		set:    (*domain.Policy).SetMCPWide,
		writer: func(repo domain.Repository) flagWriter { return repo.SetMCPWide },
		admits: validateMCPWidePlugin,
	}
)

func (s *scoper) SetGlobal(ctx context.Context, gatewayID ids.GatewayID, id ids.PolicyID) (*domain.Policy, error) {
	return s.place(ctx, gatewayID, id, globalFlag, true)
}

func (s *scoper) UnsetGlobal(ctx context.Context, gatewayID ids.GatewayID, id ids.PolicyID) (*domain.Policy, error) {
	return s.place(ctx, gatewayID, id, globalFlag, false)
}

func (s *scoper) SetMCPWide(ctx context.Context, gatewayID ids.GatewayID, id ids.PolicyID) (*domain.Policy, error) {
	return s.place(ctx, gatewayID, id, mcpWideFlag, true)
}

func (s *scoper) UnsetMCPWide(ctx context.Context, gatewayID ids.GatewayID, id ids.PolicyID) (*domain.Policy, error) {
	return s.place(ctx, gatewayID, id, mcpWideFlag, false)
}

func (s *scoper) place(ctx context.Context, gatewayID ids.GatewayID, id ids.PolicyID, flag placementFlag, on bool) (*domain.Policy, error) {
	existing, err := s.repo.FindByID(ctx, id)
	if err != nil {
		return nil, err
	}
	if existing.GatewayID != gatewayID {
		return nil, domain.ErrNotFound
	}
	if flag.isSet(existing) == on {
		return existing, nil
	}
	written, err := s.write(ctx, existing, flag, on)
	if on && errors.Is(err, domain.ErrPlacementChanged) {
		current, placed, rereadErr := s.placedMeanwhile(ctx, existing, flag)
		if rereadErr != nil {
			return nil, rereadErr
		}
		if placed {
			return current, nil
		}
	}
	if err != nil {
		return nil, err
	}
	existing.Global, existing.MCPWide, existing.UpdatedAt = written.Global, written.MCPWide, written.UpdatedAt
	if existing.MCPWide {
		existing.ConsumerIDs = nil
	}
	s.memoryCache.Set(existing.ID.String(), existing)
	invalidation.GatewayData(ctx, s.publisher, s.logger, existing.GatewayID)
	if s.signaler != nil {
		s.signaler.Signal(ctx)
	}
	return existing, nil
}

// write persists the flag, guarded when it is a promotion. Promoting moves the
// policy to the all-consumers level of its planes, which a policy of the same
// plugin may already hold; demoting only releases levels, so it needs no guard
// and must not be refused by one.
//
// The guard decides on existing, which was read before it took any lock, and
// takes none at all when the promoted policy occupies nothing, as a disabled
// one does. So the promotion lands only on the row as read: an update that
// committed in between, such as one that turned the policy on, fails it with
// ErrPlacementChanged instead of leaving a placement nobody checked.
//
// It returns the placement the row holds once written, which is what the
// caller caches and answers with: a demotion leaves the other flag as the row
// has it, and that may not be what existing says.
func (s *scoper) write(ctx context.Context, existing *domain.Policy, flag placementFlag, on bool) (domain.Placement, error) {
	persist := flag.writer(s.repo)
	if !on {
		return persist(ctx, existing.GatewayID, existing.ID, false, time.Time{})
	}
	if flag.admits != nil {
		if err := flag.admits(s.plugins, existing.Slug); err != nil {
			return domain.Placement{}, err
		}
	}
	promoted := *existing
	flag.set(&promoted, true)
	var written domain.Placement
	err := s.levels.Check(ctx, &promoted, func(ctx context.Context) error {
		var err error
		written, err = persist(ctx, existing.GatewayID, existing.ID, true, existing.UpdatedAt)
		return err
	})
	return written, err
}

// placedMeanwhile re-reads a policy whose promotion was refused because the row
// changed after it was read. When the promotion would change nothing on the row
// as it stands, another write already placed it there, most often the same
// request sent twice, and that write cached and announced it. The promotion
// then answers the row the way a no-op does, so a retry stays idempotent. A
// policy deleted in between answers ErrNotFound; any other row, or a re-read
// that fails otherwise, keeps the conflict.
func (s *scoper) placedMeanwhile(ctx context.Context, existing *domain.Policy, flag placementFlag) (*domain.Policy, bool, error) {
	current, err := s.repo.FindByID(ctx, existing.ID)
	if errors.Is(err, domain.ErrNotFound) {
		return nil, false, err
	}
	if err != nil {
		s.logger.Warn("policy placement re-read failed",
			slog.String("policy_id", existing.ID.String()),
			slog.String("gateway_id", existing.GatewayID.String()),
			slog.String("error", err.Error()),
		)
		return nil, false, nil
	}
	promoted := *current
	flag.set(&promoted, true)
	return current, promoted.Global == current.Global && promoted.MCPWide == current.MCPWide, nil
}
