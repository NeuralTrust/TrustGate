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
	"log/slog"

	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache"
)

//go:generate mockery --name=Scoper --dir=. --output=./mocks --filename=policy_scoper_mock.go --case=underscore --with-expecter
type Scoper interface {
	SetGlobal(ctx context.Context, gatewayID ids.GatewayID, id ids.PolicyID) (*domain.Policy, error)
	UnsetGlobal(ctx context.Context, gatewayID ids.GatewayID, id ids.PolicyID) (*domain.Policy, error)
}

var _ Scoper = (*scoper)(nil)

type scoper struct {
	repo        domain.Repository
	memoryCache *cache.TTLMap
	publisher   cache.EventPublisher
	logger      *slog.Logger
}

func NewScoper(
	repo domain.Repository,
	manager *cache.TTLMapManager,
	publisher cache.EventPublisher,
	logger *slog.Logger,
) Scoper {
	return &scoper{
		repo:        repo,
		memoryCache: manager.GetTTLMap(cache.PolicyTTLName),
		publisher:   publisher,
		logger:      logger,
	}
}

func (s *scoper) SetGlobal(ctx context.Context, gatewayID ids.GatewayID, id ids.PolicyID) (*domain.Policy, error) {
	return s.setGlobal(ctx, gatewayID, id, true)
}

func (s *scoper) UnsetGlobal(ctx context.Context, gatewayID ids.GatewayID, id ids.PolicyID) (*domain.Policy, error) {
	return s.setGlobal(ctx, gatewayID, id, false)
}

func (s *scoper) setGlobal(ctx context.Context, gatewayID ids.GatewayID, id ids.PolicyID, global bool) (*domain.Policy, error) {
	existing, err := s.repo.FindByID(ctx, id)
	if err != nil {
		return nil, err
	}
	if existing.GatewayID != gatewayID {
		return nil, domain.ErrNotFound
	}
	if existing.Global == global {
		return existing, nil
	}
	if err := s.repo.SetGlobal(ctx, gatewayID, id, global); err != nil {
		return nil, err
	}
	existing.Global = global
	s.memoryCache.Set(existing.ID.String(), existing)
	publishGatewayDataInvalidation(ctx, s.publisher, s.logger, existing.GatewayID)
	return existing, nil
}
