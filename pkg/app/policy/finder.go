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

//go:generate mockery --name=Finder --dir=. --output=./mocks --filename=policy_finder_mock.go --case=underscore --with-expecter
type Finder interface {
	FindByID(ctx context.Context, gatewayID ids.GatewayID, id ids.PolicyID) (*domain.Policy, error)
	List(ctx context.Context, filter domain.ListFilter) ([]*domain.Policy, int, error)
}

var _ Finder = (*finder)(nil)

type finder struct {
	repo        domain.Repository
	memoryCache *cache.TTLMap
	logger      *slog.Logger
}

func NewFinder(repo domain.Repository, manager *cache.TTLMapManager, logger *slog.Logger) Finder {
	return &finder{
		repo:        repo,
		memoryCache: manager.GetTTLMap(cache.PolicyTTLName),
		logger:      logger,
	}
}

func (f *finder) FindByID(ctx context.Context, gatewayID ids.GatewayID, id ids.PolicyID) (*domain.Policy, error) {
	if cached, ok := f.memoryCache.Get(id.String()); ok {
		if p, ok := cached.(*domain.Policy); ok {
			return scopeToGateway(p, gatewayID)
		}
		f.logger.Warn("policy cache entry failed type assertion; falling back to database",
			slog.String("policy_id", id.String()))
		f.memoryCache.Delete(id.String())
	}
	p, err := f.repo.FindByID(ctx, id)
	if err != nil {
		return nil, err
	}
	f.memoryCache.Set(id.String(), p)
	return scopeToGateway(p, gatewayID)
}

// scopeToGateway enforces that a policy belongs to the requesting gateway,
// returning ErrNotFound for cross-gateway ids so the API never confirms the
// existence of another gateway's resource.
func scopeToGateway(p *domain.Policy, gatewayID ids.GatewayID) (*domain.Policy, error) {
	if p.GatewayID != gatewayID {
		return nil, domain.ErrNotFound
	}
	return p, nil
}

func (f *finder) List(ctx context.Context, filter domain.ListFilter) ([]*domain.Policy, int, error) {
	return f.repo.List(ctx, filter)
}
