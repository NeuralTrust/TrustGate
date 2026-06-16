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

package role

import (
	"context"
	"log/slog"

	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
	domain "github.com/NeuralTrust/AgentGateway/pkg/domain/role"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/cache"
)

//go:generate mockery --name=Finder --dir=. --output=./mocks --filename=role_finder_mock.go --case=underscore --with-expecter
type Finder interface {
	FindByID(ctx context.Context, gatewayID ids.GatewayID, id ids.RoleID) (*domain.Role, error)
	List(ctx context.Context, filter domain.ListFilter) ([]*domain.Role, int, error)
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
		memoryCache: manager.GetTTLMap(cache.RoleTTLName),
		logger:      logger,
	}
}

func (f *finder) FindByID(ctx context.Context, gatewayID ids.GatewayID, id ids.RoleID) (*domain.Role, error) {
	if cached, ok := f.memoryCache.Get(id.String()); ok {
		if role, ok := cached.(*domain.Role); ok {
			return scopeToGateway(role, gatewayID)
		}
		f.logger.Warn("role cache entry failed type assertion; falling back to database",
			slog.String("role_id", id.String()))
		f.memoryCache.Delete(id.String())
	}
	role, err := f.repo.FindByID(ctx, id)
	if err != nil {
		return nil, err
	}
	f.memoryCache.Set(id.String(), role)
	return scopeToGateway(role, gatewayID)
}

func scopeToGateway(role *domain.Role, gatewayID ids.GatewayID) (*domain.Role, error) {
	if role.GatewayID != gatewayID {
		return nil, domain.ErrNotFound
	}
	return role, nil
}

func (f *finder) List(ctx context.Context, filter domain.ListFilter) ([]*domain.Role, int, error) {
	return f.repo.List(ctx, filter)
}
