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

package auth

import (
	"context"
	"log/slog"

	domain "github.com/NeuralTrust/AgentGateway/pkg/domain/auth"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/cache"
)

//go:generate mockery --name=Finder --dir=. --output=./mocks --filename=auth_finder_mock.go --case=underscore --with-expecter
type Finder interface {
	FindByID(ctx context.Context, gatewayID ids.GatewayID, id ids.AuthID) (*domain.Auth, error)
	List(ctx context.Context, filter domain.ListFilter) ([]*domain.Auth, int, error)
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
		memoryCache: manager.GetTTLMap(cache.AuthTTLName),
		logger:      logger,
	}
}

func (f *finder) FindByID(ctx context.Context, gatewayID ids.GatewayID, id ids.AuthID) (*domain.Auth, error) {
	if cached, ok := f.memoryCache.Get(id.String()); ok {
		if a, ok := cached.(*domain.Auth); ok {
			return scopeToGateway(a, gatewayID)
		}
		f.logger.Warn("auth cache entry failed type assertion; falling back to database",
			slog.String("auth_id", id.String()))
		f.memoryCache.Delete(id.String())
	}
	a, err := f.repo.FindByID(ctx, id)
	if err != nil {
		return nil, err
	}
	f.memoryCache.Set(id.String(), a)
	return scopeToGateway(a, gatewayID)
}
func scopeToGateway(a *domain.Auth, gatewayID ids.GatewayID) (*domain.Auth, error) {
	if a.GatewayID != gatewayID {
		return nil, domain.ErrNotFound
	}
	return a, nil
}

func (f *finder) List(ctx context.Context, filter domain.ListFilter) ([]*domain.Auth, int, error) {
	return f.repo.List(ctx, filter)
}
