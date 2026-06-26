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

package gateway

import (
	"context"
	"log/slog"

	domain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache"
)

//go:generate mockery --name=Deleter --dir=. --output=./mocks --filename=gateway_deleter_mock.go --case=underscore --with-expecter
type Deleter interface {
	Delete(ctx context.Context, id ids.GatewayID) error
}

var _ Deleter = (*deleter)(nil)

type deleter struct {
	repo              domain.Repository
	memoryCache       *cache.TTLMap
	registryCache     *cache.TTLMap
	policyCache       *cache.TTLMap
	consumerCache     *cache.TTLMap
	consumerDataCache *cache.TTLMap
	loadBalancerCache *cache.TTLMap
	authCache         *cache.TTLMap
	consumerPathCache *cache.TTLMap
	roleCache         *cache.TTLMap
	publisher         cache.EventPublisher
	logger            *slog.Logger
}

func NewDeleter(
	repo domain.Repository,
	manager *cache.TTLMapManager,
	publisher cache.EventPublisher,
	logger *slog.Logger,
) Deleter {
	return &deleter{
		repo:              repo,
		memoryCache:       manager.GetTTLMap(cache.GatewayTTLName),
		registryCache:     manager.GetTTLMap(cache.RegistryTTLName),
		policyCache:       manager.GetTTLMap(cache.PolicyTTLName),
		consumerCache:     manager.GetTTLMap(cache.ConsumerTTLName),
		consumerDataCache: manager.GetTTLMap(cache.ConsumerDataTTLName),
		loadBalancerCache: manager.GetTTLMap(cache.LoadBalancerTTLName),
		authCache:         manager.GetTTLMap(cache.AuthTTLName),
		consumerPathCache: manager.GetTTLMap(cache.ConsumerPathTTLName),
		roleCache:         manager.GetTTLMap(cache.RoleTTLName),
		publisher:         publisher,
		logger:            logger,
	}
}

func (d *deleter) Delete(ctx context.Context, id ids.GatewayID) error {
	g, _ := cachedGatewayForDelete(d.memoryCache, id)
	if err := d.repo.Delete(ctx, id); err != nil {
		return err
	}
	deleteGatewayCache(d.memoryCache, g)
	d.memoryCache.Delete(gatewayIDCacheKey(id))
	d.evictGatewayScopedCaches(id)
	publishGatewayDataInvalidation(ctx, d.publisher, d.logger, id)
	return nil
}

// evictGatewayScopedCaches drops the in-memory read caches for resources owned
// by the deleted gateway on this instance, so a read that immediately follows
// the delete cannot serve a cascade-removed registry/policy/etc. from cache.
// Other instances are converged by the published InvalidateGatewayDataEvent.
func (d *deleter) evictGatewayScopedCaches(id ids.GatewayID) {
	if d.consumerDataCache != nil {
		d.consumerDataCache.Delete(id.String())
	}
	if d.loadBalancerCache != nil {
		d.loadBalancerCache.DeleteByPrefix(id.String() + ":")
	}
	if d.registryCache != nil {
		d.registryCache.Clear()
	}
	if d.policyCache != nil {
		d.policyCache.Clear()
	}
	if d.consumerCache != nil {
		d.consumerCache.Clear()
	}
	if d.authCache != nil {
		d.authCache.Clear()
	}
	if d.consumerPathCache != nil {
		d.consumerPathCache.Clear()
	}
	if d.roleCache != nil {
		d.roleCache.Clear()
	}
}

func cachedGatewayForDelete(memoryCache *cache.TTLMap, id ids.GatewayID) (*domain.Gateway, bool) {
	cached, ok := memoryCache.Get(gatewayIDCacheKey(id))
	if !ok {
		return nil, false
	}
	g, ok := cached.(*domain.Gateway)
	if !ok {
		return nil, false
	}
	return g, true
}
